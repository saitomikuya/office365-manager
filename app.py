import os
import json
import uuid
import secrets
import string
import hashlib
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
import threading  # For deferred background tasks
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash)
from msal import ConfidentialClientApplication

# Path to the configuration file used to store the hashed password and
# organization connection details.  The configuration file is persisted on
# disk so that organizations and passwords survive container restarts.
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.json')

# Initialise the Flask application.  A secret key is required for session
# management.  In production you should override this via the environment.
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'changeme-secret')

# In‑memory cache for access tokens.  Keys are organisation IDs and values are
# dicts containing the token and its expiry time.  This reduces the number of
# authentication requests and helps minimise API calls.
token_cache: Dict[str, Dict[str, Any]] = {}

# In‑memory API test status for organisations.  The key is an organisation ID
# and the value indicates whether the last API test succeeded (True), failed
# (False), or has not yet been performed (None).  These statuses are not
# persisted across server restarts.
org_api_status: Dict[str, Optional[bool]] = {}

# ---------------------------------------------------------------------------
# Licence SKU to product name mapping
#
# Microsoft Graph's subscribedSkus endpoint returns SKU identifiers via the
# ``skuPartNumber`` field but does not provide friendly product names.  To
# present a more meaningful label in the organisation overview, we map
# commonly encountered SKU identifiers to human‑readable product names.
# This mapping is not exhaustive; unknown identifiers are transformed into
# a title‑cased string (e.g. ``O365_BUSINESS_BASIC`` becomes
# ``O365 Business Basic``).  Administrators may expand this dictionary to
# cover additional licences specific to their tenants.

SKU_PRODUCT_NAMES: Dict[str, str] = {
    # Office 365 企业版
    'ENTERPRISEPACK': 'Office 365 企业版 E3',
    'ENTERPRISEPREMIUM': 'Office 365 企业版 E5',
    'STANDARDPACK': 'Office 365 企业版 E1',
    # Microsoft 365 企业版/商业版
    'SPE_E3': 'Microsoft 365 E3',
    'SPE_E5': 'Microsoft 365 E5',
    'SPE_F3': 'Microsoft 365 F3',
    'SPE_F1': 'Microsoft 365 F1',
    'M365_BUSINESS_PREMIUM': 'Microsoft 365 商业高级版',
    'M365_BUSINESS_STANDARD': 'Microsoft 365 商业标准版',
    'M365_BUSINESS_BASIC': 'Microsoft 365 商业基础版',
    # Office 365 商业版（旧名称）
    'O365_BUSINESS_PREMIUM': 'Office 365 商业高级版',
    'O365_BUSINESS_ESSENTIALS': 'Office 365 商业基础版',
    # 企业移动性与安全套件
    'EMS': '企业移动性与安全性套件',
    # 学生/教师版 Office 365 A1
    'STANDARDWOFFPACK_STUDENT': '面向学生的 Office 365 A1',
    'STANDARDWOFFPACK_FACULTY': '面向教师的 Office 365 A1',
    # 留出更多扩展项供管理员自定义
    # 'SOME_OTHER_SKU': '产品中文名称',
}

# Attempt to extend the static SKU mapping with entries from an external JSON file.
# A full mapping file (sku_product_mapping.json) may be placed alongside this
# script.  If present, it should contain a JSON object mapping SKU identifiers
# ("SKU名称") to product names ("产品名称").  Loading the file at runtime
# allows administrators to update the mapping without modifying code.  Any
# entries in the external file will override the default values defined above.
mapping_file_path = os.path.join(os.path.dirname(__file__), 'sku_product_mapping.json')
if os.path.exists(mapping_file_path):
    try:
        with open(mapping_file_path, 'r', encoding='utf-8') as f:
            external_mapping = json.load(f)
        if isinstance(external_mapping, dict):
            # Update and override existing entries
            SKU_PRODUCT_NAMES.update({k: v for k, v in external_mapping.items() if isinstance(k, str) and isinstance(v, str)})
    except Exception as exc:
        # Log error to console but continue gracefully
        print(f"Failed to load SKU mapping file: {exc}")


def get_product_name_for_sku(sku_part_number: Optional[str]) -> str:
    """Translate a SKU part number to a friendly product name.

    If the SKU is found in the predefined mapping, the corresponding
    product name is returned.  Otherwise, a generic transformation is
    applied: underscores are replaced by spaces and the result is
    title‑cased.  If no part number is provided, an empty string is
    returned.

    :param sku_part_number: The SKU identifier returned by Graph API.
    :return: A human‑readable product name.
    """
    if not sku_part_number:
        return ''
    # Return mapped name if available
    if sku_part_number in SKU_PRODUCT_NAMES:
        return SKU_PRODUCT_NAMES[sku_part_number]
    # Fallback: replace underscores and capitalise words
    return sku_part_number.replace('_', ' ').title()

# Mapping of subscription capability statuses returned by subscribedSkus
# to more user‑friendly Chinese labels.  Microsoft Graph returns
# values such as ``Enabled``, ``Warning``, ``Suspended``, ``Deleted``
# and ``LockedOut`` via the ``capabilityStatus`` property.  We use
# this dictionary to translate these values into descriptive terms in
# the UI.  Unknown statuses are left unchanged.
CAPABILITY_STATUS_LABELS: Dict[str, str] = {
    'Enabled': '活动',
    'Warning': '警告',
    'Suspended': '已禁用',
    'Deleted': '已删除',
    'LockedOut': '已锁定',
    'Expired': '已过期',
    'Unknown': '未知'
}



def load_config() -> Dict[str, Any]:
    """Load the configuration from disk, creating defaults if necessary."""
    if not os.path.exists(CONFIG_FILE):
        # On first run initialise the configuration with a default password
        # (hash of 'admin') and an empty organisation list.  The user should
        # immediately change this password after first login.
        default_config = {
            "password_hash": hashlib.sha256("admin".encode()).hexdigest(),
            "organizations": []
        }
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=4)
        return default_config
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_config(config: Dict[str, Any]) -> None:
    """Persist the configuration dictionary to disk."""
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=4, ensure_ascii=False)


config = load_config()


def verify_password(password: str) -> bool:
    """Check if a provided password matches the stored hash."""
    return hashlib.sha256(password.encode()).hexdigest() == config.get("password_hash")


def set_password(new_password: str) -> None:
    """Update the stored password hash and save the configuration."""
    config["password_hash"] = hashlib.sha256(new_password.encode()).hexdigest()
    save_config(config)


def get_org(org_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve an organisation record by its ID from the configuration."""
    for org in config.get("organizations", []):
        if org.get("id") == org_id:
            return org
    return None


def get_access_token(org: Dict[str, str]) -> Optional[str]:
    """Acquire an access token for the Microsoft Graph API using client credentials.

    Tokens are cached until shortly before expiration to avoid excessive
    authentication requests.  If the token has expired or is about to expire,
    a new one is fetched using the MSAL library.
    """
    # Check the in‑memory cache first
    cache_entry = token_cache.get(org['id'])
    if cache_entry and cache_entry.get('expires_at', 0) > time.time() + 60:
        return cache_entry['access_token']

    authority = f"https://login.microsoftonline.com/{org['tenant_id']}"
    client = ConfidentialClientApplication(
        client_id=org['client_id'],
        client_credential=org['client_secret'],
        authority=authority
    )

    # Attempt to silently obtain a token from the MSAL cache.  This may fail
    # when no token has been cached yet, so fall back to acquiring a new one.
    result = client.acquire_token_silent(
        scopes=["https://graph.microsoft.com/.default"], account=None
    )
    if not result:
        result = client.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )

    if 'access_token' in result:
        token_cache[org['id']] = {
            'access_token': result['access_token'],
            'expires_at': time.time() + result.get('expires_in', 3600)
        }
        return result['access_token']
    # Authentication failed
    return None


def graph_request(org: Dict[str, str], method: str, endpoint: str,
                  params: Optional[Dict[str, str]] = None,
                  data: Optional[Dict[str, Any]] = None,
                  extra_headers: Optional[Dict[str, str]] = None) -> Any:
    """Send an authenticated request to the Microsoft Graph API for a specific organisation.

    :param org: The organisation configuration containing tenant and client
        credentials.
    :param method: HTTP method (GET, POST, PATCH, etc.).
    :param endpoint: API endpoint starting with a slash (e.g., '/users').
    :param params: Optional query parameters.
    :param data: Optional JSON body for POST/PATCH requests.
    :param extra_headers: Optional additional HTTP headers to include in the request.
        This can be used, for example, to specify the 'ConsistencyLevel' header when
        requesting counts via '/users/$count'.
    :return: Parsed JSON response, plain text response (for $count), or None if an error occurs.
    """
    token = get_access_token(org)
    if not token:
        return None
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    # Merge in any extra headers provided by the caller
    if extra_headers:
        headers.update(extra_headers)
    url = f"https://graph.microsoft.com/v1.0{endpoint}"
    try:
        response = requests.request(method, url, headers=headers, params=params, json=data)
        # If the token has expired, clear the cache entry so the next call will refresh
        if response.status_code == 401:
            token_cache.pop(org['id'], None)
            return None
        # If the response indicates an error (4xx/5xx), attempt to parse the
        # JSON error body and return it.  This allows callers to surface
        # error messages rather than always treating errors as None.
        if response.status_code >= 400:
            try:
                return response.json()
            except Exception:
                return None
        # No content indicates success without body.  Return an empty dict so callers
        # can treat None as error and truthy as success.
        if response.status_code == 204:
            return {}
        # The /$count endpoints return a plain integer in the body as text/plain
        if endpoint.endswith('/$count') or endpoint.endswith('$count'):
            return response.text.strip()
        # Otherwise return parsed JSON
        return response.json()
    except requests.RequestException as exc:
        # Log exception for debugging; return None
        print(f"Graph API error on {endpoint}: {exc}")
        return None


# Helper to fetch a role definition ID by display name.  If the role is not
# found this returns None.  This function caches results locally to avoid
# repeated API calls for the same role name.
_role_cache: Dict[str, str] = {}

# Global paging cache for user lists.  Keys are tuples of
# (organisation ID, search query, role filter, page size).  Each entry
# stores a dict containing a list of pages and the nextLink returned by
# the Graph API.  This allows pagination of large user lists without
# retrieving all users at once.  Note: this cache is not persisted and
# will reset when the application restarts.
user_paging_cache: Dict[Tuple[str, str, str, int], Dict[str, Any]] = {}


def get_role_definition_id(org: Dict[str, str], display_name: str) -> Optional[str]:
    if display_name in _role_cache:
        return _role_cache[display_name]
    params = {
        '$filter': f"displayName eq '{display_name}'",
        '$select': 'id,displayName'
    }
    resp = graph_request(org, 'GET', '/roleManagement/directory/roleDefinitions', params=params)
    if resp and 'value' in resp and resp['value']:
        role_id = resp['value'][0]['id']
        _role_cache[display_name] = role_id
        return role_id
    return None


@app.before_request
def require_login() -> None:
    """Redirect to the login page when the user is not authenticated.

    Certain routes (static assets and login pages) are exempted.  This
    provides simple password protection for the entire web application.
    """
    allowed_routes = {'login', 'do_login', 'static'}
    if request.endpoint in allowed_routes or request.endpoint is None:
        return
    if not session.get('logged_in'):
        return redirect(url_for('login'))


@app.route('/login', methods=['GET'])
def login() -> Any:
    """Render the login form."""
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def do_login() -> Any:
    """Handle login form submission."""
    password = request.form.get('password', '')
    if verify_password(password):
        session['logged_in'] = True
        return redirect(url_for('dashboard'))
    flash('密码错误，请重试。')
    return redirect(url_for('login'))


@app.route('/logout')
def logout() -> Any:
    """Clear the session and log the user out."""
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
def index() -> Any:
    """Redirect the root URL to the dashboard.

    The dashboard provides a summary of organisations and API status.  By
    redirecting the root to the dashboard the application has a clear
    landing page for administrators after login.
    """
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard() -> Any:
    """Show a high‑level overview of configured organisations and API status.

    The dashboard summarises how many organisations have been added and
    provides counts of API connectivity status (available, unavailable,
    untested).  A button allows the administrator to perform or refresh
    API tests across all organisations.  If the default login password
    has not been changed from 'admin', a warning banner is displayed at
    the top to encourage updating the password for security.
    """
    # Gather organisation list and total count
    orgs = config.get('organizations', [])
    total = len(orgs)
    # Count API status categories
    available = 0
    unavailable = 0
    for oid in org_api_status:
        status = org_api_status.get(oid)
        if status is True:
            available += 1
        elif status is False:
            unavailable += 1
    # Organisations whose status has not been tested
    untested = total - available - unavailable
    # Determine if the login password is still the default 'admin'
    default_hash = hashlib.sha256("admin".encode()).hexdigest()
    is_default_password = config.get("password_hash") == default_hash
    return render_template(
        'dashboard.html',
        organizations=orgs,
        total=total,
        available=available,
        unavailable=unavailable,
        untested=untested,
        is_default_password=is_default_password,
        active_org_id=session.get('org_id')
    )


@app.route('/set_password', methods=['GET', 'POST'])
def change_password() -> Any:
    """Allow the administrator to change the login password."""
    if request.method == 'POST':
        current_pw = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')
        if not verify_password(current_pw):
            flash('当前密码不正确。')
            return redirect(url_for('change_password'))
        if not new_pw or new_pw != confirm_pw:
            flash('新密码不能为空且两次输入必须一致。')
            return redirect(url_for('change_password'))
        set_password(new_pw)
        flash('密码已更新。请重新登录。')
        return redirect(url_for('logout'))
    return render_template('set_password.html')


@app.route('/organizations', methods=['GET', 'POST'])
def manage_orgs() -> Any:
    """Display and manage organisations.

    The page lists existing organisations and provides a form to add a new one.
    """
    if request.method == 'POST':
        name = request.form.get('name')
        client_id = request.form.get('client_id')
        tenant_id = request.form.get('tenant_id')
        client_secret = request.form.get('client_secret')
        if not all([name, client_id, tenant_id, client_secret]):
            flash('所有字段均为必填。')
            return redirect(url_for('manage_orgs'))
        org_record = {
            'id': str(uuid.uuid4()),
            'name': name,
            'client_id': client_id,
            'tenant_id': tenant_id,
            'client_secret': client_secret
        }
        config.setdefault('organizations', []).append(org_record)
        save_config(config)
        flash('已添加组织。')
        return redirect(url_for('manage_orgs'))
    return render_template('organizations.html', organizations=config.get('organizations', []), active_org_id=session.get('org_id'))


@app.route('/organizations/edit/<org_id>', methods=['GET', 'POST'])
def edit_org(org_id: str) -> Any:
    """Edit an existing organisation's connection details.

    When the form is submitted via POST the organisation record is updated
    in the configuration and persisted to disk.  On GET the current values
    are displayed in a form for editing."""
    org = get_org(org_id)
    if not org:
        flash('未找到该组织。')
        return redirect(url_for('manage_orgs'))
    if request.method == 'POST':
        name = request.form.get('name')
        client_id = request.form.get('client_id')
        tenant_id = request.form.get('tenant_id')
        client_secret = request.form.get('client_secret')
        if not all([name, client_id, tenant_id, client_secret]):
            flash('所有字段均为必填。')
            return redirect(url_for('edit_org', org_id=org_id))
        # Update the organisation fields in place
        org['name'] = name
        org['client_id'] = client_id
        org['tenant_id'] = tenant_id
        org['client_secret'] = client_secret
        save_config(config)
        flash('组织信息已更新。')
        return redirect(url_for('manage_orgs'))
    # GET request: show edit form
    return render_template('edit_org.html', org=org)


@app.route('/organizations/test/<org_id>')
def test_org(org_id: str) -> Any:
    """Test whether the configured API credentials for a single organisation are valid.

    This endpoint attempts to call a lightweight Microsoft Graph API endpoint
    (retrieving the organisation's subscribed SKUs) to verify connectivity
    and permissions.  The result is reported via flash messages."""
    org = get_org(org_id)
    if not org:
        flash('未找到该组织。')
        return redirect(url_for('manage_orgs'))
    # Attempt to fetch subscribed SKUs as a basic connectivity check
    resp = graph_request(org, 'GET', '/subscribedSkus')
    if resp is not None:
        org_api_status[org_id] = True
        flash(f"组织 {org['name']} API 测试成功。")
    else:
        org_api_status[org_id] = False
        flash(f"组织 {org['name']} API 测试失败，请检查配置。")
    return redirect(url_for('manage_orgs'))


@app.route('/organizations/test_all')
def test_all_orgs() -> Any:
    """Test API connectivity for all configured organisations.

    Each organisation is tested in turn using a lightweight Graph API
    request.  A summary of how many tests succeeded and failed is
    provided to the user via a single flash message."""
    orgs = config.get('organizations', [])
    if not orgs:
        flash('没有已配置的组织。')
        return redirect(url_for('manage_orgs'))
    success = 0
    failure = 0
    for org in orgs:
        resp = graph_request(org, 'GET', '/subscribedSkus')
        if resp is not None:
            org_api_status[org['id']] = True
            success += 1
        else:
            org_api_status[org['id']] = False
            failure += 1
    flash(f"API 测试完成：成功 {success} 个，失败 {failure} 个。")
    return redirect(url_for('manage_orgs'))


@app.route('/organizations/template')
def download_org_template() -> Any:
    """Provide a CSV template for batch importing organisation details.

    The template includes a header row with columns: name, client_id,
    tenant_id, client_secret.  Users can download and populate this file to
    import multiple organisations at once."""
    from flask import Response
    template_csv = 'name,client_id,tenant_id,client_secret\n'
    # Create a response with the CSV content
    response = Response(template_csv, mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=org_template.csv'
    return response


@app.route('/organizations/import', methods=['POST'])
def import_orgs() -> Any:
    """Import multiple organisations from an uploaded CSV file.

    Each row in the uploaded file should contain four columns: name,
    client_id, tenant_id and client_secret.  Rows with missing fields are
    skipped and an error is recorded.  Successfully parsed organisations are
    added to the configuration and persisted to disk."""
    file = request.files.get('file')
    if not file:
        flash('未选择文件。')
        return redirect(url_for('manage_orgs'))
    import csv
    import io
    success_count = 0
    errors: List[str] = []
    try:
        stream = io.StringIO(file.stream.read().decode('utf-8'))
        reader = csv.DictReader(stream)
        for idx, row in enumerate(reader, start=1):
            name = row.get('name', '').strip()
            client_id = row.get('client_id', '').strip()
            tenant_id = row.get('tenant_id', '').strip()
            client_secret = row.get('client_secret', '').strip()
            if not all([name, client_id, tenant_id, client_secret]):
                errors.append(f'第 {idx+1} 行缺少字段。')
                continue
            # Check for duplicate by name or client_id and skip if exists
            duplicate = False
            for org in config.get('organizations', []):
                if org.get('name') == name or org.get('client_id') == client_id:
                    duplicate = True
                    errors.append(f'第 {idx+1} 行重复的名称或客户端 ID。')
                    break
            if duplicate:
                continue
            # Create organisation record
            new_org = {
                'id': str(uuid.uuid4()),
                'name': name,
                'client_id': client_id,
                'tenant_id': tenant_id,
                'client_secret': client_secret
            }
            config.setdefault('organizations', []).append(new_org)
            success_count += 1
        # Persist changes if any
        if success_count > 0:
            save_config(config)
        if success_count:
            flash(f'成功导入 {success_count} 个组织。')
        if errors:
            flash('导入过程中存在问题：' + '；'.join(errors))
    except Exception as exc:
        flash(f'导入失败：{exc}')
    return redirect(url_for('manage_orgs'))


@app.route('/organizations/delete/<org_id>')
def delete_org(org_id: str) -> Any:
    """Remove an organisation from the configuration."""
    orgs = config.get('organizations', [])
    updated = [o for o in orgs if o.get('id') != org_id]
    if len(updated) != len(orgs):
        config['organizations'] = updated
        save_config(config)
        # Remove token cache entry as well
        token_cache.pop(org_id, None)
        # Clear active organisation if it was removed
        if session.get('org_id') == org_id:
            session.pop('org_id', None)
        flash('组织已删除。')
    else:
        flash('未找到该组织。')
    return redirect(url_for('manage_orgs'))


@app.route('/select_org/<org_id>')
def select_org(org_id: str) -> Any:
    """Select an organisation for subsequent operations."""
    """Select an organisation for subsequent operations.

    When called with a 'next' query parameter, the user will be
    redirected to that URL after the organisation is selected.  If no
    'next' parameter is provided, the default redirection is to the
    user management page.  This allows callers to choose whether the
    user should land on the organisation summary or another view.
    """
    if get_org(org_id):
        session['org_id'] = org_id
        flash('已切换到选定组织。')
        next_url = request.args.get('next')
        # If the next parameter is present, redirect there; otherwise to list_users
        if next_url:
            return redirect(next_url)
        return redirect(url_for('list_users'))
    flash('未找到该组织。')
    return redirect(url_for('manage_orgs'))


@app.route('/users')
def list_users() -> Any:
    """User management page with optional search and pagination.

    This view serves multiple purposes depending on the state:

    * When no organisation has been selected (``session['org_id']`` is absent),
      the page displays a list of available organisations for selection.
    * Once an organisation is selected and the ``view`` query parameter is not
      present or equals ``'summary'``, a summary of the organisation is shown,
      including licence usage and counts of administrators.  This avoids an
      expensive user list query on initial load.
    * When ``view=users`` is specified, the user list is fetched.  An optional
      ``role`` query parameter filters users by administrative role.  Paging
      parameters ``page`` and ``page_size`` control how many users to show per
      page.  A ``search`` query parameter allows filtering by display name
      or user principal name.
    """
    # If a reset flag is present, clear any previously selected organisation
    if request.args.get('reset'):
        session.pop('org_id', None)
        # Clear paging cache when resetting organisation selection
        user_paging_cache.clear()
    # Determine if an organisation has been selected via the session
    org_id = session.get('org_id')
    # Determine which view to show: summary or user list
    view_mode = request.args.get('view', 'summary')
    role_filter = request.args.get('role', '')

    # If no organisation is selected, show selection list
    if not org_id:
        return render_template(
            'users.html',
            mode='select',
            organizations=config.get('organizations', []),
            role_filter='',
            active_org_id=None
        )

    # Ensure the organisation exists
    org = get_org(org_id)
    if not org:
        flash('组织配置错误。')
        session.pop('org_id', None)
        # Clear caches for invalid organisation
        user_paging_cache.clear()
        return redirect(url_for('list_users'))

    # Summary view by default
    if view_mode != 'users':
        # Verify API connectivity before loading summary
        api_resp = graph_request(org, 'GET', '/subscribedSkus')
        if api_resp is None:
            org_api_status[org_id] = False
            return render_template(
                'users.html',
                mode='api_unavailable',
                organizations=config.get('organizations', []),
                active_org_id=org_id
            )
        # API is available; record status and compute summary
        org_api_status[org_id] = True
        summary: Dict[str, Any] = {}
        licences: List[Dict[str, Any]] = []
        if api_resp and 'value' in api_resp:
            # Attempt to fetch renewal and status information via the directory/subscriptions endpoint.
            # This endpoint returns objects keyed by skuId with fields including status and nextLifecycleDateTime.
            # Not all tenants or SKUs will have renewal information; if the call fails, we ignore it.
            renewal_info: Dict[str, Dict[str, Any]] = {}
            try:
                subs_resp = graph_request(org, 'GET', '/directory/subscriptions')
                # subs_resp may be a list of subscription objects
                if subs_resp and 'value' in subs_resp:
                    for sub in subs_resp['value']:
                        sku_id = sub.get('skuId')
                        if sku_id:
                            renewal_info[sku_id] = {
                                'status': sub.get('status'),
                                'renewal_date': sub.get('nextLifecycleDateTime')
                            }
            except Exception:
                # ignore errors – fallback to default status/renewal
                pass
            for sku in api_resp['value']:
                prepaid = sku.get('prepaidUnits', {})
                sku_part = sku.get('skuPartNumber')
                sku_id = sku.get('skuId')
                enabled = prepaid.get('enabled') or 0
                warning = prepaid.get('warning') or 0
                suspended = prepaid.get('suspended') or 0
                total = enabled + warning + suspended
                used = sku.get('consumedUnits') or 0
                available_units = total - used if total >= used else 0
                # Translate capabilityStatus
                capability = sku.get('capabilityStatus')
                status_label = CAPABILITY_STATUS_LABELS.get(capability, capability or '未知')
                # Renewal date from directory/subscriptions
                renewal = None
                if sku_id and sku_id in renewal_info:
                    renewal = renewal_info[sku_id].get('renewal_date')
                licences.append({
                    'productName': get_product_name_for_sku(sku_part),
                    'skuPartNumber': sku_part,
                    'ratio': f"{used}/{total}" if total > 0 else f"{used}/{used}",
                    'available': available_units,
                    'status': status_label,
                    'renewal': renewal or '未知'
                })
        summary['licences'] = licences
        # Count Global and Privileged administrators
        global_admin_count = 0
        privileged_admin_count = 0
        ga_id = get_role_definition_id(org, 'Global Administrator')
        pra_id = get_role_definition_id(org, 'Privileged Role Administrator')
        if ga_id:
            ga_assignments = graph_request(org, 'GET', '/roleManagement/directory/roleAssignments', params={'$filter': f"roleDefinitionId eq '{ga_id}'"})
            global_admin_count = len(ga_assignments.get('value', [])) if ga_assignments else 0
        if pra_id:
            pra_assignments = graph_request(org, 'GET', '/roleManagement/directory/roleAssignments', params={'$filter': f"roleDefinitionId eq '{pra_id}'"})
            privileged_admin_count = len(pra_assignments.get('value', [])) if pra_assignments else 0
        summary['global_admin_count'] = global_admin_count
        summary['privileged_admin_count'] = privileged_admin_count
        # Retrieve total user count if possible
        total_users: Optional[int] = None
        count_resp = graph_request(org, 'GET', '/users/$count', extra_headers={'ConsistencyLevel': 'eventual'})
        try:
            if count_resp is not None:
                total_users = int(count_resp)
        except ValueError:
            total_users = None
        summary['total_users'] = total_users
        return render_template(
            'users.html',
            mode='summary',
            summary=summary,
            organizations=config.get('organizations', []),
            active_org_id=org_id
        )

    # view_mode == 'users' – build user list with pagination and search
    # If a refresh flag is present, clear the paging cache so the list will be re-fetched
    if request.args.get('refresh'):
        user_paging_cache.clear()
    # Parse paging and search parameters
    try:
        page = int(request.args.get('page', '1'))
        if page < 1:
            page = 1
    except ValueError:
        page = 1
    try:
        page_size = int(request.args.get('page_size', '50'))
        # Limit page_size to a reasonable range (10–200)
        if page_size < 10:
            page_size = 10
        if page_size > 200:
            page_size = 200
    except ValueError:
        page_size = 50
    search_query = request.args.get('search', '').strip()

    users: List[Dict[str, Any]] = []
    has_next: bool = False
    has_prev: bool = page > 1

    total_pages: Optional[int] = None  # Number of pages for page navigation
    if role_filter:
        # When a specific role is selected, fetch all assignments and then page locally.
        role_id = get_role_definition_id(org, role_filter)
        if not role_id:
            flash(f'无法找到角色 {role_filter}。')
            return redirect(url_for('list_users'))
        assignments = graph_request(org, 'GET', '/roleManagement/directory/roleAssignments', params={'$filter': f"roleDefinitionId eq '{role_id}'"})
        principal_ids = [a['principalId'] for a in assignments.get('value', [])]
        # Fetch user details for each principal ID
        all_users: List[Dict[str, Any]] = []
        for uid in principal_ids:
            # Include givenName and surname when selecting fields
            user_data = graph_request(org, 'GET', f'/users/{uid}', params={'$select': 'id,displayName,userPrincipalName,mail,givenName,surname'})
            if user_data:
                # Apply search filtering if provided; match displayName, UPN, givenName or surname
                if search_query:
                    q = search_query.lower()
                    dn = (user_data.get('displayName') or '').lower()
                    upn = (user_data.get('userPrincipalName') or '').lower()
                    given = (user_data.get('givenName') or '').lower()
                    sur = (user_data.get('surname') or '').lower()
                    if not (dn.startswith(q) or upn.startswith(q) or given.startswith(q) or sur.startswith(q)):
                        continue
                all_users.append(user_data)
        # Determine total pages based on page_size
        total_pages = (len(all_users) + page_size - 1) // page_size
        # Bound the page number
        if page > total_pages and total_pages > 0:
            page = total_pages
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        users = all_users[start_idx:end_idx]
        has_prev = page > 1
        has_next = page < total_pages
    else:
        # No role filter: use paging cache and Graph API nextLink to avoid refetching
        cache_key = (org_id, search_query.lower(), role_filter, page_size)
        cache_entry = user_paging_cache.get(cache_key)
        if not cache_entry:
            cache_entry = {'pages': [], 'next_link': None}
            user_paging_cache[cache_key] = cache_entry
        pages: List[List[Dict[str, Any]]] = cache_entry['pages']
        next_link = cache_entry.get('next_link')
        # Fetch pages until we have at least the desired page or no more data
        while len(pages) < page and (next_link or not pages):
            if not pages:
                # Fetch first page
                params: Dict[str, str] = {
                    '$select': 'id,displayName,userPrincipalName,mail,givenName,surname',
                    '$top': str(page_size)
                }
                # Apply search filter if provided
                if search_query:
                    # Use startswith for displayName, userPrincipalName, givenName and surname
                    safe_q = search_query.replace("'", "''")
                    params['$filter'] = (
                        f"startswith(displayName,'{safe_q}') or startswith(userPrincipalName,'{safe_q}') "
                        f"or startswith(givenName,'{safe_q}') or startswith(surname,'{safe_q}')"
                    )
                response = graph_request(org, 'GET', '/users', params=params)
                if not response:
                    break
                page_users = response.get('value', [])
                pages.append(page_users)
                # Capture nextLink if present
                next_link = response.get('@odata.nextLink')
                cache_entry['next_link'] = next_link
            else:
                # Fetch the next page using the stored nextLink
                if not next_link:
                    break
                # Next link is a full URL; extract the path after the domain
                prefix = 'https://graph.microsoft.com/v1.0'
                if next_link.startswith(prefix):
                    next_endpoint = next_link[len(prefix):]
                else:
                    next_endpoint = next_link
                response = graph_request(org, 'GET', next_endpoint)
                if not response:
                    break
                page_users = response.get('value', [])
                pages.append(page_users)
                next_link = response.get('@odata.nextLink')
                cache_entry['next_link'] = next_link
        # Determine page bounds
        if page > len(pages) and len(pages) > 0:
            page = len(pages)
        if len(pages) > 0:
            users = pages[page - 1]
        has_prev = page > 1
        # Next page exists if there are more pages in cache or a nextLink
        has_next = (page < len(pages)) or (cache_entry.get('next_link') is not None and len(pages) == page)

        # Compute total pages for navigation.  When search filtering is applied or no role filter is used,
        # query the Graph API for the count of matching users to determine the number of pages.  If the
        # count request fails, fall back to estimating based on whether a next page exists.
        try:
            count_params: Dict[str, str] = {}
            if search_query:
                safe_q = search_query.replace("'", "''")
                count_params['$filter'] = (
                    f"startswith(displayName,'{safe_q}') or startswith(userPrincipalName,'{safe_q}') "
                    f"or startswith(givenName,'{safe_q}') or startswith(surname,'{safe_q}')"
                )
            count_resp = graph_request(org, 'GET', '/users/$count', params=count_params, extra_headers={'ConsistencyLevel': 'eventual'})
            if count_resp is not None:
                total_count = int(count_resp)
                total_pages = (total_count + page_size - 1) // page_size if total_count > 0 else 1
            else:
                total_pages = page + 1 if has_next else page
        except Exception:
            # On any error, approximate total pages based on current page and next
            total_pages = page + 1 if has_next else page

    # Fetch admin assignments once to mark roles for current page
    global_admin_set: set = set()
    privileged_admin_set: set = set()
    ga_id = get_role_definition_id(org, 'Global Administrator')
    pra_id = get_role_definition_id(org, 'Privileged Role Administrator')
    if ga_id:
        ga_assignments = graph_request(org, 'GET', '/roleManagement/directory/roleAssignments', params={'$filter': f"roleDefinitionId eq '{ga_id}'"})
        global_admin_set = {a['principalId'] for a in ga_assignments.get('value', [])}
    if pra_id:
        pra_assignments = graph_request(org, 'GET', '/roleManagement/directory/roleAssignments', params={'$filter': f"roleDefinitionId eq '{pra_id}'"})
        privileged_admin_set = {a['principalId'] for a in pra_assignments.get('value', [])}
    # Annotate users with role flags
    for u in users:
        uid = u.get('id')
        u['is_global_admin'] = uid in global_admin_set
        u['is_privileged_admin'] = uid in privileged_admin_set
    # Build a list of page numbers to display around the current page for navigation (max 5 pages)
    if total_pages is None or total_pages < 1:
        total_pages = 1
    start_page = max(1, page - 2)
    end_page = min(total_pages, page + 2)
    page_numbers = list(range(start_page, end_page + 1))
    return render_template(
        'users.html',
        mode='list',
        users=users,
        role_filter=role_filter,
        search=search_query,
        page=page,
        page_size=page_size,
        has_prev=has_prev,
        has_next=has_next,
        total_pages=total_pages,
        page_numbers=page_numbers,
        organizations=config.get('organizations', []),
        active_org_id=org_id
    )


@app.route('/user/<user_id>')
def user_detail(user_id: str) -> Any:
    """Show detailed information for a single user, including roles and licences."""
    org_id = session.get('org_id')
    org = get_org(org_id) if org_id else None
    if not org:
        flash('请先选择组织。')
        return redirect(url_for('manage_orgs'))

    # Fetch user object with additional attributes.  Only select properties
    # required for display to avoid retrieving unnecessary data.  In particular,
    # accountEnabled, createdDateTime, and lastPasswordChangeDateTime are not
    # returned by default and must be explicitly selected according to the
    # Microsoft Graph documentation【787419988700041†L450-L461】.  These fields
    # help administrators see whether the account is enabled and view basic
    # account lifecycle information.
    user = graph_request(
        org,
        'GET',
        f'/users/{user_id}',
        params={
            '$select': 'id,displayName,userPrincipalName,accountEnabled,lastPasswordChangeDateTime,createdDateTime'
        }
    )
    if not user:
        flash('无法获取用户信息。')
        return redirect(url_for('list_users'))

    # Fetch role assignments for this user, expanding the roleDefinition to get the display name
    roles_resp = graph_request(org, 'GET', '/roleManagement/directory/roleAssignments', params={'$filter': f"principalId eq '{user_id}'", '$expand': 'roleDefinition'})
    roles: List[str] = []
    is_global_admin = False
    is_privileged_admin = False
    if roles_resp and 'value' in roles_resp:
        for assignment in roles_resp['value']:
            role_def = assignment.get('roleDefinition', {})
            display = role_def.get('displayName', role_def.get('id'))
            roles.append(display)
            if display == 'Global Administrator':
                is_global_admin = True
            if display == 'Privileged Role Administrator':
                is_privileged_admin = True

    # Fetch licence details for the user, but we only keep top-level fields to avoid showing service plans
    licence_resp = graph_request(org, 'GET', f'/users/{user_id}/licenseDetails')
    licence_details_raw = licence_resp.get('value', []) if licence_resp else []
    # Simplify licence details: only include skuPartNumber
    licence_details = []
    for lic in licence_details_raw:
        part = lic.get('skuPartNumber')
        licence_details.append({
            'skuPartNumber': part,
            'productName': get_product_name_for_sku(part)
        })

    # Determine current role for default selection in UI
    if is_global_admin:
        current_role = 'Global Administrator'
    elif is_privileged_admin:
        current_role = 'Privileged Role Administrator'
    else:
        current_role = 'normal'

    return render_template(
        'user_detail.html',
        user=user,
        roles=roles,
        licence_details=licence_details,
        current_role=current_role,
        organizations=config.get('organizations', []),
        active_org_id=org_id
    )


@app.route('/user/<user_id>/license', methods=['GET', 'POST'])
def assign_licence(user_id: str) -> Any:
    """Assign licences to the specified user.

    This view lists available subscribed SKUs (licences) in the current tenant
    and allows the administrator to add one or more licences.  Existing
    assignments are preselected in the UI.  Removal of licences is not
    supported at this time.
    """
    org_id = session.get('org_id')
    org = get_org(org_id) if org_id else None
    if not org:
        flash('请先选择组织。')
        return redirect(url_for('manage_orgs'))
    # Handle licence assignment submission
    if request.method == 'POST':
        # Retrieve selected SKU IDs from the form (multiple selection)
        selected_sku_ids = request.form.getlist('sku_ids')
        # Fetch currently assigned licences to compare additions and removals
        current_lic_resp = graph_request(org, 'GET', f'/users/{user_id}/licenseDetails')
        current_sku_ids: set = set()
        if current_lic_resp and 'value' in current_lic_resp:
            for lic in current_lic_resp['value']:
                sid = lic.get('skuId')
                if sid:
                    current_sku_ids.add(sid)
        # Determine which SKUs to add and which to remove
        selected_set = set(selected_sku_ids)
        add_list: List[Dict[str, Any]] = []
        remove_list: List[str] = []
        # Add licences not currently assigned
        for sid in selected_set:
            if sid not in current_sku_ids:
                add_list.append({'skuId': sid, 'disabledPlans': []})
        # Remove licences that were assigned but are now unchecked
        for sid in current_sku_ids:
            if sid not in selected_set:
                remove_list.append(sid)
        # If neither adding nor removing, nothing to do
        if not add_list and not remove_list:
            flash('未检测到订阅变更。')
            return redirect(url_for('user_detail', user_id=user_id))
        payload = {
            'addLicenses': add_list,
            'removeLicenses': remove_list
        }
        resp = graph_request(org, 'POST', f'/users/{user_id}/assignLicense', data=payload)
        # Determine if the response indicates an error
        error_msg = ''
        if resp is None:
            error_msg = '令牌无效或权限不足'
        elif isinstance(resp, dict) and resp.get('error'):
            err = resp.get('error') or {}
            error_msg = err.get('message', '')
        if error_msg:
            flash('订阅更新失败：' + error_msg)
        else:
            flash('订阅已成功更新。')
        return redirect(url_for('user_detail', user_id=user_id))
    # GET request: fetch available SKUs and current assignments
    skus_resp = graph_request(org, 'GET', '/subscribedSkus')
    all_skus = skus_resp.get('value', []) if skus_resp else []
    current_lic_resp = graph_request(org, 'GET', f'/users/{user_id}/licenseDetails')
    assigned_ids: set = set()
    if current_lic_resp and 'value' in current_lic_resp:
        for lic in current_lic_resp['value']:
            sid = lic.get('skuId')
            if sid:
                assigned_ids.add(sid)
    # Attempt to fetch renewal information for subscription statuses
    renewal_info: Dict[str, Dict[str, Any]] = {}
    try:
        subs_resp = graph_request(org, 'GET', '/directory/subscriptions')
        if subs_resp and 'value' in subs_resp:
            for sub in subs_resp['value']:
                sku_id = sub.get('skuId')
                if sku_id:
                    renewal_info[sku_id] = {
                        'status': sub.get('status'),
                        'renewal_date': sub.get('nextLifecycleDateTime')
                    }
    except Exception:
        pass
    # Build enriched list for the template
    enriched_skus: List[Dict[str, Any]] = []
    for sku in all_skus:
        sku_id = sku.get('skuId')
        sku_part = sku.get('skuPartNumber')
        prepaid = sku.get('prepaidUnits', {})
        enabled = prepaid.get('enabled') or 0
        warning = prepaid.get('warning') or 0
        suspended = prepaid.get('suspended') or 0
        total = enabled + warning + suspended
        used = sku.get('consumedUnits') or 0
        available_units = total - used if total >= used else 0
        capability = sku.get('capabilityStatus')
        status_label = CAPABILITY_STATUS_LABELS.get(capability, capability or '未知')
        renewal_date = '未知'
        if sku_id and sku_id in renewal_info:
            renewal_date = renewal_info[sku_id].get('renewal_date') or '未知'
        enriched_skus.append({
            'skuId': sku_id,
            'skuPartNumber': sku_part,
            'productName': get_product_name_for_sku(sku_part),
            'ratio': f"{used}/{total}" if total > 0 else f"{used}/{used}",
            'available': available_units,
            'status': status_label,
            'renewal': renewal_date,
            'assigned': sku_id in assigned_ids
        })
    return render_template('assign_license.html', user_id=user_id, skus=enriched_skus)


@app.route('/user/<user_id>/update', methods=['POST'])
def update_user(user_id: str) -> Any:
    """Update a user's password and administrative role.

    The administrator may provide a new password and/or select a new role.
    Only fields that are explicitly changed will be applied.  Role updates
    involve adding or removing assignments for Global Administrator and
    Privileged Role Administrator roles as appropriate.  Password updates
    use the Graph API to update the user's passwordProfile."""
    org_id = session.get('org_id')
    org = get_org(org_id) if org_id else None
    if not org:
        flash('请先选择组织。')
        return redirect(url_for('manage_orgs'))

    # Fetch new values from form
    new_password = request.form.get('new_password', '').strip()
    selected_role = request.form.get('role')
    # Account enabled flag: value will be 'true' or 'false' (or None if not provided)
    account_enabled_str = request.form.get('account_enabled')

    # Build a single patch payload combining password and accountEnabled updates.
    # According to the Microsoft Graph documentation, multiple properties can be
    # updated in a single PATCH request【139664042075369†L690-L723】.  Combining
    # updates reduces the number of requests and helps avoid partial failures.
    patch_payload: Dict[str, Any] = {}
    # Include password profile if a new password has been provided
    if new_password:
        patch_payload['passwordProfile'] = {
            'forceChangePasswordNextSignIn': False,
            'password': new_password
        }
    # Include accountEnabled property if the form included it
    if account_enabled_str is not None:
        new_status = account_enabled_str.lower() == 'true'
        patch_payload['accountEnabled'] = new_status
    # If there is any property to update, send the PATCH request
    if patch_payload:
        update_resp = graph_request(org, 'PATCH', f'/users/{user_id}', data=patch_payload)
        # Determine if the response indicates an error.  graph_request returns
        # error details as a dictionary containing an 'error' field when the
        # status code is 4xx/5xx.  A None response indicates an authentication
        # failure.  An empty dict indicates success (204 No Content).
        error_msg = ''
        if update_resp is None:
            error_msg = '令牌无效或权限不足'
        elif isinstance(update_resp, dict) and update_resp.get('error'):
            err = update_resp.get('error') or {}
            error_msg = err.get('message', '')
        if error_msg:
            # One or more updates failed; display Graph error message
            msgs: List[str] = []
            if 'passwordProfile' in patch_payload:
                msgs.append('密码更新')
            if 'accountEnabled' in patch_payload:
                msgs.append('账户启用状态更新')
            flash('、'.join(msgs) + '失败：' + error_msg)
        else:
            # At least one update succeeded.  Provide separate success messages
            if 'passwordProfile' in patch_payload:
                flash('密码已更新。')
            if 'accountEnabled' in patch_payload:
                flash('账户启用状态已更新。')

    # Update role if selected
    if selected_role:
        # Determine role definition IDs
        ga_id = get_role_definition_id(org, 'Global Administrator')
        pra_id = get_role_definition_id(org, 'Privileged Role Administrator')
        # Fetch existing assignments for this user
        assignments_resp = graph_request(org, 'GET', '/roleManagement/directory/roleAssignments', params={'$filter': f"principalId eq '{user_id}'"})
        assignments = assignments_resp.get('value', []) if assignments_resp else []
        # Determine if GA or PRA assignments exist
        ga_assignment_id = None
        pra_assignment_id = None
        for a in assignments:
            if ga_id and a.get('roleDefinitionId') == ga_id:
                ga_assignment_id = a['id']
            if pra_id and a.get('roleDefinitionId') == pra_id:
                pra_assignment_id = a['id']
        # Helper to assign role
        def add_role_assignment(role_def_id: str) -> None:
            data = {
                'principalId': user_id,
                'roleDefinitionId': role_def_id,
                'directoryScopeId': '/'
            }
            graph_request(org, 'POST', '/roleManagement/directory/roleAssignments', data=data)
        # Helper to remove assignment by ID
        def remove_assignment(assignment_id: str) -> None:
            graph_request(org, 'DELETE', f'/roleManagement/directory/roleAssignments/{assignment_id}')
        # Process according to selected role
        if selected_role == 'normal':
            # Remove any admin roles
            if ga_assignment_id:
                remove_assignment(ga_assignment_id)
            if pra_assignment_id:
                remove_assignment(pra_assignment_id)
            flash('已设置为普通用户。')
        elif selected_role == 'Global Administrator':
            # Ensure GA assignment exists
            if not ga_assignment_id and ga_id:
                add_role_assignment(ga_id)
            # Remove PRA if exists
            if pra_assignment_id:
                remove_assignment(pra_assignment_id)
            flash('已设置为全局管理员。')
        elif selected_role == 'Privileged Role Administrator':
            # Ensure PRA assignment exists
            if not pra_assignment_id and pra_id:
                add_role_assignment(pra_id)
            # Remove GA if exists
            if ga_assignment_id:
                remove_assignment(ga_assignment_id)
            flash('已设置为特权角色管理员。')
    return redirect(url_for('user_detail', user_id=user_id))

# ---------------------------------------------------------------------------
# User deletion

@app.route('/user/<user_id>/delete', methods=['GET', 'POST'])
def delete_user(user_id: str) -> Any:
    """Delete a user from the currently selected organisation.

    GET requests render a confirmation page to avoid accidental deletion.
    POST requests perform the deletion via the Graph API.  This operation is
    irreversible.  Appropriate permissions (e.g., User.ReadWrite.All or
    Directory.ReadWrite.All) are required.  When using the web UI, a
    secondary confirmation is shown before proceeding.
    """
    org_id = session.get('org_id')
    org = get_org(org_id) if org_id else None
    if not org:
        flash('请先选择组织。')
        return redirect(url_for('manage_orgs'))
    # If GET, show confirmation page with user info
    if request.method == 'GET':
        # Fetch user to display their name; ignore if fails
        user = graph_request(org, 'GET', f'/users/{user_id}', params={'$select': 'displayName,userPrincipalName'})
        return render_template('delete_user.html', user=user, user_id=user_id)
    # POST: perform deletion
    # Send DELETE to /users/{id}
    # Before deleting the user, remove any administrative role assignments.  Some tenants
    # may forbid deletion of users who hold roles such as Global Administrator or
    # Privileged Role Administrator.  Fetch assignments and remove them one by one.
    try:
        assignments_resp = graph_request(org, 'GET', '/roleManagement/directory/roleAssignments', params={'$filter': f"principalId eq '{user_id}'"})
        if assignments_resp and 'value' in assignments_resp:
            for assignment in assignments_resp['value']:
                assn_id = assignment.get('id')
                if assn_id:
                    graph_request(org, 'DELETE', f"/roleManagement/directory/roleAssignments/{assn_id}")
    except Exception:
        # Ignore errors when removing role assignments; deletion may still succeed
        pass
    # Attempt to delete the user
    resp = graph_request(org, 'DELETE', f'/users/{user_id}')
    # If the response indicates an error: None or a dict containing an 'error'.
    # An empty dict ({}), returned for 204 No Content, signifies success.
    if resp is None or (isinstance(resp, dict) and resp.get('error')):
        error_msg = ''
        if isinstance(resp, dict):
            err = resp.get('error') or {}
            error_msg = err.get('message', '')
        # If the deletion failed due to insufficient privileges, attempt to remove
        # any remaining role assignments and retry deletion once more.  If it
        # still fails, display the error with a suggestion for manual intervention.
        insufficient = False
        if error_msg and 'insufficient privileges' in error_msg.lower():
            insufficient = True
        if insufficient:
            # Remove roles and schedule deletion attempts in the background.  A separate
            # thread will attempt to delete the user multiple times until it succeeds.
            def delete_user_later(org_copy: Dict[str, str], uid: str) -> None:
                for _ in range(5):
                    # Remove all role assignments
                    try:
                        assignments_resp2 = graph_request(org_copy, 'GET', '/roleManagement/directory/roleAssignments', params={'$filter': f"principalId eq '{uid}'"})
                        if assignments_resp2 and 'value' in assignments_resp2:
                            for assignment in assignments_resp2['value']:
                                assn_id2 = assignment.get('id')
                                if assn_id2:
                                    graph_request(org_copy, 'DELETE', f"/roleManagement/directory/roleAssignments/{assn_id2}")
                    except Exception:
                        pass
                    # Attempt deletion
                    resp_retry = graph_request(org_copy, 'DELETE', f'/users/{uid}')
                    # Success if resp_retry is not None and does not contain error
                    if resp_retry is not None and not (isinstance(resp_retry, dict) and resp_retry.get('error')):
                        # Clear cache to reflect deletion
                        user_paging_cache.clear()
                        print(f"[Deferred deletion] User {uid} deleted successfully")
                        return
                    # Wait before next attempt
                    time.sleep(5)
                    # Continue loop if not succeeded
                # After attempts, log failure
                print(f"[Deferred deletion] Failed to delete user {uid} after retries")
            org_copy = dict(org)
            threading.Thread(target=delete_user_later, args=(org_copy, user_id), daemon=True).start()
            flash('删除任务已提交，后台将尝试删除该用户，请稍后刷新列表查看。')
            return redirect(url_for('list_users', view='users'))
        # Final failure message
        flash('删除用户失败：' + (error_msg if error_msg else '请检查权限或用户状态。'))
        return redirect(url_for('user_detail', user_id=user_id))
    # Deletion succeeded.  Clear the user list cache so it refreshes.
    user_paging_cache.clear()
    flash('用户已删除。')
    return redirect(url_for('list_users', view='users'))

# ---------------------------------------------------------------------------
# User creation

@app.route('/users/add', methods=['GET', 'POST'])
def add_user() -> Any:
    """Create a new user in the currently selected organisation.

    On GET, this view displays a form allowing entry of a display name,
    user principal name, selection of licences to assign and the desired
    administrative role.  On POST, it creates the user with a random
    initial password, assigns the chosen licences and role, and then
    displays the credentials for copying.  If any step fails, an error
    message is flashed and the form is redisplayed.
    """
    org_id = session.get('org_id')
    org = get_org(org_id) if org_id else None
    if not org:
        flash('请先选择组织。')
        return redirect(url_for('manage_orgs'))

    if request.method == 'POST':
        display_name = request.form.get('display_name', '').strip()
        local_part = request.form.get('local_part', '').strip()
        domain = request.form.get('domain')
        selected_sku_ids = request.form.getlist('sku_ids')
        role = request.form.get('role', 'normal')
        # Basic validation
        if not display_name or not local_part:
            flash('显示名称和用户名为必填。')
            return redirect(url_for('add_user'))
        if not domain:
            flash('请选择域名。')
            return redirect(url_for('add_user'))
        # Construct UPN from local part and domain
        upn = f"{local_part}@{domain}"
        # Generate a secure temporary password that meets complexity requirements.
        # Microsoft Graph enforces password complexity rules (uppercase, lowercase,
        # digit and special character).  Use secrets.choice to build a 12‑character
        # password containing at least one of each category.
        alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + '!@#$%^&*()'
        # Ensure at least one character from each class
        temp_password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice('!@#$%^&*()')
        ]
        # Fill the remaining characters randomly
        temp_password += [secrets.choice(alphabet) for _ in range(8)]
        # Shuffle to avoid predictable positions
        secrets.SystemRandom().shuffle(temp_password)
        temp_password = ''.join(temp_password)
        # mailNickname uses local part
        mail_nickname = local_part
        # Determine usage location for licence assignment.  If the tenant's
        # organisation record specifies a country code, use it; otherwise
        # default to 'US'.  Some licence assignments require a usage location.
        usage_location = 'US'
        try:
            org_info = graph_request(org, 'GET', '/organization')
            if org_info and 'value' in org_info and len(org_info['value']) > 0:
                country_code = org_info['value'][0].get('countryLetterCode')
                if country_code:
                    usage_location = country_code
        except Exception:
            pass
        # Build user creation payload.  Include userType and usageLocation to
        # improve compatibility.  Force password change on next sign-in.
        user_payload = {
            'accountEnabled': True,
            'userType': 'Member',
            'displayName': display_name,
            'mailNickname': mail_nickname,
            'userPrincipalName': upn,
            'usageLocation': usage_location,
            'passwordProfile': {
                'forceChangePasswordNextSignIn': True,
                'password': temp_password
            }
        }
        # Create user
        create_resp = graph_request(org, 'POST', '/users', data=user_payload)
        if not create_resp or not isinstance(create_resp, dict) or not create_resp.get('id'):
            # Attempt to surface Graph API error details if available
            error_msg = ''
            if isinstance(create_resp, dict):
                # Graph errors are returned in an 'error' object with a 'message'
                err = create_resp.get('error') or {}
                error_msg = err.get('message', '')
            flash('创建用户失败，请检查输入或权限。' + (f" 错误详情：{error_msg}" if error_msg else ''))
            return redirect(url_for('add_user'))
        new_user_id = create_resp['id']
        # Assign licences if any selected
        if selected_sku_ids:
            add_list = [{'skuId': sid, 'disabledPlans': []} for sid in selected_sku_ids]
            assign_payload = {
                'addLicenses': add_list,
                'removeLicenses': []
            }
            lic_resp = graph_request(org, 'POST', f'/users/{new_user_id}/assignLicense', data=assign_payload)
            if lic_resp is None:
                flash('分配订阅时出现问题，请稍后检查。')
        # Assign administrative role asynchronously if necessary.  To avoid
        # failures caused by eventual consistency delays, schedule the role
        # assignment in a background thread a few seconds after user creation.
        if role and role != 'normal':
            def assign_role_later(org_copy: Dict[str, str], uid: str, selected_role: str) -> None:
                # Attempt to assign the selected role multiple times.  Wait a few seconds
                # between attempts to allow the new user to propagate.
                for _ in range(5):
                    time.sleep(5)
                    ga = get_role_definition_id(org_copy, 'Global Administrator')
                    pra = get_role_definition_id(org_copy, 'Privileged Role Administrator')
                    role_id = None
                    if selected_role == 'Global Administrator':
                        role_id = ga
                    elif selected_role == 'Privileged Role Administrator':
                        role_id = pra
                    if role_id:
                        data = {
                            'principalId': uid,
                            'roleDefinitionId': role_id,
                            'directoryScopeId': '/'
                        }
                        resp = graph_request(org_copy, 'POST', '/roleManagement/directory/roleAssignments', data=data)
                        if resp is not None and not (isinstance(resp, dict) and resp.get('error')):
                            # Success
                            print(f"[Deferred role assignment] Role assigned to user {uid} successfully")
                            return
                        # Log failure and retry
                        err_msg = ''
                        if isinstance(resp, dict):
                            err = resp.get('error') or {}
                            err_msg = err.get('message', '')
                        print(f"[Deferred role assignment] Attempt failed for user {uid}: {err_msg}")
                    # continue loop until success
                print(f"[Deferred role assignment] Gave up assigning role to user {uid}")
            org_copy = dict(org)
            threading.Thread(target=assign_role_later, args=(org_copy, new_user_id, role), daemon=True).start()
            flash(f'用户已创建。用户名：{upn} 临时密码：{temp_password}（角色分配正在后台处理，请稍后查看）')
            return redirect(url_for('user_detail', user_id=new_user_id))
        # If no special role, simply provide credentials and redirect to user detail
        flash(f'用户已创建。用户名：{upn} 临时密码：{temp_password}')
        return redirect(url_for('user_detail', user_id=new_user_id))

    # GET request: display form
    # Fetch available SKUs with details for selection
    skus_resp = graph_request(org, 'GET', '/subscribedSkus')
    all_skus = skus_resp.get('value', []) if skus_resp else []
    # Attempt to fetch renewal/status info for subscriptions
    renewal_info: Dict[str, Dict[str, Any]] = {}
    try:
        subs_resp = graph_request(org, 'GET', '/directory/subscriptions')
        if subs_resp and 'value' in subs_resp:
            for sub in subs_resp['value']:
                sid = sub.get('skuId')
                if sid:
                    renewal_info[sid] = {
                        'status': sub.get('status'),
                        'renewal_date': sub.get('nextLifecycleDateTime')
                    }
    except Exception:
        pass
    enriched_skus: List[Dict[str, Any]] = []
    for sku in all_skus:
        sku_id = sku.get('skuId')
        sku_part = sku.get('skuPartNumber')
        prepaid = sku.get('prepaidUnits', {})
        enabled = prepaid.get('enabled') or 0
        warning = prepaid.get('warning') or 0
        suspended = prepaid.get('suspended') or 0
        total = enabled + warning + suspended
        used = sku.get('consumedUnits') or 0
        available_units = total - used if total >= used else 0
        capability = sku.get('capabilityStatus')
        status_label = CAPABILITY_STATUS_LABELS.get(capability, capability or '未知')
        renewal_date = '未知'
        if sku_id and sku_id in renewal_info:
            renewal_date = renewal_info[sku_id].get('renewal_date') or '未知'
        enriched_skus.append({
            'skuId': sku_id,
            'skuPartNumber': sku_part,
            'productName': get_product_name_for_sku(sku_part),
            'ratio': f"{used}/{total}" if total > 0 else f"{used}/{used}",
            'available': available_units,
            'status': status_label,
            'renewal': renewal_date
        })
    # Fetch available domains for user creation
    domains_resp = graph_request(org, 'GET', '/domains')
    domain_options: List[str] = []
    default_domain = None
    if domains_resp and 'value' in domains_resp:
        for d in domains_resp['value']:
            # Only include verified or root domains
            name = d.get('id')
            if not name:
                continue
            # Exclude special domains like *.onmicrosoft.com when other domains exist
            domain_options.append(name)
        # Choose default domain: prefer non‑onmicrosoft.com; otherwise first
        for name in domain_options:
            if not name.endswith('.onmicrosoft.com'):
                default_domain = name
                break
        if not default_domain and domain_options:
            default_domain = domain_options[0]
    return render_template('add_user.html', skus=enriched_skus, domains=domain_options, default_domain=default_domain)


if __name__ == '__main__':
    # Run the Flask development server when executed directly.  In production
    # the Dockerfile will invoke gunicorn to serve the app.
    app.run(host='0.0.0.0', port=5000, debug=True)

# Provide helper functions to templates
@app.context_processor
def inject_helpers() -> Dict[str, Any]:
    """Inject helper functions and variables into Jinja templates."""
    return {
        'get_org': get_org,
        'config': config,
        'org_api_status': org_api_status,
        'active_org_id': session.get('org_id')
    }
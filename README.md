# Office 365 多租户管理工具

这是一个基于 Flask 和 MSAL 的 Web 应用，用于集中管理多个 Microsoft 365/Office 365 租户中的用户、角色和订阅。界面支持中文，具备权限管理、角色分配、订阅管理、组织切换等功能。

## ☁️ 快速启动：使用 DockerHub 镜像

如果您不想自行构建镜像，可以直接使用预构建的镜像一键运行本项目。假设您的服务器已经安装了 Docker，执行以下命令即可：

```bash
docker run -d -p 5000:5000 --name office365-manager saitomikuya/office365-manager:latest
```

运行后，访问 `http://<服务器IP>:5000` 即可进入系统。首次登录用户名默认为 `admin`，密码也为 `admin`，请在登录后立即通过“修改密码”功能更新密码以保障安全。

## 🛠 项目特点

- **多租户支持**：通过网页添加多个组织（租户）的应用程序 ID、目录 ID 及密钥，并在用户管理界面方便地切换不同组织进行操作。
- **权限安全**：系统使用登录密码保护，除拥有密码的管理员外无法访问。密码采用哈希形式存储在 `config.json` 文件中，登录成功后可在“修改密码”页面修改。
- **用户管理**：
  - 支持分页查询所有用户，不再局限于前 200 个。可以选择每页显示的数量（50、100 或 200），并通过页码快速跳转到任意页；同时可以按显示名称、登录名、姓或名进行搜索。列表页提供醒目的“刷新列表”按钮，可强制清空缓存并重新查询最新用户数据。
  - 用户列表显示显示名称、**姓、名**、登录名、角色等信息，可根据“全局管理员”或“特权角色管理员”筛选，并显示当前页用户的角色状态。列表下方提供分页导航以及“添加用户”按钮，可直接创建新用户。
  - 支持添加用户：填写显示名称和用户名前缀，系统会自动获取租户内的域名并提供下拉选择（优先选用非 `onmicrosoft.com` 域）。创建时自动设置 `usageLocation` 和 `userType`，可一次性分配多个许可证并指定管理员角色。系统生成符合 **复杂性要求** 的随机临时密码（包含大写字母、小写字母、数字和特殊字符），并提醒复制。若选择创建管理员角色，系统会在后台延迟分配该角色（一般几秒钟后生效），以避免新用户尚未完全同步导致的 “资源不存在” 错误。如需即时修改角色，可在用户详情页手动调整。
  - 查看单个用户的详情，包括角色列表、订阅（许可证）以及账户启用状态。订阅部分同时显示 **SKU 名称和对应的产品名称**。
  - 支持修改用户密码、启用/禁用账户，并在下拉框中切换角色（普通用户 / 全局管理员 / 特权角色管理员）。密码或启用状态修改成功后页面会给予反馈。若看到“更新失败”提示，请确认注册的应用已授予 `User.PasswordProfile.ReadWrite.All`、`User.EnableDisableAccount.All` 等权限。根据 Microsoft Graph 权限参考，`Directory.ReadWrite.All` 并不允许应用重置用户密码【61968289932983†L7-L10】。
    - 提供删除用户功能：在用户详情页可点击“删除用户”进入确认界面，系统会先自动撤销该用户的管理角色（如全局管理员或特权角色管理员），然后调用 Graph API 删除用户。若删除返回“Insufficient privileges”错误，系统会在后台循环尝试删除，直到成功；界面会提示“删除任务已提交，请稍后刷新列表查看”，提升体验。删除操作不可撤销，请谨慎使用，并确保已获得相应权限。
  - 订阅分配支持 **多选及撤销**：在分配订阅页面按产品名称和 SKU 列出所有租户内的许可，显示已分配/总数量、可用数量、状态和续订到期日期。用户已拥有的 SKU 默认打勾，但勾选框不再禁用，可取消勾选以撤销订阅；可用数量为 0 的 SKU 无法新增但仍可以取消已有订阅。
  - **组织概况**：在查询用户列表前，先显示租户概要信息，包括全局管理员数、特权管理员数、总用户数以及各订阅 SKU 的许可使用情况。许可信息除了 **产品名称** 和 **SKU 名称** 外，还显示 **已分配/总数量**、**可用许可证数**、**订阅状态** 以及 **续订到期日期**（若可获取）。这些信息来自 `subscribedSkus` 和 `directory/subscriptions` 接口，并结合 `sku_product_mapping.json` 映射表展示友好的产品名称。
    - 订阅状态以不同颜色展示：活动（绿色）、警告（黄色）、已禁用/已删除（红色）、已过期或未知（灰色）。
- **API 管理与检测**：组织管理界面可测试单个或全部组织的 API 配置是否可用，结果以颜色标识呈现；必要时可批量导入组织配置。
- **中文界面 & 自适应设计**：界面采用简洁的中文文本，配合自定义 CSS 样式，适用于桌面与移动浏览器。

## 📦 源码部署与本地构建

若您希望查看或修改源码，也可自行构建镜像运行：

1. 下载并解压本项目源码（包括 `Dockerfile`、`app.py`、模板与静态资源）。
2. 在项目根目录执行构建命令：

   ```bash
   docker build -t office365-manager .
   ```

3. 构建完成后运行容器：

   ```bash
   docker run -d -p 5000:5000 --name office365-manager office365-manager
   ```

   默认密码同样是 `admin`，请登陆后及时修改。

4. （可选）如果希望持久化配置和密码，请将容器中的配置文件目录挂载到宿主机。例如：

   ```bash
   docker run -d -p 5000:5000 \
     -v /path/to/persist/config.json:/usr/src/app/office365-manager/config.json \
     --name office365-manager office365-manager
   ```

5. （可选）**自定义许可映射**：项目根目录提供了 `sku_product_mapping.json` 文件，包含 Microsoft 365/Office 365 的 SKU 与产品名称的完整对应关系。本应用在启动时会自动加载该文件并覆盖默认映射。如果 Microsoft 发布了新的 SKU，您可以更新此 JSON 文件（例如通过 Excel 转换脚本生成），然后重启容器即可生效。

这样即使删除容器，配置文件也会保留在宿主机的 `/path/to/persist/config.json` 位置。

## 🔄 上传镜像到 DockerHub

如果您拥有 DockerHub 账号（如 `saitomikuya`），并希望将自己构建的镜像分享给他人，可以按照以下步骤推送：

1. 在本地构建好镜像（名称假设为 `office365-manager`）。
2. 使用您的 DockerHub 账号登录：

   ```bash
   docker login -u saitomikuya
   ```

   系统会提示您输入密码。登录成功后即可推送镜像。

3. 给镜像打标签，使其名称匹配您的仓库：

   ```bash
   docker tag office365-manager saitomikuya/office365-manager:latest
   ```

   如果需要特定版本号，可以将 `latest` 替换为其他标签。

4. 推送镜像到 DockerHub：

   ```bash
   docker push saitomikuya/office365-manager:latest
   ```

   完成后，其他用户即可通过 `docker pull saitomikuya/office365-manager:latest` 拉取镜像并按照“快速启动”章节的命令运行。

## 📁 项目结构概览

```
office365-manager/
├─ app.py                # Flask 主应用，路由与业务逻辑
├─ requirements.txt      # Python 依赖列表
├─ Dockerfile            # 构建镜像的 Docker 配置
├─ templates/            # Jinja2 模板 (HTML)
│   ├─ base.html
│   ├─ dashboard.html
│   ├─ organizations.html
│   ├─ users.html
│   ├─ user_detail.html
│   ├─ assign_license.html
│   ├─ edit_org.html
│   ├─ set_password.html
│   └─ login.html
├─ static/
│   └─ style.css         # 自定义样式表
└─ README.md             # 项目说明
```

## 🔐 使用注意事项

* 本工具仅在拥有相应 Microsoft Entra 权限（如 Directory.ReadWrite.All、User.ReadWrite.All、User.PasswordProfile.ReadWrite.All、User.EnableDisableAccount.All 等）时才能正确调用 Graph API。请确保您创建的应用已经分配了这些权限，并在组织管理页面录入正确的应用 ID、目录 ID 和密钥。对于删除用户、重置密码等操作，系统会根据 Graph 返回的错误信息直接反馈，例如提示密码复杂度不符合要求或权限不足，便于排查。
* 生产环境建议通过 HTTPS 部署，并调整 `FLASK_SECRET_KEY` 环境变量增强会话安全。
* 默认密码为 `admin`，务必在首次登录后及时修改。
* 本项目为演示性质，实现逻辑简洁明了，未考虑大规模并发或复杂的错误处理，请根据业务需求自行完善。

祝使用愉快！
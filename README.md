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
  - 支持分页查询所有用户，可以选择每页显示的数量（50、100 或 200），并通过页码快速跳转到任意页；也可以按显示名称、登录名、姓或名搜索用户。
  - 用户列表显示显示名称、姓、名、登录名、角色等信息，可以按“全局管理员”或“特权角色管理员”筛选，并显示当前页用户的角色状态。
  - 查看单个用户的详情，包括角色列表、订阅（许可证）以及账户启用状态。
  - 提供重置密码、调整角色（普通用户、全局管理员、特权角色管理员）、分配订阅和启用/禁用账户等管理功能。
- **组织概况**：在查询用户列表前，先显示租户概要信息，包括全局管理员数、特权管理员数、总用户数以及各订阅 SKU 的许可使用情况。许可信息同时展示 SKU 名称和对应的产品名称，产品名称来自 `sku_product_mapping.json` 的完整映射表，可自行扩展。
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

* 本工具仅在拥有相应 Microsoft Entra 权限（如 Directory.ReadWrite.All、User.ReadWrite.All 等）时才能正确调用 Graph API。请确保您创建的应用已经分配了这些权限，并在组织管理页面录入正确的应用 ID、目录 ID 和密钥。
* 生产环境建议通过 HTTPS 部署，并调整 `FLASK_SECRET_KEY` 环境变量增强会话安全。
* 默认密码为 `admin`，务必在首次登录后及时修改。
* 本项目为演示性质，实现逻辑简洁明了，未考虑大规模并发或复杂的错误处理，请根据业务需求自行完善。

祝使用愉快！

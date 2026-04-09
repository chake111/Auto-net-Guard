# AutoNetGuard

![Python](https://img.shields.io/badge/Python-100%25-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-未提供-lightgrey)

> 一个基于 Python 的网络守护工具：持续监测网络状态，在断线后自动触发认证重连，并通过系统托盘提供快捷管理能力。

---

## 关于项目（About The Project）

AutoNetGuard 主要面向需要门户认证（如校园网）的场景。程序在后台运行，周期性检测网络连通性；当检测到离线时，会自动执行登录重试与退避策略，并记录状态与日志。同时，项目提供系统托盘交互界面，可查看实时状态、手动触发重新登录、切换开机自启动等。

## 核心特性（Features）

- ✅ **自动连通性检测**：按配置间隔检查网络是否可用。
- 🔁 **断线自动重连**：检测离线后自动调用认证接口并重试。
- 📊 **状态可视化托盘**：托盘图标与菜单实时显示联网状态、上次登录时间、断线次数。
- 🚀 **开机自启动支持**：支持通过 Windows 注册表启用/关闭开机启动。
- ⚙️ **配置驱动**：通过 `config.ini` 管理账号、认证网关、检测地址、重试参数等。
- 🧱 **单实例运行保护**：通过 PID 文件防止重复启动。
- 📝 **滚动日志记录**：内置 RotatingFileHandler，便于长期运行排障。
- 📦 **可打包为 EXE**：提供 `build.py`，可构建为单文件后台程序。

## 前置要求（Prerequisites）

- Python **3.8+**（推荐 3.9 及以上）。
- Windows 环境（托盘与开机自启功能主要面向 Windows）。

安装依赖（仓库当前未提供 `requirements.txt`，可直接安装）：

```bash
pip install requests psutil pystray pillow
```

如需打包为 EXE，请额外安装：

```bash
pip install pyinstaller
```

## 安装与使用（Installation & Usage）

### 1) 克隆仓库

```bash
git clone https://github.com/chake111/Auto-net-Guard.git
cd Auto-net-Guard
```

### 2) 创建并编辑配置文件

将模板复制为运行配置：

```bash
# Windows
copy config.ini.example config.ini

# macOS / Linux
cp config.ini.example config.ini
```

然后编辑 `config.ini`，至少填写：

- `user_account`
- `user_password`

### 3) 启动程序

```bash
python guardian.py
```

> 启动后会在主线程运行托盘图标，并在后台线程执行网络守护逻辑。

### 4) 开机自启设置

- 启动后通过托盘菜单中的 **“开机自启动”** 开关进行启用/禁用。
- 程序通过 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 注册启动项（当前用户级）。

## 配置说明（Configuration）

配置文件：`config.ini`

| 分区 | 参数 | 说明 |
|---|---|---|
| `[credentials]` | `user_account` | 登录账号（如学号@运营商） |
| `[credentials]` | `user_password` | 登录密码 |
| `[network]` | `gateway_ip` | 认证网关 IP |
| `[network]` | `login_url` | 认证接口地址 |
| `[network]` | `referer` | 登录请求 Referer |
| `[network]` | `wlan_ac_ip` | 无线控制器 IP |
| `[network]` | `wlan_ac_name` | 无线控制器名称 |
| `[connectivity]` | `check_url` | 连通性检测 URL（返回 204 代表在线） |
| `[timing]` | `request_timeout_seconds` | 单次请求超时（秒） |
| `[timing]` | `check_interval_seconds` | 连通性检查间隔（秒） |
| `[timing]` | `login_retry_count` | 登录失败最大重试次数 |
| `[timing]` | `backoff_base_seconds` | 指数退避基准时间（秒） |
| `[logging]` | `log_file` | 日志文件名（相对运行目录） |

## 构建（Build）

项目提供 `build.py` 用于调用 PyInstaller 打包：

```bash
python build.py
```

构建完成后会在 `dist/` 目录生成：

- `AutoNetGuard.exe`
- `config.ini.example`

运行 EXE 前，请先在 `dist/` 目录下创建并填写 `config.ini`。

## 项目结构（Project Structure）

```text
Auto-net-Guard/
├── guardian.py          # 核心守护逻辑：检测网络、自动重连、日志与单实例控制
├── tray.py              # 系统托盘与交互菜单
├── autostart.py         # Windows 开机自启（注册表）
├── config.py            # 配置读取与默认值管理
├── config.ini.example   # 配置模板
└── build.py             # PyInstaller 打包脚本
```

## 贡献与许可证（Contributing & License）

欢迎通过 **Issue** 反馈问题，或提交 **Pull Request** 改进功能与文档。

本仓库当前未包含明确的 License 文件；如需开源分发，建议补充 `LICENSE` 后再进行二次使用与发布。

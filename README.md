# Auto-net-Guard

![Python](https://img.shields.io/badge/Python-100%25-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)

## 项目简介

Auto-net-Guard 是一个基于 Python 的网络监控与自动重连守护工具。程序在后台持续检测网络连通性，当发现断网或认证失效时会自动执行重连流程，并通过系统托盘提供状态查看、手动重登和开机自启管理能力。

## 核心特性

- 后台守护进程，按固定间隔检测网络状态。
- 断网后自动触发认证登录，并支持失败重试与退避。
- 系统托盘菜单显示当前状态、上次登录时间和断线次数。
- 支持从托盘菜单直接触发“立即重新登录”。
- 凭据加密存储：首次运行自动使用与当前机器绑定的 Fernet 密钥加密 `config.ini` 中的账号与密码，明文不再落盘。
- 支持开机自启开关（Windows 注册表 / macOS LaunchAgent / Linux XDG 自启动）。
- 使用 `config.ini` 管理账号、网关、检测地址和重试参数。
- 提供单实例运行保护与日志轮转记录。
- 跨平台支持：Windows、macOS、Linux 均可运行。

## 环境依赖

- Python 3.8 及以上版本。
- 支持平台：Windows、macOS、Linux。

安装基础依赖：

```bash
pip install requests psutil pystray pillow cryptography
```

如需打包：

```bash
pip install pyinstaller
```

## 安装与运行

1. 克隆仓库：

```bash
git clone https://github.com/chake111/Auto-net-Guard.git
cd Auto-net-Guard
```

1. 创建配置文件：

```bash
# Windows
copy config.ini.example config.ini

# macOS / Linux
cp config.ini.example config.ini
```

1. 编辑 `config.ini`，至少填写以下字段：

- `user_account`
- `user_password`

1. 启动程序：

```bash
python guardian.py
```

程序启动后会在主线程运行系统托盘，同时在后台线程执行网络守护逻辑。

## 配置说明

配置文件为项目根目录下的 `config.ini`。建议基于 `config.ini.example` 修改。

常用配置项说明：

- `[credentials]`
  - `user_account`：认证账号。
  - `user_password`：认证密码。
- `[network]`
  - `gateway_ip`：认证网关地址。
  - `login_url`：认证接口 URL。
  - `referer`：认证请求 Referer。
  - `wlan_ac_ip` / `wlan_ac_name`：控制器参数。
- `[connectivity]`
  - `check_url`：连通性检测地址，通常使用返回 204 的地址。
- `[timing]`
  - `request_timeout_seconds`：请求超时秒数。
  - `connectivity_timeout_seconds`：连通性检测超时秒数，默认 2 秒。
  - `check_interval_seconds`：检测间隔秒数。
  - `online_check_interval_seconds`：断线/在线状态下的快速检测间隔秒数，默认 1 秒。
  - `offline_debounce_failures`：连续失败确认次数，默认 2 次，用于过滤单次网络抖动。
  - `login_retry_count`：登录失败最大重试次数。
  - `backoff_base_seconds`：重试退避基准秒数。
- `[logging]`
  - `log_file`：日志文件名。
- `[ui]`
  - `enable_notifications`：是否弹出状态通知。
  - `status_notification_cooldown_seconds`：状态通知冷却时间，默认 2 秒，用于抑制短时间内重复弹窗。

## 构建说明

项目内置 `build.py`，用于调用 PyInstaller 进行打包：

```bash
python build.py
```

执行后会在 `dist/` 目录生成可执行文件（Windows 为 `AutoNetGuard.exe`，macOS/Linux 为 `AutoNetGuard`），并自动复制 `config.ini.example` 到同目录。运行前请在 `dist/` 下创建并填写 `config.ini`。

## 许可证与贡献

- 欢迎通过 Issue 提交问题、通过 Pull Request 提交改进。
- 本项目采用 [MIT 许可证](LICENSE) 进行开源分发，允许自由使用、修改和再分发，需保留版权声明。

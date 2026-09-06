# Secret Broker — Snap / apt / winget 安装指南

macOS 用户用 [Homebrew](HOMEBREW.md)。Windows / Ubuntu / Debian 用户用本指南。

---

## Snap (Ubuntu 16.04+)

```bash
# 1. snap 已经预装在 Ubuntu, 否则:
sudo apt update && sudo apt install -y snapd

# 2. 装 broker
sudo snap install secret-broker
# (注: snap store 还没 publish, 走 sideload — 见 maintainer 指南)

# 3. 验证
secret-broker --help
```

### Snap 自动更新

snap 装的应用默认 auto-refresh (每天 4 次 check)。`snap refresh secret-broker --stable` 手动触发。

### Snap 限制

- **首次安装慢** (3-5 min, 编译 Node.js + 拉 source)
- **strict confinement** — broker 访问 `/etc/secret-broker/` 需要 `system-files` interface (snapcraft.yaml 已经列)
- **服务需要 `--devmode` 启 daemon** 或自己写 systemd unit (snap daemon simple 也行)
- **WSL 不支持 snap**

---

## apt (Ubuntu / Debian, 通过 PPA)

```bash
# 1. 加 PPA
sudo add-apt-repository ppa:tyj1987/broker
sudo apt update

# 2. 装 broker
sudo apt install secret-broker
# 自动 resolve nodejs (>= 20) dependency

# 3. 验证
secret-broker --help
```

### 自动更新

`sudo apt upgrade` 自动跟 standard Ubuntu security update 一起。

### 已知限制

- **PPA build 慢** (5-15 min/arch on Launchpad)
- **Launchpad 只支持 Ubuntu**, 纯 Debian 用 Debian Backports 流程 (类似但不同)
- **armhf** build 在 32-bit ARM 上 (Raspberry Pi 1/Zero), 性能有限

### 不通过 PPA 装 (本地 .deb)

```bash
# build (需要 fpm + ruby)
bash deploy/apt/build-deb.sh

# install
sudo dpkg -i secret-broker_4.1.1-1_amd64.deb
sudo apt install -f   # 补装依赖 (nodejs)
```

---

## winget (Windows 10 1809+ / Windows 11)

```powershell
# 1. winget 已经预装在 Windows 11 + App Installer on Windows 10
winget --version

# 2. 装 broker
winget install tyj1987.broker
# (注: winget-pkgs 还没 PR, 走 sideload — 见 maintainer 指南)

# 3. 验证
secret-broker --help
```

### 自动更新

`winget upgrade` 自动检测。`winget upgrade tyj1987.broker` 手动触发。

### 已知限制

- **Windows only**, 不支持 macOS / Linux (用 Homebrew / Snap / apt)
- **依赖 PowerShell 5.1+** (Win10 默认有)
- **依赖 Node.js 20+** (Win 11 默认有, Win 10 要手动装 — `winget install OpenJS.NodeJS.LTS`)
- **没有 Windows service auto-register** — 服务启动是 user 责任 (NSSM / Task Scheduler / 自启脚本)

---

## 跟其他部署方式对比

| 方式 | 平台 | 优点 | 缺点 |
|------|------|------|------|
| **Homebrew** | macOS / Linux | 一行装, ecosystem 一致 | macOS/Linux 才有 |
| **Snap** | Ubuntu | 一行装, auto-update | 首次慢, strict confinement |
| **apt PPA** | Ubuntu/Debian | 系统原生包, auto-update | 首次 build 慢, 仅 Ubuntu |
| **winget** | Windows 10/11 | Windows 原生, auto-update | 依赖 Node.js, 首次要 winget-pkgs PR |
| Docker | 跨平台 | 隔离干净 | 多一层 container |
| Systemd | Linux | 性能最好, OS 集成 | 配置稍多 |
| Helm (k8s) | 跨平台 | k8s 集成 | 需 k8s 集群 |

推荐:
- **macOS 开发机**: Homebrew
- **Ubuntu 服务器**: apt PPA (PPA 已经 build 好) 或 Snap
- **Debian 服务器**: 本地 .deb (build-deb.sh) 或 Backports
- **Windows 开发机**: winget (等 winget-pkgs PR)
- **生产 HA**: Docker / Helm

---

## 故障排查

### Snap: `error: cannot perform the following tasks: ... confinement cannot be strict`

snap 在 LXD / docker 内不允许 strict confinement。改用 `--devmode`:
```bash
sudo snap install secret-broker --devmode
```

### Snap: `secret-broker: command not found`

snap bin 路径在 `/snap/bin`, 你的 PATH 可能没包含:
```bash
echo 'export PATH="$PATH:/snap/bin"' >> ~/.bashrc
source ~/.bashrc
```

### apt: `The following packages have unmet dependencies: secret-broker : Depends: nodejs (>= 20) but it is not installed`

装 Node.js 20+ (用 NodeSource):
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

### apt: `E: Unable to locate package secret-broker`

PPA 没加。重新加:
```bash
sudo add-apt-repository ppa:tyj1987/broker
sudo apt update
apt-cache search secret-broker   # 应输出 "secret-broker"
```

### winget: `Package requires NuGet provider to be installed`

装 NuGet provider:
```powershell
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
```

### winget: `No package found matching input criteria`

winget-pkgs PR 还没合并。等 maintainer PR + Microsoft review 周期 (1-4 周)。
临时方案: 走 sideload:
```powershell
Invoke-WebRequest -Uri "https://github.com/tyj1987/broker/releases/download/v4.1.1/broker-4.1.1.zip" -OutFile "broker.zip"
Expand-Archive broker.zip -DestinationPath "C:\Program Files\secret-broker"
$env:PATH += ";C:\Program Files\secret-broker"
[Environment]::SetEnvironmentVariable("Path", $env:PATH, "User")
secret-broker --help
```

---

## 反馈

- Bug: https://github.com/tyj1987/broker/issues
- Snap / apt / winget 包装 bug: 也在上面 repo (manifests 在 `snap/` `deploy/apt/` `winget/`)
- Launchpad PPA: https://launchpad.net/~tyj1987/+archive/ubuntu/broker
- winget-pkgs PR: https://github.com/microsoft/winget-pkgs/pulls?q=tyj1987

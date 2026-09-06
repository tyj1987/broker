# apt package — 发布流程 (maintainer)

## 第一次发布 (Launchpad PPA)

1. **建 Launchpad 账号** + **建 PPA**
   - https://launchpad.net/~tyj1987
   - https://launchpad.net/~tyj1987/+activate-ppa
   - `ppa:tyj1987/broker`

2. **本地 build .deb** (用 fpm — 简单):

   ```bash
   # 安装 fpm (需要 ruby)
   gem install fpm

   # build for current arch
   bash deploy/apt/build-deb.sh

   # build for amd64 / arm64 / armhf
   for arch in amd64 arm64 armhf; do
     ARCH=$arch bash deploy/apt/build-deb.sh
   done
   ```

3. **(替代) 用 debhelper** (传统 Debian 流程, 严格但慢):

   ```bash
   # 把 deploy/apt/debian/ 复制到 broker source 的根 (临时)
   cp -r deploy/apt/debian /tmp/broker-debian
   wget -O /tmp/broker-${VERSION}.tar.gz https://github.com/tyj1987/broker/releases/download/v${VERSION}/broker-${VERSION}.tar.gz
   tar -xzf /tmp/broker-${VERSION}.tar.gz -C /tmp/
   cp -r /tmp/broker-debian /tmp/broker-${VERSION}/debian
   cd /tmp/broker-${VERSION}
   dpkg-buildpackage -us -uc -b
   ls ../secret-broker_${VERSION}-*_*.deb
   ```

4. **签名 .deb + push 到 PPA**:

   ```bash
   # GPG sign (Launchpad 用 GPG key)
   debsigs --sign=origin secret-broker_4.1.1-1_amd64.deb
   dput ppa:tyj1987/broker secret-broker_4.1.1-1_amd64.changes
   ```

5. **等 build 完成** (Launchpad 自动 build amd64/arm64/armhf), 通常 5-15 min
   - https://launchpad.net/~tyj1987/+archive/ubuntu/broker

6. **验证 user 端**:
   ```bash
   sudo add-apt-repository ppa:tyj1987/broker
   sudo apt update
   sudo apt install secret-broker
   secret-broker --help
   ```

## 后续升级 (新版本 V4.x.y)

1. **broker repo**: V4.x.y release 推到 GitHub Release
2. **更新 `deploy/apt/debian/changelog`**: 新增 entry:
   ```
   secret-broker (4.x.y-1) unstable; urgency=medium
     * Release V4.x.y.
   ```
3. **更新 `deploy/apt/build-deb.sh` 里的 VERSION** (或在 env override: `VERSION=4.x.y bash build-deb.sh`)
4. **build + push PPA**: 跟上面 step 2-4 一样
5. **Merge PR** `feat/snap-apt-winget-prep` 到 master

## 检查清单 (新 .deb release 前)

- [ ] `debian/changelog`: 新 version entry
- [ ] `debian/control`: 同步 Description / Maintainer / Homepage
- [ ] `debian/compat`: 12 (debhelper 12)
- [ ] `build-deb.sh`: 3 架构都 build 成功
- [ ] PPA build: 3 架构 (amd64 / arm64 / armhf) 全 green
- [ ] `apt install secret-broker` 成功 + `secret-broker --help` 输出正常

## 已知限制

- **Launchpad PPA 只支持 Ubuntu**, 纯 Debian 用户用 Debian Backports
- **首次 build 慢** (5-15 min/arch on Launchpad), 后续 incremental 1-2 min
- **没有 systemd unit** — server setup 是 user 责任 (见 docs/HOMEBREW.md §"Server 配置" 跟 RUNBOOK.md §5)
- **GPG key 必须** 上传到 Launchpad (`gpg --keyserver keyserver.ubuntu.com --send-keys <KEY_ID>`)

# Snap package — 发布流程 (maintainer)

## 第一次发布 (Snap Store)

1. **建 Snapcraft 账号**
   - https://snapcraft.io/
   - 登录 + 注册 name `tyj1987`
   - `snapcraft login` (本地 Linux / WSL / multipass)

2. **本地 build + push**
   ```bash
   # 需要 Linux 18.04+ (snapcraft 自身)
   sudo snap install snapcraft --classic
   sudo snap install lxd
   lxd init --auto

   # 在 broker repo 根目录
   cd /path/to/broker
   # 算 source SHA256:
   curl -L https://github.com/tyj1987/broker/archive/refs/tags/v4.1.1.tar.gz | sha256sum
   # 编辑 snap/snapcraft.yaml 替换 PLACEHOLDER_SHA256_V4_1_1_TARBALL

   snapcraft
   # 输出: secret-broker_4.1.1_amd64.snap (跟 arm64, armhf)

   # push 到 edge channel
   snapcraft upload --release=edge secret-broker_4.1.1_amd64.snap
   ```

3. **测试 edge channel**
   ```bash
   sudo snap install secret-broker --edge
   secret-broker --help
   ```

4. **Promote 到 stable**
   - Web: https://snapcraft.io/tyj1987/broker/releases
   - 或 CLI: `snapcraft release secret-broker revision stable`

5. **注册 broker name** (如果还没)
   - https://snapcraft.io/register-snap
   - 名称: `secret-broker` (broker 已经被其他人注册则用 `tyj1987-broker`)

## 后续升级 (新版本 V4.x.y)

1. **broker repo**: V4.x.y release 推到 GitHub Release
2. **更新 `snap/snapcraft.yaml`**:
   - `version: '4.x.y'`
   - `source-checksum: sha256-NEW_HASH` (新 tarball)
3. **`snapcraft` + `snapcraft upload`**: 跟上面 step 2-4 一样
4. **Merge PR** `feat/snap-apt-winget-prep` 到 master

## 检查清单 (新 snap release 前)

- [ ] `snap/snapcraft.yaml`: version + source-checksum 更新
- [ ] `architectures: [build-on: amd64, arm64, armhf]` (3 平台)
- [ ] `confinement: strict` + 必要 `plugs: [network, network-bind, home]`
- [ ] `apps.secret-broker-server.daemon: simple` (server 跑 daemon)
- [ ] `license: MIT`
- [ ] `snapcraft` 跑通 (本地 3-5 min)
- [ ] `snap install secret-broker --edge` 验证 install + run OK
- [ ] `snapcraft release` 推到 stable

## 已知限制

- **首次 build 慢** (3-5 min/arch 在 LXD 内)
- **strict confinement** 需要明示 `plugs` (network / network-bind / home / removable-media)
- **核心 (kernel) snap 限制** — broker 不用 kernel feature, 没问题
- **WSL2 不支持 snap daemon** (WSL1 不支持 snap)
- **没有自动 snap revision cleanup** — 旧 revision 累积占空间 (可以用 `snapcraft release --delete-revision` 手动清)

## 参考

- https://snapcraft.io/docs
- https://snapcraft.io/docs/snap-format
- https://forum.snapcraft.io/ (community)

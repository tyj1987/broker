# winget package — 发布流程 (maintainer)

## 第一次发布 (Windows Package Manager Community Repository)

1. **建 winget-pkgs PR**
   - Fork: https://github.com/microsoft/winget-pkgs
   - Clone fork: `git clone https://github.com/tyj1987/winget-pkgs.git`
   - 创分支: `git checkout -b tyj1987-broker-4.1.1`
   - 放 manifests:
     ```
     manifests/t/tyj1987/broker/4.1.1/tyj1987.broker.installer.yaml
     manifests/t/tyj1987/broker/4.1.1/tyj1987.broker.yaml
     manifests/t/tyj1987/broker/4.1.1/tyj1987.broker.locale.en-US.yaml
     ```
   - 算 SHA256:
     ```powershell
     (Get-FileHash broker-4.1.1.zip -Algorithm SHA256).Hash.ToLower()
     ```
   - 编辑 3 个 manifest 替换 `PLACEHOLDER_SHA256_V4_1_1_ZIP` 为真实 hash
   - Commit + push:
     ```bash
     git add manifests/t/tyj1987/broker/4.1.1/
     git commit -m "New package: tyj1987.broker version 4.1.1"
     git push origin tyj1987-broker-4.1.1
     ```
   - Open PR: https://github.com/microsoft/winget-pkgs/compare/main...tyj1987:tyj1987-broker-4.1.1

2. **等 Microsoft auto-validation** (1-4 周):
   - 自动化: schema 校验 + URL 可达性 + SHA256 匹配
   - 人工 review: 包描述 / tags / 跟其他 manifest 冲突
   - PR 状态: https://github.com/microsoft/winget-pkgs/pulls?q=tyj1987

3. **合并后 user 装**:
   ```powershell
   winget install tyj1987.broker
   secret-broker --help
   ```

## 后续升级 (新版本 V4.x.y)

1. **broker repo**: V4.x.y release 推到 GitHub Release, 含 `broker-4.x.y.zip`
2. **算新 SHA256**:
   ```powershell
   (Get-FileHash broker-4.x.y.zip -Algorithm SHA256).Hash.ToLower()
   ```
3. **更新 `winget/tyj1987.broker.{installer,locale.en-US}.yaml`** 跟 broker repo:
   - 替换 `PackageVersion: 4.x.y`
   - 替换 `InstallerUrl` + `InstallerSha256`
4. **新 winget-pkgs PR** (跟上面 step 1 一样, 但 version 改 4.x.y)
5. **Merge PR** `feat/snap-apt-winget-prep` 到 master

## 检查清单 (新 winget release 前)

- [ ] `winget/tyj1987.broker.installer.yaml`: `PackageVersion` + `InstallerUrl` + `InstallerSha256` 更新
- [ ] `winget/tyj1987.broker.yaml`: `PackageVersion` 更新
- [ ] `winget/tyj1987.broker.locale.en-US.yaml`: `PackageVersion` + `ReleaseNotes` 更新
- [ ] 3 个 manifest 的 `ManifestVersion: 1.6.0` (跟 winget CLI 当前版本对齐)
- [ ] `winget validate` (本地): `winget validate --manifest winget\tyj1987.broker.installer.yaml`
- [ ] winget-pkgs PR 标题格式: `New package: tyj1987.broker version 4.x.y` 或 `Update package: tyj1987.broker to 4.x.y`

## 已知限制

- **审核周期 1-4 周** (Microsoft 人工 review)
- **Schema 严苛**: 1.6.0 schema, 任何错位字符 reject
- **必须填全 Locale en-US** (默认 locale), 不然 PR auto-fail
- **没有 sideload 长期方案** — winget-pkgs 是唯一 canonical source (临时用 manifest 旁路)

## 参考

- https://github.com/microsoft/winget-pkgs
- https://github.com/microsoft/winget-cli/blob/master/doc/manifestSchema/1.6.0/schema.json
- https://learn.microsoft.com/en-us/windows/package-manager/winget/

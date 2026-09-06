# Homebrew tap — 发布流程 (maintainer)

## 第一次发布 (tap repo 还不存在)

1. **建 GitHub repo** `tyj1987/homebrew-broker` (公开, MIT license)

   https://github.com/organizations/tyj1987/repositories/new
   - Owner: tyj1987
   - Name: homebrew-broker
   - Public
   - Initialize with MIT License
   - Don't add README / .gitignore (我们要自己加)

2. **本地 clone + 推初始结构**

   ```bash
   git clone https://github.com/tyj1987/homebrew-broker.git
   cd homebrew-broker
   mkdir Formula
   cp ../broker/deploy/homebrew/broker.rb Formula/broker.rb
   # 编辑 Formula/broker.rb,把 PLACEHOLDER_SHA256_V4_1_1_TARBALL 替换成 V4.1.1 tarball 的真实 SHA256
   # 算 SHA256: shasum -a 256 broker-4.1.1.tar.gz (macOS) 或 sha256sum (Linux)
   # tarball URL: https://github.com/tyj1987/broker/archive/refs/tags/v4.1.1.tar.gz
   # 实际 SHA256 跟 broker V4.1.1 GitHub Release 的 source tarball 一样

   cat > README.md <<'EOF'
   # tyj1987/homebrew-broker

   Homebrew tap for [Secret Broker](https://github.com/tyj1987/broker).

   ## Install

       brew tap tyj1987/broker
       brew install broker

   ## Packages

   - `broker` — Secret Broker CLI + server (Node.js based, mTLS credential proxy for AI clients)
   EOF

   git add Formula/broker.rb README.md
   git commit -m "feat: add broker formula v4.1.1"
   git push origin master
   ```

3. **跑 `brew audit` 验证 formula**

   ```bash
   brew tap tyj1987/broker
   brew install --build-from-source tyj1987/broker/broker
   brew test tyj1987/broker/broker
   brew audit --strict tyj1987/broker/broker
   ```

   期望: 三个命令都通过。

4. **(可选) 推 Homebrew/homebrew-core**

   如果想把 `broker` 推到官方 `homebrew-core` (这样用户可以 `brew install broker` 不用先 tap),需要按 Homebrew 官方流程:
   - https://github.com/Homebrew/homebrew-core/blob/HEAD/CONTRIBUTING.md
   - 准备 100+ star / 30+ fork / 75+ commit / 稳定 release 历史
   - 提 PR 到 homebrew-core
   - 当前 broker 状态: 不够,先用 private tap,等 V4.2.0 / V5.0.0 成熟再推

## 后续升级 (新版本 V4.x.y)

1. **broker repo**: V4.x.y release 推到 GitHub Release,带 source tarball (`broker-4.x.y.tar.gz`)

2. **更新 Formula/broker.rb**:

   - `url` 改到新 tag
   - `sha256` 改到新 tarball 的 sha256 (从 GitHub Release assets 拿)

3. **更新 `deploy/homebrew/broker.rb` in broker repo** (同步):

   ```bash
   cd broker
   $EDITOR deploy/homebrew/broker.rb   # 同步 url + sha256
   git add deploy/homebrew/broker.rb
   git commit -m "chore(homebrew): bump formula to v4.x.y"
   git push origin master
   ```

4. **推 tap repo**:

   ```bash
   cd homebrew-broker
   cp ../broker/deploy/homebrew/broker.rb Formula/broker.rb
   git diff Formula/broker.rb   # 确认只改 url + sha256
   git add Formula/broker.rb
   git commit -m "chore: bump broker to v4.x.y"
   git push origin master
   ```

5. **`brew audit` 验证**

   ```bash
   brew uninstall tyj1987/broker/broker
   brew install --build-from-source tyj1987/broker/broker
   brew test tyj1987/broker/broker
   ```

---

## 检查清单 (新 formula release 前)

- [ ] `url` 指向 `vX.Y.Z` tag
- [ ] `sha256` 是真实 tarball 的 hash (从 `shasum -a 256` 算)
- [ ] `desc` 一句话清晰
- [ ] `homepage` 是 GitHub repo
- [ ] `license "MIT"` (跟 broker repo 一致)
- [ ] `depends_on` 列出所有系统依赖
- [ ] `install` block 干净,无副作用
- [ ] `caveats` 解释 post-install 配置
- [ ] `test do` block 跑通 (`brew test` 0 exit)
- [ ] `brew audit --strict` 通过

---

## 常见问题

### bottle (预编译) 怎么搞?

bottle 是 Homebrew 给常用平台 (arm64_sonoma, x86_64_linux, etc.) 预编译的二进制。
第一次 formula release 不需要 bottle,用户 `brew install --build-from-source` 装。
后续如果有 maintainer 机器 (macOS + Linux x64),可以本地 build bottle 然后推 GitHub Release。

broker 因为是 Node.js app,formula 装 source + 跑 `node broker/server.js`,bottle 收益有限 (compile 时间 < 1s,瓶颈是 npm install 的 node_modules 大小)。

### 怎么加 manpage?

`cli/secret-broker.js` 现在没用 manpage。如果想加:
1. 写 `cli/secret-broker.1` (mandoc 格式)
2. Formula `install` block: `man1.install "cli/secret-broker.1"`
3. `brew audit` 检查

### formula 在哪个 branch?

Homebrew 官方 tap 习惯 `master` branch。GitHub tap (e.g. `tyj1987/homebrew-broker`) 也用 `master` (Homebrew 默认)。
如果想用 `main`,formula 里加 `head "https://github.com/tyj1987/broker.git"` 让 user 可以 `brew install --HEAD tyj1987/broker/broker` 装 main 分支。

### 怎么测试 formula 不污染自己的 brew?

```bash
# 装到独立 prefix
brew install --prefix=/tmp/test-prefix tyj1987/broker/broker
/tmp/test-prefix/bin/secret-broker --version
# 跑完删除
rm -rf /tmp/test-prefix
```

# Morphida

> *Polymorphic, anti-detection Frida — formerly "Florida (standalone)".*

**English** | [中文](#中文)

---

Automatically tracks **FRIDA** upstream releases and builds an anti-detection
version of `frida-server` for Android (arm64). Every build *morphs* its giveaway
symbols and strings, so no two server binaries share the same static fingerprint.

> The `standalone` branch was rewritten from scratch and is **no longer based on
> the original Florida patch set**. The Frida source tree is **never vendored
> here** — every build freshly clones the latest upstream release tag, applies a
> small set of patches, and randomizes giveaway strings per build.

## Download

[Latest Release](https://github.com/1013503897/Morphida/releases/latest)

Each release asset is named `frida-server-<ver>-android-arm64.gz`.

## How it works

A scheduled GitHub Actions workflow (`.github/workflows/build.yml`) runs daily
(and on demand via *workflow_dispatch*):

1. **Check** — query `frida/frida` latest release. On a cron run, skip if a
   release for that version already exists; a manual dispatch always builds.
2. **Clone** — `git clone -b <ver> https://github.com/frida/frida` (latest
   upstream release, with submodules).
3. **Patch** — apply the structural patches in `patches/`:
   - `02-payload-base-allow-exec-only.patch` — relax the `libstagefright.so`
     payload-base check to accept `PROT_EXEC`-only segments (Android 10+), fixing
     `frida -f` "Unable to pick a payload base".
4. **Source-level rename** (per-build random tokens, via `sed`): `g_set_prgname`,
   the `memfd_create` name, the `frida-agent-<arch>.so` prefix, and
   `frida_agent_main` → `main` (the dlsym entry point).
5. **Binary sanitize** — `tools/sanitize.py` runs on the agent (at embed time)
   and on the final `frida-server` (post build):
   - **Consistent, length-preserving rename** of giveaway tokens across **all
     non-executable data sections** (`.rodata`, `.data`, `.dynstr`, and the
     embedded JS bytecode's string table): `frida` / `Frida` / `FRIDA` (which
     also rewrites `frida:rpc`, `re.frida`, `frida-agent`), plus `gum-js-loop`,
     `gmain`, `gdbus`. Because the rename is consistent, internal name-based
     bindings (GType names, GDBus names, the gumjs `Frida` global, the RPC wire
     tag) stay intact while the external signature is destroyed. Executable code
     is never touched.
   - `llvm-strip --strip-all` to drop the symbol table full of `gum_`/`frida_`
     names.
   - a **strings-audit gate** that fails the build if hard signatures
     (`frida:rpc`, `gum-js-loop`) survive.
6. **Build & release** — configure for `android-arm64`, `make`, gzip the
   `frida-server`, and publish a GitHub release tagged `<ver>-r<rand>`.

Because the patches and seds are pinned to specific upstream strings/locations,
a Frida source-layout change will fail the build's `grep` guards (or the strings
audit) rather than silently produce a broken binary — that is the signal to
update them.

## Hardened launch (optional)

The randomization above defeats *static* signature and `/proc` scans. The two
cheapest *network-level* detections — the fixed `27042` port and the bare D-Bus
handshake — are best handled at launch time, with a random port behind an auth
token:

```sh
# random port + auth token + adb forward; prints the connect command
tools/run-server.sh -s <serial> -b /data/local/tmp/frida-server-<ver>
# then:
frida-ps -H 127.0.0.1:<port> --token <token>
frida    -H 127.0.0.1:<port> --token <token> -f <package>
```

Trade-off: with a custom port + token, `frida -U` no longer auto-connects — use
`-H` + `--token` as printed by the helper. Launching the server with no flags
keeps the default `27042` for `frida -U` convenience.

## Repository layout

| Path | Purpose |
| --- | --- |
| `.github/workflows/build.yml` | the daily check → clone → patch → sanitize → build → release pipeline |
| `patches/` | structural source patches applied via `git am` |
| `tools/sanitize.py` | section-scoped binary sanitizer (`patch` / `report` modes) |
| `tools/run-server.sh` | hardened-launch helper (random port + auth token) |

## References

- [https://github.com/hluwa/Patchs](https://github.com/hluwa/Patchs)
- [https://github.com/feicong/strong-frida](https://github.com/feicong/strong-frida)
- [https://github.com/qtfreet00/AntiFrida](https://github.com/qtfreet00/AntiFrida)
- [https://github.com/darvincisec/DetectFrida](https://github.com/darvincisec/DetectFrida)
- [https://github.com/b-mueller/frida-detection-demo](https://github.com/b-mueller/frida-detection-demo)

## Thanks

Originally inspired by [Ylarod/Florida](https://github.com/Ylarod/Florida) and
the wider anti-detection community:

- [@Ylarod](https://github.com/Ylarod)
- [@hluwa](https://github.com/hluwa)
- [@feicong](https://github.com/feicong)
- [@r0ysue](https://github.com/r0ysue)
- [@hellodword](https://github.com/hellodword)
- [@qtfreet00](https://github.com/qtfreet00)

---

# 中文

> *多态、反检测的 Frida —— 原 “Florida (standalone)”。*

[English](#morphida) | **中文**

---

跟随 **FRIDA** 上游正式 release，自动修补并为 Android (arm64) 构建反检测版
`frida-server`。每次构建都会 *morph*（变形）自身的特征符号与字符串，因此任意两个
server 二进制都不会有相同的静态指纹。

> `standalone` 分支已从零重写，**不再基于原 Florida 的补丁集**。仓库内**不保存
> Frida 源码** —— 每次构建实时克隆上游最新 release tag，打上一小组补丁，并对特征
> 字符串做逐次随机化。

## 下载

[最新 Release](https://github.com/1013503897/Morphida/releases/latest)

每个 release 资产命名为 `frida-server-<版本>-android-arm64.gz`。

## 工作原理

一个定时的 GitHub Actions 工作流（`.github/workflows/build.yml`）每天运行一次
（也可通过 *workflow_dispatch* 手动触发）：

1. **检查** —— 查询 `frida/frida` 的最新 release。定时触发时，若该版本已发过
   release 则跳过；手动触发则总是构建。
2. **克隆** —— `git clone -b <版本> https://github.com/frida/frida`（上游最新
   release，含子模块）。
3. **打补丁** —— 应用 `patches/` 中的结构性补丁：
   - `02-payload-base-allow-exec-only.patch` —— 放宽对 `libstagefright.so` 的
     payload-base 检查，接受仅 `PROT_EXEC` 的段（Android 10+），修复
     `frida -f` 的 “Unable to pick a payload base”。
4. **源码级改名**（逐次构建的随机 token，用 `sed`）：`g_set_prgname`、
   `memfd_create` 的名字、`frida-agent-<arch>.so` 前缀，以及
   `frida_agent_main` → `main`（dlsym 入口）。
5. **二进制清洗** —— `tools/sanitize.py` 分别作用于 agent（嵌入时）与最终的
   `frida-server`（构建后）：
   - 对特征 token 做**一致的、等长的改名**，覆盖**所有非可执行数据段**
     （`.rodata`、`.data`、`.dynstr`，以及内嵌 JS 字节码的字符串表）：
     `frida` / `Frida` / `FRIDA`（连带改写 `frida:rpc`、`re.frida`、
     `frida-agent`），外加 `gum-js-loop`、`gmain`、`gdbus`。因为改名是一致的，
     所有基于名字的内部绑定（GType 名、GDBus 名、gumjs 的 `Frida` 全局、RPC 线
     标签）都保持自洽，而对外的静态指纹被摧毁。可执行代码段绝不触碰。
   - `llvm-strip --strip-all` 去掉满是 `gum_`/`frida_` 名字的符号表。
   - 一道**字符串审计关卡**：若硬特征（`frida:rpc`、`gum-js-loop`）仍残留，
     则构建失败。
6. **构建并发布** —— 按 `android-arm64` 配置、`make`、gzip 压缩 `frida-server`，
   发布 tag 为 `<版本>-r<随机>` 的 GitHub release。

由于补丁与 sed 都绑定了上游特定的字符串/位置，一旦 Frida 源码结构变动，会让构建
中的 `grep` 守卫（或字符串审计）直接失败，而不是默默产出坏掉的二进制 —— 这正是
该更新它们的信号。

## 硬化启动（可选）

上面的随机化能破掉**静态**特征扫描和 `/proc` 扫描。而两个最廉价的**网络层**检测
—— 固定的 `27042` 端口、裸 D-Bus 握手 —— 最好在启动时处理：用随机端口 + 鉴权
token：

```sh
# 随机端口 + token + adb forward；会打印连接命令
tools/run-server.sh -s <serial> -b /data/local/tmp/frida-server-<版本>
# 然后：
frida-ps -H 127.0.0.1:<端口> --token <token>
frida    -H 127.0.0.1:<端口> --token <token> -f <包名>
```

取舍：用了自定义端口 + token 后，`frida -U` 不再自动连通 —— 改用脚本打印的
`-H` + `--token` 连接。若启动时不带任何参数，则仍是默认 `27042`，方便 `frida -U`。

## 仓库结构

| 路径 | 作用 |
| --- | --- |
| `.github/workflows/build.yml` | 每日 检查 → 克隆 → 打补丁 → 清洗 → 构建 → 发布 的流水线 |
| `patches/` | 通过 `git am` 应用的结构性源码补丁 |
| `tools/sanitize.py` | 分段作用的二进制清洗器（`patch` / `report` 两种模式） |
| `tools/run-server.sh` | 硬化启动助手（随机端口 + 鉴权 token） |

## 参考

- [https://github.com/hluwa/Patchs](https://github.com/hluwa/Patchs)
- [https://github.com/feicong/strong-frida](https://github.com/feicong/strong-frida)
- [https://github.com/qtfreet00/AntiFrida](https://github.com/qtfreet00/AntiFrida)
- [https://github.com/darvincisec/DetectFrida](https://github.com/darvincisec/DetectFrida)
- [https://github.com/b-mueller/frida-detection-demo](https://github.com/b-mueller/frida-detection-demo)

## 致谢

最初受 [Ylarod/Florida](https://github.com/Ylarod/Florida) 及更广泛的反检测社区启发：

- [@Ylarod](https://github.com/Ylarod)
- [@hluwa](https://github.com/hluwa)
- [@feicong](https://github.com/feicong)
- [@r0ysue](https://github.com/r0ysue)
- [@hellodword](https://github.com/hellodword)
- [@qtfreet00](https://github.com/qtfreet00)

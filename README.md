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
   - `01-hide-rpc-magic.patch` — replace the literal `frida:rpc` wire magic with
     a runtime triple-base64 decode, so the string never appears in the binary.
     Wire protocol is unchanged.
   - `02-payload-base-allow-exec-only.patch` — relax the `libstagefright.so`
     payload-base check to accept `PROT_EXEC`-only segments (Android 10+), fixing
     `frida -f` "Unable to pick a payload base".
4. **Randomize** — per-build random tokens rewrite giveaway strings:
   - source-level `sed`: `g_set_prgname`, `memfd_create` name,
     `frida-agent-<arch>.so` prefix, `frida_agent_main` → `main`.
   - post-build `tools/post-agent-patch.py` (LIEF): rename agent ELF symbols
     (`frida`/`FRIDA` → random 5-char prefix), reverse a few `.rodata` giveaway
     literals, and length-preserving swaps of thread names `gum-js-loop`,
     `gmain`, `gdbus`.
5. **Build & release** — configure for `android-arm64`, `make`, gzip the
   `frida-server`, and publish a GitHub release tagged `<ver>-r<rand>`.

Because the patches and seds are pinned to specific upstream strings/locations,
a Frida source-layout change will fail the build's `grep` guards rather than
silently produce a broken binary — that is the signal to update the patches.

## Repository layout

| Path | Purpose |
| --- | --- |
| `.github/workflows/build.yml` | the daily check → clone → patch → build → release pipeline |
| `patches/` | structural source patches applied via `git am` |
| `tools/post-agent-patch.py` | post-build LIEF + sed patcher for the embedded agent |

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
   - `01-hide-rpc-magic.patch` —— 把字面量 `frida:rpc` 协议魔数替换为运行时三层
     base64 解码，使该字符串不再出现在二进制中。线协议保持不变。
   - `02-payload-base-allow-exec-only.patch` —— 放宽对 `libstagefright.so` 的
     payload-base 检查，接受仅 `PROT_EXEC` 的段（Android 10+），修复
     `frida -f` 的 “Unable to pick a payload base”。
4. **随机化** —— 逐次构建的随机 token 重写特征字符串：
   - 源码级 `sed`：`g_set_prgname`、`memfd_create` 的名字、
     `frida-agent-<arch>.so` 前缀、`frida_agent_main` → `main`。
   - 构建后 `tools/post-agent-patch.py`（LIEF）：重命名 agent 的 ELF 符号
     （`frida`/`FRIDA` → 随机 5 字符前缀）、反转 `.rodata` 中若干特征字面量，
     并对线程名 `gum-js-loop`、`gmain`、`gdbus` 做等长替换。
5. **构建并发布** —— 按 `android-arm64` 配置、`make`、gzip 压缩 `frida-server`，
   发布 tag 为 `<版本>-r<随机>` 的 GitHub release。

由于补丁与 sed 都绑定了上游特定的字符串/位置，一旦 Frida 源码结构变动，会让构建
中的 `grep` 守卫直接失败，而不是默默产出坏掉的二进制 —— 这正是该更新补丁的信号。

## 仓库结构

| 路径 | 作用 |
| --- | --- |
| `.github/workflows/build.yml` | 每日 检查 → 克隆 → 打补丁 → 构建 → 发布 的流水线 |
| `patches/` | 通过 `git am` 应用的结构性源码补丁 |
| `tools/post-agent-patch.py` | 对内嵌 agent 做构建后 LIEF + sed 修补 |

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

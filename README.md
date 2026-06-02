# Morphida

> *Polymorphic, anti-detection Frida — formerly "Florida (standalone)".*

Automatically tracks **FRIDA** upstream releases and builds an anti-detection
version of `frida-server` for Android (arm64). Every build *morphs* its giveaway
symbols and strings, so no two server binaries share the same static fingerprint.

跟随 **FRIDA** 上游正式 release，自动修补并为 Android (arm64) 构建反检测版
`frida-server`。

> This `standalone` branch was rewritten from scratch and is **no longer based
> on the original Florida patch set**. The Frida source tree is **never vendored
> here** — every build freshly clones the latest upstream release tag, applies a
> small set of patches, and randomizes giveaway strings per build.
>
> 本 `standalone` 分支已从零重写，**不再基于原 Florida 的补丁集**。仓库内不保存
> Frida 源码，每次构建实时克隆上游最新 release，打补丁并对特征字符串做随机化。

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

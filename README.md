# Morphida

> Polymorphic, anti-detection **frida-server** for Android arm64.
> Tracks upstream Frida releases; every build morphs its static fingerprint.

**English** | [中文](#中文)

[![Latest Release](https://img.shields.io/github/v/release/1013503897/Morphida?label=release)](https://github.com/1013503897/Morphida/releases/latest)

---

## What it is

Morphida is a thin build pipeline around [Frida](https://frida.re): it does **not** vendor the Frida tree. Each CI run clones an upstream release tag, applies a small patch set, randomizes giveaway names/strings, strips symbols, and publishes an Android **arm64** `frida-server`.

Two builds of the same Frida version do **not** share the same static fingerprint — that is the *morph*.

This is a from-scratch `standalone` line of work (formerly Florida standalone). It is **not** the old Florida mega-patch set.

| | |
| --- | --- |
| **Target** | Android arm64 `frida-server` |
| **Branch** | `standalone` (default) |
| **Upstream** | latest Frida release tag (daily cron + manual) |
| **Assets** | `frida-server-<ver>-android-arm64.gz` |

## Features

- **Polymorphic builds** — per-build random tokens for process name, memfd name, agent SO prefix, GType/`frida` string prefix, thread names, path fingerprints, etc.
- **Binary sanitizer** (`tools/sanitize.py`) — length-preserving renames across the whole file (including C-string tables parked in `.text`) plus nested ELF string sections; DEX blobs left intact for ART.
- **Symbol strip** — NDK `llvm-strip --strip-all` drops `gum_*` / `frida_*` debug symbols.
- **CI strings gate** — build fails if hard signatures remain outside DEX (`Frida.` / `gmain` / `gdbus` / `linjector` / `frida-core` paths, …).
- **Payload-base patch** — correct protection restore when the spawn anchor is an exec-only mapping (Android 10+).
- **Ops helpers** — version-asserting connect script and hardened listen (random port + auth token).

## Download

**[Latest release](https://github.com/1013503897/Morphida/releases/latest)**

```text
frida-server-<ver>-android-arm64.gz
```

Release notes list the random tokens used for that build.  
**Client and server versions must match** (`frida --version` == device server `--version`).

## Quick start

Prefer a **non-frida filename** on device — many apps grep for `frida` in paths.

```sh
# 1) push (example deploy name)
gunzip -k frida-server-*-android-arm64.gz   # or gzip -d
adb push frida-server-*-android-arm64 /data/local/tmp/art-runtime-srv
adb shell "su -c 'chmod 755 /data/local/tmp/art-runtime-srv'"

# 2) start
adb shell "su -c 'nohup /data/local/tmp/art-runtime-srv -l 0.0.0.0:27042 \
  >/data/local/tmp/art-srv.log 2>&1 &'"

# 3) forward + use (-H; renamed binary is not the default USB frida-server)
adb forward tcp:27042 tcp:27042
frida-ps -H 127.0.0.1:27042
frida    -H 127.0.0.1:27042 -f <package> -l hook.js
```

### One-shot connect (version check + daemon + forward)

```sh
tools/frida-connect.sh -s <adb-serial>
# prints READY endpoint: frida-ps / frida -H 127.0.0.1:<port>
```

### Hardened listen (random port + token)

Defeats cheap scans for fixed `27042` / bare D-Bus handshakes:

```sh
tools/run-server.sh -s <adb-serial> -b /data/local/tmp/art-runtime-srv
# then: frida -H 127.0.0.1:<port> --token <token> ...
```

## How a build works

```text
Frida release tag
    → clone + submodules
    → git am patches/*
    → source-level sed (prgname / memfd / agent prefix)
    → compile android-arm64 (agent sanitized at embed time)
    → sanitize + strip server
    → strings audit (CI gate)
    → GitHub Release asset
```

| Path | Role |
| --- | --- |
| `.github/workflows/build.yml` | daily / dispatch / push CI |
| `patches/` | minimal source patches |
| `tools/sanitize.py` | binary morph + report gate |
| `tools/frida-connect.sh` | version assert + start + forward |
| `tools/run-server.sh` | random port + auth token |

## What it is not

Morphida hardens **static and cheap runtime fingerprints** of `frida-server`. It does **not**:

- guarantee invisibility against integrity checks (libc/libart memory vs disk, inline-hook probes);
- remove every `frida` substring — stock CLI needs `frida:rpc`, and some `frida_*` / `re.frida` name-couplings stay for correctness;
- replace app-specific detection bypass (that is still target-side work).

Prefer **spawn** (`-f`) over attach when ptrace is unstable on the device.

## References

Detection / community prior art:

- [hluwa/Patchs](https://github.com/hluwa/Patchs)
- [feicong/strong-frida](https://github.com/feicong/strong-frida)
- [qtfreet00/AntiFrida](https://github.com/qtfreet00/AntiFrida)
- [darvincisec/DetectFrida](https://github.com/darvincisec/DetectFrida)
- [b-mueller/frida-detection-demo](https://github.com/b-mueller/frida-detection-demo)

## Thanks

Inspired by [Ylarod/Florida](https://github.com/Ylarod/Florida) and the wider anti-detection community:

[@Ylarod](https://github.com/Ylarod) · [@hluwa](https://github.com/hluwa) · [@feicong](https://github.com/feicong) · [@r0ysue](https://github.com/r0ysue) · [@hellodword](https://github.com/hellodword) · [@qtfreet00](https://github.com/qtfreet00)

---

# 中文

> 面向 Android arm64 的**多态、反检测 frida-server**。
> 跟随上游 Frida 正式版；每次构建都会 morph 静态指纹。

[English](#morphida) | **中文**

[![Latest Release](https://img.shields.io/github/v/release/1013503897/Morphida?label=release)](https://github.com/1013503897/Morphida/releases/latest)

---

## 是什么

Morphida 是套在 [Frida](https://frida.re) 外的**薄构建流水线**：仓库**不 vendoring** Frida 源码。CI 每次克隆上游 release tag，打一小撮补丁，随机化特征名/字符串，strip 符号，再发布 Android **arm64** 的 `frida-server`。

同一 Frida 版本的两次构建，**静态指纹不同** —— 这就是 *morph*。

当前默认分支 `standalone` 为自维护产线（独立补丁集）。

| | |
| --- | --- |
| **产物** | Android arm64 `frida-server` |
| **分支** | `standalone`（默认） |
| **上游** | Frida 最新正式 tag（日构 cron + 手动） |
| **资产名** | `frida-server-<版本>-android-arm64.gz` |

## 特性

- **多态构建** —— 每次随机进程名、memfd 名、agent so 前缀、GType/`frida` 串前缀、线程名、路径指纹等
- **二进制清洗**（`tools/sanitize.py`）—— 整文件等长重命名（含落在 `.text` 里的 C 字符串表）+ 嵌套 ELF 字符串段；DEX 原样保留以兼容 ART
- **符号剥离** —— NDK `llvm-strip --strip-all` 去掉 `gum_*` / `frida_*` 调试符号
- **CI 字符串门禁** —— DEX 外仍残留硬特征则构建失败
- **payload-base 补丁** —— Android 10+ spawn 锚点为 exec-only 映射时的权限还原
- **运维脚本** —— 版本断言连接；随机端口 + token 硬化监听

## 下载

**[最新 Release](https://github.com/1013503897/Morphida/releases/latest)**

```text
frida-server-<版本>-android-arm64.gz
```

Release 说明里会列出本次随机 token。  
**本地 frida client 版本必须与设备上 server `--version` 严格一致。**

## 快速上手

设备上建议**不要用带 frida 的文件名**（很多 app 会扫路径）。

```sh
gunzip -k frida-server-*-android-arm64.gz
adb push frida-server-*-android-arm64 /data/local/tmp/art-runtime-srv
adb shell "su -c 'chmod 755 /data/local/tmp/art-runtime-srv'"

adb shell "su -c 'nohup /data/local/tmp/art-runtime-srv -l 0.0.0.0:27042 \
  >/data/local/tmp/art-srv.log 2>&1 &'"

adb forward tcp:27042 tcp:27042
frida-ps -H 127.0.0.1:27042
frida    -H 127.0.0.1:27042 -f <包名> -l hook.js
```

### 一键连接（版本检查 + 起 daemon + forward）

```sh
tools/frida-connect.sh -s <adb-serial>
```

### 硬化监听（随机端口 + token）

```sh
tools/run-server.sh -s <adb-serial> -b /data/local/tmp/art-runtime-srv
# frida -H 127.0.0.1:<port> --token <token> ...
```

## 构建流程（简图）

```text
Frida release tag
    → clone + submodules
    → git am patches/*
    → 源码级 sed（prgname / memfd / agent 前缀）
    → 编 android-arm64（embed 时清洗 agent）
    → sanitize + strip server
    → 字符串审计（CI 门禁）
    → GitHub Release
```

| 路径 | 作用 |
| --- | --- |
| `.github/workflows/build.yml` | 日构 / 手动 / 推送 CI |
| `patches/` | 最小源码补丁 |
| `tools/sanitize.py` | 二进制 morph + report 门禁 |
| `tools/frida-connect.sh` | 版本断言 + 启动 + forward |
| `tools/run-server.sh` | 随机端口 + auth token |

## 明确做不到的

Morphida 针对的是 `frida-server` 的**静态特征与廉价运行时指纹**，并不是：

- 对 libc/libart「内存 vs 磁盘」完整性、inline-hook 探测的隐身保证；
- 清掉二进制里每一个 `frida` 子串（官方 client 需要 `frida:rpc`，部分 `frida_*` / `re.frida` 为正确性保留）；
- 替代「按 app 拆检测点」的目标侧对抗。

设备 ptrace 不稳时，业务优先用 **spawn**（`-f`）。

## 参考

- [hluwa/Patchs](https://github.com/hluwa/Patchs)
- [feicong/strong-frida](https://github.com/feicong/strong-frida)
- [qtfreet00/AntiFrida](https://github.com/qtfreet00/AntiFrida)
- [darvincisec/DetectFrida](https://github.com/darvincisec/DetectFrida)
- [b-mueller/frida-detection-demo](https://github.com/b-mueller/frida-detection-demo)

## 致谢

受 [Ylarod/Florida](https://github.com/Ylarod/Florida) 与反检测社区启发：

[@Ylarod](https://github.com/Ylarod) · [@hluwa](https://github.com/hluwa) · [@feicong](https://github.com/feicong) · [@r0ysue](https://github.com/r0ysue) · [@hellodword](https://github.com/hellodword) · [@qtfreet00](https://github.com/qtfreet00)

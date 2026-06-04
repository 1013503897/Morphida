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

## Features

- **Polymorphic builds** — each release has unique randomized signatures
- **String sanitization** — removes `frida`, `gum-js-loop`, `gdbus` etc. from data sections
- **Symbol stripping** — `llvm-strip` removes `gum_*`/`frida_*` symbols
- **Hardened launch** — random port + auth token to bypass network detection

## Download

[Latest Release](https://github.com/1013503897/Morphida/releases/latest)

Each release asset is named `frida-server-<ver>-android-arm64.gz`.

## Usage

```sh
# Push to device
adb push frida-server-<ver>-android-arm64 /data/local/tmp/frida-server

# Start server
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"

# Use with frida
frida-ps -U
frida -U -f <package>
```

For hardened launch with random port and auth token:
```sh
tools/run-server.sh -s <serial> -b /data/local/tmp/frida-server-<ver>
```

## Repository layout

| Path | Purpose |
| --- | --- |
| `.github/workflows/build.yml` | CI/CD pipeline for automated builds |
| `patches/` | source patches for anti-detection |
| `tools/sanitize.py` | binary sanitizer for removing signatures |
| `tools/run-server.sh` | hardened launch helper (random port + auth token) |

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

## 特性

- **多态构建** —— 每个 release 都有独特的随机化签名
- **字符串清洗** —— 从数据段移除 `frida`、`gum-js-loop`、`gdbus` 等特征
- **符号剥离** —— `llvm-strip` 移除 `gum_*`/`frida_*` 符号
- **硬化启动** —— 随机端口 + 鉴权 token 绕过网络层检测

## 下载

[最新 Release](https://github.com/1013503897/Morphida/releases/latest)

每个 release 资产命名为 `frida-server-<版本>-android-arm64.gz`。

## 使用方法

```sh
# 推送到设备
adb push frida-server-<版本>-android-arm64 /data/local/tmp/frida-server

# 启动服务
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"

# 使用 frida
frida-ps -U
frida -U -f <包名>
```

如需使用随机端口和鉴权 token 的硬化启动：
```sh
tools/run-server.sh -s <serial> -b /data/local/tmp/frida-server-<版本>
```

## 仓库结构

| 路径 | 作用 |
| --- | --- |
| `.github/workflows/build.yml` | CI/CD 自动构建流水线 |
| `patches/` | 反检测源码补丁 |
| `tools/sanitize.py` | 二进制清洗器，移除特征签名 |
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

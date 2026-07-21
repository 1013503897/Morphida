#!/usr/bin/env python3
"""
Morphida binary sanitizer.

Works on any ELF — the embedded frida-agent .so (at embed time) and the final
frida-server (post build). Two modes:

  sanitize.py patch  <elf>   rename giveaway tokens + strip symbols
  sanitize.py report <elf>   count residual signatures (CI gate)

Giveaway tokens are replaced by build-random values of the **same length**:

  * High-value plain tokens (`Frida`/`FRIDA`, thread names, `frida-core`/
    `frida-helper` path fingerprints, `linjector`, …) are rewritten
    **whole-file** with an identifier-boundary check — NDK builds park many of
    these C-string tables inside `.text`, so a `.rodata`-only pass misses them.
  * Free-form lowercase `frida` uses a safer regex and is limited to
    string-bearing sections of the outer ELF **and nested ELF blobs** (embedded
    agent), so we do not spray a 5-byte pattern across raw code.
  * Embedded DEX blobs are restored byte-for-byte (ART checksum + `re/frida`
    class paths). Stock-client wire tag `frida:rpc` and `frida_*` / `frida-agent`
    name-couplings are intentionally preserved.
  * `$STRIP --strip-all` drops gum_/frida_ debug symbols afterwards.

All randomness comes from the caller via env vars (workflow-generated tokens).
"""
from __future__ import annotations

import os
import re
import struct
import subprocess
import sys

SHT_NOBITS = 8
ELF_MAGIC = b"\x7fELF"

# scanned in `report` mode (informational + gate)
SIG_TOKENS = [
    "frida",
    "Frida",
    "FRIDA",
    "frida:rpc",
    "re.frida",
    "frida-agent",
    "frida-core",
    "frida-helper",
    "frida-server",
    "projects/frida",
    "gum-js-loop",
    "gmain",
    "gdbus",
    "linjector",
    "LIBFRIDA",
    "pool-frida",
    "gum_",
]

# MUST be 0 after a patch; a survivor fails the build.
# Intentionally NOT gated: frida:rpc (stock client wire tag), re.frida / frida_*
# / frida-agent (name-couplings preserved for runtime correctness).
HARD_ZERO = [
    "gum-js-loop",
    "gmain",
    "gdbus",
    "linjector",
    "LIBFRIDA",
    "pool-frida",
    "frida-core",
    "frida-helper",
    "frida-server",
    "projects/frida",
    "Frida",   # GType / JS names must become SYMBOL.capitalize()
    "FRIDA",
]


def _lief():
    try:
        import lief
        return lief
    except ImportError:
        sys.exit("[sanitize] lief is required: pip install lief")


def _need(name, length):
    v = os.environ.get(name)
    if not v or len(v) != length:
        sys.exit(f"[sanitize] env {name} must be a {length}-char value (got {v!r})")
    return v


DEX_MAGIC = b"dex\n"


def _dex_ranges(path):
    """(start, size) of embedded DEX blobs, left byte-for-byte intact.

    A DEX has a sorted string-id table plus Adler-32 + SHA-1 over its body, so
    renaming anything inside it makes ART reject the whole DEX (and
    find_class("re/frida/HelperBackend") returns null).
    """
    with open(path, "rb") as f:
        data = f.read()
    ranges, i = [], data.find(DEX_MAGIC)
    while i != -1:
        ver = data[i + 4 : i + 8]
        if ver[:3].isdigit() and ver[3:4] == b"\x00" and i + 0x24 <= len(data):
            size = int.from_bytes(data[i + 0x20 : i + 0x24], "little")
            if 0x70 <= size <= len(data) - i:
                ranges.append((i, size))
                i = data.find(DEX_MAGIC, i + size)
                continue
        i = data.find(DEX_MAGIC, i + 1)
    return ranges


# lowercase "frida", EXCEPT when it is part of a token whose runtime value must
# stay byte-identical because it is matched by string against something we do
# not rename in lockstep:
#   * "frida" followed by "-"/"_"  -> identifier/path tokens (frida_agent_main,
#     frida_zymbiote_*, /frida-zymbiote-, frida-android-helper, ...)
#   * "frida:" (i.e. "frida:rpc")  -> agent<->client RPC wire tag for stock CLI
#   * "re/frida" / "re.frida"      -> helper DEX class path + filesystem
# Free-form "frida" and "Frida"/"FRIDA" GType/JS names still rename.
# Explicit plain replacements below also cover frida-core / frida-helper / etc.
_FRIDA_RE = re.compile(rb"(?<!re/)(?<!re\.)frida(?![-_:])")


def _is_string_section(name: str) -> bool:
    return (
        name == ".dynstr"
        or name == ".strtab"
        or name.startswith(".rodata")
    )


def _elf_image_size(data: bytes, base: int) -> int | None:
    """Return the on-disk size of an ELF image at data[base:], or None if bogus."""
    if base + 64 > len(data) or data[base : base + 4] != ELF_MAGIC:
        return None
    ei_class = data[base + 4]  # 1=32, 2=64
    ei_data = data[base + 5]   # 1=LE, 2=BE
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None
    endian = "<" if ei_data == 1 else ">"
    try:
        if ei_class == 1:
            # e_shoff@32, e_shentsize@46, e_shnum@48
            e_shoff, e_shentsize, e_shnum = struct.unpack_from(
                endian + "IHH", data, base + 32
            )
        else:
            # e_shoff@40, e_shentsize@58, e_shnum@60
            e_shoff = struct.unpack_from(endian + "Q", data, base + 40)[0]
            e_shentsize, e_shnum = struct.unpack_from(
                endian + "HH", data, base + 58
            )
    except struct.error:
        return None
    if e_shnum == 0 or e_shentsize < 40 or e_shoff == 0:
        # fall back: use program headers max file end
        return _elf_ph_size(data, base, ei_class, endian)
    end = e_shoff + e_shentsize * e_shnum
    # also cover section payloads
    sh_off_field = 16 if ei_class == 1 else 24
    sh_size_field = 20 if ei_class == 1 else 32
    sh_fmt = endian + ("I" if ei_class == 1 else "Q")
    for i in range(min(e_shnum, 512)):
        sh = base + e_shoff + i * e_shentsize
        if sh + e_shentsize > len(data):
            return None
        try:
            sh_offset = struct.unpack_from(sh_fmt, data, sh + sh_off_field)[0]
            sh_size = struct.unpack_from(sh_fmt, data, sh + sh_size_field)[0]
        except struct.error:
            return None
        if sh_size and sh_offset:
            end = max(end, sh_offset + sh_size)
    if end <= 0 or base + end > len(data):
        return _elf_ph_size(data, base, ei_class, endian)
    # sanity: nested agent is typically 5–40 MB, reject absurd sizes
    if end < 0x1000 or end > 80 * 1024 * 1024:
        return None
    return int(end)


def _elf_ph_size(data: bytes, base: int, ei_class: int, endian: str) -> int | None:
    try:
        if ei_class == 1:
            e_phoff, e_phentsize, e_phnum = struct.unpack_from(
                endian + "IHH", data, base + 28
            )
            p_off_field, p_filesz_field, fmt = 4, 16, endian + "I"
        else:
            e_phoff = struct.unpack_from(endian + "Q", data, base + 32)[0]
            e_phentsize, e_phnum = struct.unpack_from(
                endian + "HH", data, base + 54
            )
            p_off_field, p_filesz_field, fmt = 8, 32, endian + "Q"
    except struct.error:
        return None
    if e_phnum == 0 or e_phentsize == 0:
        return None
    end = 0
    for i in range(min(e_phnum, 256)):
        ph = base + e_phoff + i * e_phentsize
        if ph + e_phentsize > len(data):
            return None
        try:
            p_offset = struct.unpack_from(fmt, data, ph + p_off_field)[0]
            p_filesz = struct.unpack_from(fmt, data, ph + p_filesz_field)[0]
        except struct.error:
            return None
        if p_filesz:
            end = max(end, p_offset + p_filesz)
    if end < 0x1000 or base + end > len(data):
        return None
    return int(end)


def _nested_elf_bases(path: str) -> list[tuple[int, int]]:
    """(offset, size) of nested ELF images inside path (excluding the outer ELF at 0)."""
    with open(path, "rb") as f:
        data = f.read()
    found: list[tuple[int, int]] = []
    i = data.find(ELF_MAGIC, 1)
    while i != -1:
        size = _elf_image_size(data, i)
        if size:
            found.append((i, size))
            i = data.find(ELF_MAGIC, i + size)
        else:
            i = data.find(ELF_MAGIC, i + 1)
    return found


def _string_ranges(path: str) -> list[tuple[str, int, int]]:
    """Absolute file ranges of string-bearing sections for outer + nested ELFs."""
    lief = _lief()
    binary = lief.parse(path)
    if binary is None:
        sys.exit(f"[sanitize] cannot parse ELF: {path}")

    ranges: list[tuple[str, int, int]] = []

    def collect(elf, label_prefix: str, base: int = 0):
        for s in elf.sections:
            try:
                name, off, size, stype = (
                    s.name,
                    int(s.offset),
                    int(s.size),
                    int(s.type),
                )
            except Exception:
                continue
            if size == 0 or off == 0 or stype == SHT_NOBITS:
                continue
            if _is_string_section(name):
                ranges.append((f"{label_prefix}{name}", base + off, size))

    collect(binary, "")

    # Nested ELFs (embedded agent, helpers): parse slice via temp is heavy;
    # instead re-parse from file offset using lief on a memory view written once.
    nested = _nested_elf_bases(path)
    if nested:
        import tempfile

        with open(path, "rb") as f:
            blob = f.read()
        for idx, (off, size) in enumerate(nested):
            chunk = blob[off : off + size]
            nested_elf = None
            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".so") as tmp:
                    tmp.write(chunk)
                    tmp_path = tmp.name
                nested_elf = lief.parse(tmp_path)
            except Exception as exc:
                print(f"[sanitize] warn: nested ELF @{off:#x}: {exc}")
            finally:
                if tmp_path:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
            if nested_elf is None:
                continue
            collect(nested_elf, f"nested{idx}:", base=off)

    return ranges


def _replacements():
    sym = _need("SYMBOL", 5)
    frida_repl = sym.encode()
    # length-preserving, longest first. pool-frida = "pool-" + 5-char SYMBOL.
    plain = [
        (b"gum-js-loop", _need("GUM_JS_LOOP", 11).encode()),
        (b"frida-server", frida_repl + b"-server"),
        (b"frida-helper", frida_repl + b"-helper"),
        (b"frida-core", frida_repl + b"-core"),
        (b"frida-gum", frida_repl + b"-gum"),
        (b"projects/frida", b"projects/" + frida_repl),
        (b"pool-frida", b"pool-" + frida_repl),
        (b"linjector", _need("LINJECTOR", 9).encode()),
        (b"LIBFRIDA", _need("LIBFRIDA", 8).encode()),
        (b"Frida", sym.capitalize().encode()),
        (b"FRIDA", sym.upper().encode()),
        (b"gmain", _need("GMAIN", 5).encode()),
        (b"gdbus", _need("GDBUS", 5).encode()),
    ]
    for old, new in plain:
        if len(old) != len(new):
            sys.exit(f"[sanitize] non length-preserving token: {old!r} -> {new!r}")
    return frida_repl, plain


def _bounded_replace(buf: bytearray, old: bytes, new: bytes) -> int:
    """Length-preserving replace; skip matches mid-identifier (alnum before).

    Applied to the whole file (incl. .text string tables that Android/NDK
    sometimes merges into executable segments). 5–11 byte ASCII tokens are
    astronomically unlikely to collide with real opcodes at an identifier
    boundary; we still refuse mid-token hits like ``xFrida``.
    """
    if len(old) != len(new):
        raise ValueError("length drift")
    n = 0
    i = 0
    alnum = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    while True:
        j = buf.find(old, i)
        if j < 0:
            break
        prev = buf[j - 1] if j > 0 else 0
        if prev in alnum:
            i = j + 1
            continue
        buf[j : j + len(old)] = new
        n += 1
        i = j + len(new)
    return n


def patch(path):
    frida_repl, plain = _replacements()
    dex = _dex_ranges(path)
    ranges = _string_ranges(path)

    with open(path, "rb") as f:
        original = f.read()
    buf = bytearray(original)
    counts: dict[bytes, int] = {}

    # 1) High-value tokens: whole-file (covers .text C-string tables).
    for old, repl in plain:
        c = _bounded_replace(buf, old, repl)
        if c:
            counts[old] = counts.get(old, 0) + c

    # 2) Free-form lowercase "frida": only string-bearing sections of outer +
    #    nested ELFs (too short to spray across raw .text safely).
    for name, off, size in ranges:
        chunk = bytes(buf[off : off + size])
        new, c = _FRIDA_RE.subn(frida_repl, chunk)
        if c:
            counts[b"frida"] = counts.get(b"frida", 0) + c
            if len(new) != size:
                sys.exit("[sanitize] length drift in string section")
            buf[off : off + size] = new

    # 3) Never touch embedded DEX (ART checksum + sorted string ids).
    for ds, dl in dex:
        buf[ds : ds + dl] = original[ds : ds + dl]

    if len(buf) != len(original):
        sys.exit("[sanitize] file size changed — aborting")

    with open(path, "wb") as f:
        f.write(buf)

    print(
        f"[sanitize] string sections for bare-frida: {len(ranges)}; "
        f"whole-file plain tokens applied"
    )
    if dex:
        print(
            "[sanitize] preserved DEX blob(s): "
            + ", ".join(f"{o:#x}+{s:#x}" for o, s in dex)
        )
    nested = _nested_elf_bases(path)
    if nested:
        print(
            "[sanitize] nested ELF(s): "
            + ", ".join(f"{o:#x}+{s:#x}" for o, s in nested)
        )
    for tok in (
        b"frida",
        b"Frida",
        b"FRIDA",
        b"gum-js-loop",
        b"gmain",
        b"gdbus",
        b"frida-core",
        b"frida-helper",
        b"frida-server",
        b"projects/frida",
        b"linjector",
        b"LIBFRIDA",
        b"pool-frida",
    ):
        if counts.get(tok):
            print(f"[sanitize] renamed {tok.decode():<14} x{counts[tok]}")
    _strip(path)
    _verify(path)


def _strip(path):
    strip_bin = os.environ.get("STRIP")
    if not strip_bin:
        print("[sanitize] STRIP unset — skipping symbol strip")
        return
    print(f"[sanitize] {strip_bin} --strip-all {path}")
    subprocess.run([strip_bin, "--strip-all", path], check=True)


def _verify(path):
    binary = _lief().parse(path)
    if binary is None or not list(binary.sections):
        sys.exit("[sanitize] post-patch ELF failed to re-parse")
    print("[sanitize] post-patch ELF re-parse OK")


def _mask_dex(data: bytes, path: str) -> bytes:
    """Zero out embedded DEX ranges so report counts only sanitizable bytes."""
    if not _dex_ranges(path):
        return data
    buf = bytearray(data)
    for ds, dl in _dex_ranges(path):
        buf[ds : ds + dl] = b"\x00" * dl
    return bytes(buf)


def report(path):
    with open(path, "rb") as f:
        data = f.read()
    # Gate on non-DEX content only — DEX keeps re/frida + helper path couplings.
    scan = _mask_dex(data, path)
    dex = _dex_ranges(path)
    print(f"[report] {os.path.basename(path)} ({len(data)} bytes)")
    if dex:
        print(
            "[report] excluding DEX blob(s) from gate: "
            + ", ".join(f"{o:#x}+{s:#x}" for o, s in dex)
        )
    failed = []
    for tok in SIG_TOKENS:
        c_all = data.count(tok.encode())
        c = scan.count(tok.encode())
        flag = ""
        if tok in HARD_ZERO and c:
            flag = "  <-- MUST be 0 (outside DEX)"
            failed.append(tok)
        elif tok in HARD_ZERO and c_all and not c:
            flag = "  (DEX-only; OK)"
        print(f"  {tok:<16} {c_all}{flag}")
    bare = len(_FRIDA_RE.findall(scan))
    print(
        f"  {'bare-frida(re)':<16} {bare}  "
        f"(free-form lowercase outside DEX; informational)"
    )
    if failed:
        sys.exit(f"[report] FAIL: signature(s) survived: {', '.join(failed)}")
    print("[report] OK — no hard signatures survived outside DEX")


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("patch", "report"):
        print("usage: sanitize.py patch|report <elf>", file=sys.stderr)
        return 2
    mode, target = sys.argv[1], sys.argv[2]
    if not os.path.exists(target):
        print(f"[sanitize] target missing: {target}", file=sys.stderr)
        return 1
    (patch if mode == "patch" else report)(target)
    return 0


if __name__ == "__main__":
    sys.exit(main())

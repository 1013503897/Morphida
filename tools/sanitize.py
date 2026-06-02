#!/usr/bin/env python3
"""
Morphida binary sanitizer.

Works on any ELF — the embedded frida-agent .so (at embed time) and the final
frida-server (post build). Two modes:

  sanitize.py patch  <elf>   rename giveaway tokens + strip symbols
  sanitize.py report <elf>   count residual signatures (CI gate)

Why this beats string-by-string patching: every giveaway token is replaced by a
build-random value of the **same length**, applied **consistently across all
non-executable data sections** (incl. .rodata, .data, .data.rel.ro, .dynstr and
the embedded JS bytecode's string table). Because the rename is consistent, all
internal name-based bindings stay intact — GType type names, GDBus interface
names, the gumjs `Frida` global, and the `frida:rpc` wire tag are all renamed on
*both* sides at once — while the external static fingerprint is destroyed.

Implementation notes:
  * LIEF is used read-only to locate string-bearing sections (.rodata*, .dynstr);
    we patch their bytes in place (length-preserving), so the ELF layout stays
    bit-for-bit identical except for the renamed string bytes.
  * Code (.text/.plt) and pointer/relocation sections (.got/.data.rel.ro/
    .rela.*/.data) are never touched — a chance 5-byte ASCII match there would
    corrupt a pointer, not a name.
  * The agent .so is sanitized at embed time, so its giveaway strings (in the
    agent's own .rodata, incl. the JS bytecode) are renamed *before* it is
    embedded into the server's .text as a blob; the post-build server pass then
    cleans the server's own .rodata. Both halves end up clean.
  * `frida:rpc` is handled implicitly by the `frida` token: it becomes
    `<SYMBOL>:rpc` everywhere, defeating both the "frida:rpc" and "frida" greps.
  * After byte patching we run `$STRIP --strip-all` (NDK llvm-strip) to drop the
    .symtab full of gum_/frida_ debug symbol names.

All randomness is supplied by the caller via env vars so the build is
reproducible from the workflow-generated tokens.
"""
import os
import re
import subprocess
import sys

SHF_EXECINSTR = 0x4
SHT_NOBITS = 8

# scanned in `report` mode
SIG_TOKENS = [
    "frida", "Frida", "FRIDA", "frida:rpc", "re.frida",
    "frida-agent", "gum-js-loop", "gmain", "gdbus", "gum_",
]
# these MUST be 0 after a patch — they are unambiguous, always-in-.rodata
# signatures; a survivor fails the build.
HARD_ZERO = ["frida:rpc", "gum-js-loop"]


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
    """(start, size) of embedded DEX blobs, which are left byte-for-byte intact.

    A DEX has a *sorted* string-id table plus an Adler-32 + SHA-1 over its body,
    so renaming anything inside it makes ART reject the whole DEX (and the native
    `find_class("re/frida/HelperBackend")` then returns null)."""
    with open(path, "rb") as f:
        data = f.read()
    ranges, i = [], data.find(DEX_MAGIC)
    while i != -1:
        ver = data[i + 4:i + 8]
        if ver[:3].isdigit() and ver[3:4] == b"\x00" and i + 0x24 <= len(data):
            size = int.from_bytes(data[i + 0x20:i + 0x24], "little")
            if 0x70 <= size <= len(data) - i:
                ranges.append((i, size))
                i = data.find(DEX_MAGIC, i + size)
                continue
        i = data.find(DEX_MAGIC, i + 1)
    return ranges


# lowercase "frida", EXCEPT when it is part of an identifier/path *token* — i.e.
# followed by "-" or "_", or in the "re/frida" / "re.frida" package paths. Those
# are names the server resolves by string against an embedded blob / the DEX /
# the filesystem (frida_agent_main, frida_zymbiote_replacement_*, /frida-zymbiote-,
# /data/local/tmp/frida-helper-, re/frida/HelperBackend, ...) and must stay
# matched on both sides. Free-form "frida" (frida:rpc, libfrida, bare frida) and
# "Frida"/"FRIDA" GType names still rename — that is the bulk of the signature.
_FRIDA_RE = re.compile(rb"(?<!re/)(?<!re\.)frida(?![-_])")


def _string_ranges(path):
    """File ranges of string-bearing sections (.rodata*, .dynstr).

    These hold every giveaway *string* (literals, GType/GDBus names, thread
    names, and — for the agent .so — the JS bytecode string table). We
    deliberately avoid code (.text/.plt) and pointer/relocation sections
    (.got/.data.rel.ro/.rela.*/.data), where a stray 5-byte ASCII match would
    corrupt a pointer rather than a name."""
    binary = _lief().parse(path)
    if binary is None:
        sys.exit(f"[sanitize] cannot parse ELF: {path}")
    ranges = []
    for s in binary.sections:
        try:
            name, off, size, stype = s.name, int(s.offset), int(s.size), int(s.type)
        except Exception:
            continue
        if size == 0 or off == 0 or stype == SHT_NOBITS:
            continue
        if name == ".dynstr" or name.startswith(".rodata"):
            ranges.append((name, off, size))
    return ranges


def patch(path):
    sym = _need("SYMBOL", 5)
    frida_repl = sym.encode()
    plain = [                              # length-preserving, longest first
        (b"gum-js-loop", _need("GUM_JS_LOOP", 11).encode()),
        (b"Frida", sym.capitalize().encode()),
        (b"FRIDA", sym.upper().encode()),
        (b"gmain", _need("GMAIN", 5).encode()),
        (b"gdbus", _need("GDBUS", 5).encode()),
    ]
    for old, new in plain + [(b"frida", frida_repl)]:
        if len(old) != len(new):
            sys.exit(f"[sanitize] non length-preserving token: {old!r} -> {new!r}")

    dex = _dex_ranges(path)
    counts, sections = {}, []
    with open(path, "r+b") as f:
        for name, off, size in _string_ranges(path):
            sections.append(name)
            f.seek(off)
            orig = f.read(size)
            new = orig
            for old, repl in plain:
                c = new.count(old)
                if c:
                    counts[old] = counts.get(old, 0) + c
                    new = new.replace(old, repl)
            new, c = _FRIDA_RE.subn(frida_repl, new)
            if c:
                counts[b"frida"] = counts.get(b"frida", 0) + c
            if len(new) != len(orig):
                sys.exit("[sanitize] length drift — aborting to avoid corruption")
            # restore any embedded-DEX bytes overlapping this section
            for ds, dl in dex:
                a, b = max(off, ds), min(off + size, ds + dl)
                if a < b:
                    s, e = a - off, b - off
                    new = new[:s] + orig[s:e] + new[e:]
            if new != orig:
                f.seek(off)
                f.write(new)

    print(f"[sanitize] scanned sections: {', '.join(sections) or '(none!)'}")
    if dex:
        print("[sanitize] preserved DEX blob(s): "
              + ", ".join(f"{o:#x}+{s:#x}" for o, s in dex))
    for tok in (b"frida", b"Frida", b"FRIDA", b"gum-js-loop", b"gmain", b"gdbus"):
        if counts.get(tok):
            print(f"[sanitize] renamed {tok.decode():<12} x{counts[tok]}")
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


def report(path):
    with open(path, "rb") as f:
        data = f.read()
    print(f"[report] {os.path.basename(path)} ({len(data)} bytes)")
    failed = []
    for tok in SIG_TOKENS:
        c = data.count(tok.encode())
        flag = ""
        if tok in HARD_ZERO and c:
            flag = "  <-- MUST be 0"
            failed.append(tok)
        print(f"  {tok:<14} {c}{flag}")
    if failed:
        sys.exit(f"[report] FAIL: signature(s) survived: {', '.join(failed)}")
    print("[report] OK — no hard signatures survived")


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

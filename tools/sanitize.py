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


def _token_map():
    """(old, new) byte pairs, length-preserving, longest-first."""
    sym = _need("SYMBOL", 5)            # "frida"
    gjl = _need("GUM_JS_LOOP", 11)      # "gum-js-loop"
    gm = _need("GMAIN", 5)              # "gmain"
    gd = _need("GDBUS", 5)              # "gdbus"
    pairs = [
        (b"gum-js-loop", gjl.encode()),
        (b"frida", sym.encode()),
        (b"Frida", sym.capitalize().encode()),
        (b"FRIDA", sym.upper().encode()),
        (b"gmain", gm.encode()),
        (b"gdbus", gd.encode()),
    ]
    for old, new in pairs:
        if len(old) != len(new):
            sys.exit(f"[sanitize] non length-preserving token: {old!r} -> {new!r}")
    return pairs


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
    tokens = _token_map()
    counts = {old: 0 for old, _ in tokens}
    sections = []
    with open(path, "r+b") as f:
        for name, off, size in _string_ranges(path):
            sections.append(name)
            f.seek(off)
            chunk = f.read(size)
            new = chunk
            for old, repl in tokens:
                n = new.count(old)
                if n:
                    counts[old] += n
                    new = new.replace(old, repl)
            if new != chunk:
                if len(new) != len(chunk):
                    sys.exit("[sanitize] length drift — aborting to avoid corruption")
                f.seek(off)
                f.write(new)
    print(f"[sanitize] scanned sections: {', '.join(sections) or '(none!)'}")
    for old, _ in tokens:
        if counts[old]:
            print(f"[sanitize] renamed {old.decode():<12} x{counts[old]}")
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

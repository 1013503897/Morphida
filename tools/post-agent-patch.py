#!/usr/bin/env python3
"""
Post-build agent .so patcher.

Run after `make` produces a frida-agent .so but before it is embedded into
frida-server. Two passes:

  1. LIEF: rename ELF symbols. "frida_agent_main" -> "main"; any "frida"/
     "FRIDA" substring -> the value of $SYMBOL / $SYMBOL.upper(). Also reverse
     a fixed set of giveaway literals in .rodata in place.

  2. Length-preserving sed on the on-disk binary: replace thread-name string
     constants ("gum-js-loop", "gmain", "gdbus") with $GUM_JS_LOOP / $GMAIN /
     $GDBUS values supplied via env. Lengths must match the originals.

All randomness is provided by the caller via environment variables so that the
build is reproducible from the workflow-generated tokens.
"""
import os
import subprocess
import sys

try:
    import lief
except ImportError:
    print("[post-agent-patch] lief is required: pip install lief", file=sys.stderr)
    sys.exit(2)

REVERSE_LITERALS = ["FridaScriptEngine", "GLib-GIO", "GDBusProxy", "GumScript"]


def _need(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"[post-agent-patch] missing env {name}", file=sys.stderr)
        sys.exit(2)
    return value


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: post-agent-patch.py <agent.so>", file=sys.stderr)
        return 2

    target = sys.argv[1]
    if not os.path.exists(target):
        print(f"[post-agent-patch] target missing: {target}", file=sys.stderr)
        return 1

    symbol_prefix = _need("SYMBOL")
    if len(symbol_prefix) != 5:
        print("[post-agent-patch] SYMBOL must be length 5 (matches 'frida')", file=sys.stderr)
        return 2

    print(f"[post-agent-patch] patching {target}")
    print(f"[post-agent-patch] symbol prefix: frida->{symbol_prefix}")

    binary = lief.parse(target)
    if binary is None:
        print("[post-agent-patch] lief could not parse, skipping LIEF stage")
    else:
        for sym in binary.symbols:
            if sym.name == "frida_agent_main":
                sym.name = "main"
            elif "frida" in sym.name:
                sym.name = sym.name.replace("frida", symbol_prefix)
            elif "FRIDA" in sym.name:
                sym.name = sym.name.replace("FRIDA", symbol_prefix.upper())

        for section in binary.sections:
            if section.name != ".rodata":
                continue
            for literal in REVERSE_LITERALS:
                for offset in section.search_all(literal):
                    reversed_bytes = [ord(c) for c in literal[::-1]]
                    binary.patch_address(section.file_offset + offset, reversed_bytes)
                    print(f"[post-agent-patch] reverse {literal} @ rodata+{hex(offset)}")

        binary.write(target)

    # Length-preserving thread-name swaps. Each replacement must be exactly the
    # same length as the original; the workflow generates them with that
    # constraint.
    for orig, env_name in [
        ("gum-js-loop", "GUM_JS_LOOP"),
        ("gmain",       "GMAIN"),
        ("gdbus",       "GDBUS"),
    ]:
        replacement = _need(env_name)
        if len(replacement) != len(orig):
            print(f"[post-agent-patch] {env_name} must be {len(orig)} bytes (got {len(replacement)})", file=sys.stderr)
            return 2
        print(f"[post-agent-patch] sed {orig} -> {replacement}")
        subprocess.run(["sed", "-b", "-i", f"s/{orig}/{replacement}/g", target], check=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env bash
# Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Generate deterministic seed corpora for the lxp fuzz harnesses. Committed seeds
# are kept small (fast, deterministic CI replay); pass --enrich to additionally
# copy the large committed cpio rootfs images in for a heavier local run.
#
# Usage:  fuzz/tools/gen_seeds.sh [--enrich]
set -euo pipefail

fuzz_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$fuzz_dir/.." && pwd)"
corpus="$fuzz_dir/corpus"
enrich=0
[ "${1:-}" = "--enrich" ] && enrich=1

mkdir -p "$corpus"/{fdpic,etrel,cpio,path,9p,syscall}

python3 - "$corpus" <<'PY'
import os, struct, sys
corpus = sys.argv[1]

def w(sub, name, b):
    with open(os.path.join(corpus, sub, name), "wb") as f:
        f.write(b)

# ---- minimal well-formed static FDPIC ELF (mirrors tests/.../build_fdpic) -----
def build_fdpic():
    b = bytearray(128)
    b[0:4] = b"\x7fELF"
    b[4] = 1             # ELFCLASS32
    b[7] = 65            # ELFOSABI_ARM_FDPIC
    struct.pack_into("<H", b, 16, 3)     # e_type   = ET_DYN
    struct.pack_into("<H", b, 18, 40)    # e_machine = EM_ARM
    struct.pack_into("<I", b, 24, 0)     # e_entry
    struct.pack_into("<I", b, 28, 52)    # e_phoff  (phdrs after the 52-byte Ehdr)
    struct.pack_into("<H", b, 42, 32)    # e_phentsize
    struct.pack_into("<H", b, 44, 2)     # e_phnum
    # text phdr @52 : PT_LOAD, PF_X, 16 bytes in place
    struct.pack_into("<I", b, 52 + 0, 1)
    struct.pack_into("<I", b, 52 + 16, 16)
    struct.pack_into("<I", b, 52 + 20, 16)
    struct.pack_into("<I", b, 52 + 24, 1)
    # data phdr @84 : PT_LOAD, PF_R|PF_W, 8 bytes of data at offset 116
    struct.pack_into("<I", b, 84 + 0, 1)
    struct.pack_into("<I", b, 84 + 4, 116)
    struct.pack_into("<I", b, 84 + 8, 0x1000)
    struct.pack_into("<I", b, 84 + 16, 8)
    struct.pack_into("<I", b, 84 + 20, 16)
    struct.pack_into("<I", b, 84 + 24, 6)
    return bytes(b)

elf = build_fdpic()
w("fdpic", "minimal.elf", elf)
w("etrel", "minimal_elf.bin", elf)  # rejected as non-ET_REL, but walks the Ehdr path

# ---- minimal x86-64 ET_REL object (one SHF_ALLOC .text + global "foo") --------
def build_etrel():
    IMG = 512
    b = bytearray(IMG)
    def p(off, val, n):
        for i in range(n):
            b[off + i] = (val >> (8 * i)) & 0xff
    a8 = lambda n: (n + 7) & ~7
    text_off = 64                 # sizeof(Elf64_Ehdr)
    b[text_off] = 0xc3            # ret
    str_off = a8(text_off + 1)
    strtab = b"\x00foo\x00"
    b[str_off:str_off + len(strtab)] = strtab
    sym_off = a8(str_off + len(strtab))
    # Elf64_Sym[2]; entry 1 = {st_name=1, info=(GLOBAL<<4)|FUNC, shndx=1, value=0}, 24B each
    p(sym_off + 24 + 0, 1, 4)                 # st_name
    b[sym_off + 24 + 4] = (1 << 4) | 2        # st_info: STB_GLOBAL, STT_FUNC
    p(sym_off + 24 + 6, 1, 2)                 # st_shndx = .text
    sh_off = a8(sym_off + 48)
    SH = 64                                   # sizeof(Elf64_Shdr)
    # sh[1] .text PROGBITS ALLOC
    p(sh_off + 1 * SH + 4, 1, 4)              # sh_type=PROGBITS
    p(sh_off + 1 * SH + 8, 2, 8)              # sh_flags=ALLOC
    p(sh_off + 1 * SH + 24, text_off, 8)      # sh_offset
    p(sh_off + 1 * SH + 32, 1, 8)             # sh_size
    p(sh_off + 1 * SH + 48, 1, 8)             # sh_addralign
    # sh[2] .symtab
    p(sh_off + 2 * SH + 4, 2, 4)              # SHT_SYMTAB
    p(sh_off + 2 * SH + 24, sym_off, 8)
    p(sh_off + 2 * SH + 32, 48, 8)            # size = 2 syms
    p(sh_off + 2 * SH + 40, 3, 4)             # sh_link -> .strtab
    p(sh_off + 2 * SH + 56, 24, 8)            # sh_entsize
    # sh[3] .strtab
    p(sh_off + 3 * SH + 4, 3, 4)              # SHT_STRTAB
    p(sh_off + 3 * SH + 24, str_off, 8)
    p(sh_off + 3 * SH + 32, len(strtab), 8)
    # Ehdr
    b[0:4] = b"\x7fELF"
    b[4] = 2                                  # ELFCLASS64
    b[5] = 1                                  # ELFDATA2LSB
    b[6] = 1                                  # EV_CURRENT
    p(16, 1, 2)                               # e_type = ET_REL
    p(18, 62, 2)                              # e_machine = EM_X86_64
    p(20, 1, 4)                               # e_version
    p(40, sh_off, 8)                          # e_shoff
    p(58, SH, 2)                              # e_shentsize
    p(60, 4, 2)                               # e_shnum
    return bytes(b[:sh_off + 4 * SH])

w("etrel", "minimal_obj.o", build_etrel())

# ---- minimal newc cpio: one file "a" -> "x", then TRAILER!!! -------------------
def newc(name, data, ino=1, mode=0o100644):
    name_b = name.encode() + b"\x00"
    hdr = b"070701"
    for v in (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name_b), 0):
        hdr += b"%08X" % (v & 0xffffffff)
    out = bytearray(hdr + name_b)
    while len(out) % 4:
        out += b"\x00"
    out += data
    while len(out) % 4:
        out += b"\x00"
    return bytes(out)

cpio = newc("a", b"x") + newc("TRAILER!!!", b"", ino=0, mode=0)
w("cpio", "minimal.cpio", cpio)

# ---- path strings (the resolver's interesting normalization cases) ------------
for i, s in enumerate([
    b"/a/./b", b"/a/b/../c", b"//a//b/", b"rel/x", b"/../../a", b"/a/../..",
    b"/link", b"/real", b"a/" + b"../" * 40 + b"b",
]):
    w("path", "p%02d" % i, s)

# ---- 9P R-messages: fuzz/harness_9p.c prefixes 5 header bytes -----------------
# [op_sel][step][type][is64][statkind], then the R-message body. op_sel % 4 selects
# {OPEN,READ,GETDENTS,STAT}; type is the 9P reply type (7 = RLERROR).
def p9(op_sel, step, typ, body, is64=0, sk=0):
    return bytes([op_sel & 0xff, step & 0xff, typ & 0xff, is64 & 0xff, sk & 0xff]) + body

# Rread: count[4] + data
w("9p", "rread", p9(1, 0, 1, struct.pack("<I", 8) + b"datadata"))
# Rreaddir: count[4] + entry{ qid[13] off[8] dtype[1] nlen[2] name }
_entry = bytes([2]) + b"\x00\x00\x00\x00" + b"\x01\x00\x00\x00\x00\x00\x00\x00" \
         + struct.pack("<Q", 1) + bytes([4]) + struct.pack("<H", 1) + b"f"
w("9p", "rreaddir", p9(2, 0, 1, struct.pack("<I", len(_entry)) + _entry, is64=1))
# Rgetattr: the 97-byte span parse_getattr reads
w("9p", "rgetattr", p9(3, 1, 1, b"\x00" * 97))
# Rlerror: ecode[4]
w("9p", "rlerror", p9(0, 0, 7, struct.pack("<I", 2)))
# Rwalk: nwqid[2]
w("9p", "rwalk", p9(0, 0, 1, struct.pack("<H", 1)))

print("wrote fdpic/etrel/cpio/path/9p seeds")
PY

echo "seeds written under $corpus"
[ "$enrich" = "1" ] && echo "(enrich: --enrich not yet wired for this phase)"

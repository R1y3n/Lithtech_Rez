#!/usr/bin/env python3
"""
py - LithTech .rez tool: extract, inspect, pack.

  python script.py ARCHIVE.rez [MORE.rez ...]          extract to ./ARCHIVE/
  python code.py ARCHIVE.rez -o DIR                  extract to DIR/ARCHIVE/
  python python.py -v ARCHIVE.rez [MORE.rez ...]       show version and metadata
  python py.py -p FOLDER                           pack to ./FOLDER.rez (format v1)
  python rez.py -p FOLDER -o OUT.rez                pack to OUT.rez
  python lith.py -p FOLDER -clonev SRC.rez           pack using SRC.rez's format
  python lithteck.py -p FOLDER -clonev SRC.rez -o OUT    pack to OUT (dir or file)

-clonev copies the source archive's header bytes exactly (framing, file type,
title, version, and any key or unknown bytes), so the output has the same
format as SRC. Only the offsets and size fields are recomputed.

REZ format (little-endian, offsets from start of file)
    0    CR LF <60-byte file type> CR LF <60-byte title> CR LF
    126  EOF byte: 0x1A (plain header) or 0x2A (encoded header)
    127  plain header: version u32; format 2 has 7 unknown bytes before its
         version (at 134); encoded header: 72 bytes of key data, version at 195
    base 9 x u32: root_pos, root_size, root_time, next_write, time,
         largest key array, largest dir name, largest resource name,
         largest comment; then 1 byte is_sorted
    Directory blocks are flat entry lists. Each entry starts with
    (type, pos, size, time) as u32s:
      type 1 = directory: NUL-terminated name; children block at [pos, pos+size)
      type 0 = resource:  id u32, 4-byte reversed extension, key count u32,
                          NUL-terminated name, NUL-terminated description,
                          key_count x u32 keys. Data is raw at [pos, pos+size).
"""

from __future__ import annotations

import argparse
import datetime as dt
import mmap
import os
import re
import struct
import sys
import time
import zlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

ENTRY_RESOURCE = 0
ENTRY_DIRECTORY = 1
FIRST_RESOURCE_ID = 10000000
DEFAULT_FILE_TYPE = "WinRez"
DEFAULT_TITLE = "LithTech Resource File"
CHUNK = 1 << 20

_U32 = struct.Struct("<I")
_ENTRY_HDR = struct.Struct("<4I")
_HEADER_FIELDS = struct.Struct("<9I")
_HEADER_TAIL_LEN = _HEADER_FIELDS.size + 1  # + is_sorted byte

_BAD_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + [f"COM{i}" for i in range(1, 10)]
    + [f"LPT{i}" for i in range(1, 10)]
)
_ENCODE_RE = re.compile(rb"\s*[-+]?\d+")


class RezError(Exception):
    """A problem that makes an archive (or one of its blocks) unusable."""


# ===========================================================================
# Reading
# ===========================================================================

@dataclass
class Header:
    variant: str            # "v1", "v2" or "enc"
    version: int
    base: int               # offset of the 9-field block
    prefix: bytes           # raw bytes [0:base], copied verbatim by -clonev
    file_type: str
    title: str
    fields: tuple[int, ...]  # the 9 u32 values
    is_sorted: int
    warnings: list[str] = field(default_factory=list)

    @property
    def root_pos(self) -> int:
        return self.fields[0]

    @property
    def root_size(self) -> int:
        return self.fields[1]


@dataclass(frozen=True)
class Resource:
    dir_parts: tuple[str, ...]
    name: str
    ext: str
    rez_id: int
    pos: int
    size: int


@dataclass
class Layout:
    resources: list[Resource] = field(default_factory=list)
    directories: set[tuple[str, ...]] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)
    block_errors: int = 0


@dataclass(frozen=True)
class Job:
    dest: Path
    pos: int
    size: int


def _u32(buf, off: int) -> int:
    return _U32.unpack_from(buf, off)[0]


def parse_header(buf) -> Header:
    if len(buf) < 131:
        raise RezError("file too small to be a REZ archive")

    framing = (
        (0, (0x0D, 0x26)), (1, (0x0A, 0x23)),
        (62, (0x0D, 0x21)), (63, (0x0A, 0x22)),
        (124, (0x0D, 0x25)), (125, (0x0A, 0x27)),
    )
    for off, ok in framing:
        if buf[off] not in ok:
            raise RezError("not a REZ archive (bad header framing)")

    file_type = bytes(buf[2:62]).rstrip(b" \x00").decode("cp1252", "replace")
    title = bytes(buf[64:124]).rstrip(b" \x00").decode("cp1252", "replace")
    warnings: list[str] = []
    eof = buf[126]

    if eof == 0x1A:
        version = _u32(buf, 127)
        if version == 1:
            variant, base = "v1", 131
        elif len(buf) >= 138 and _u32(buf, 134) == 2:
            variant, version, base = "v2", 2, 138
        else:
            raise RezError(f"unsupported REZ format version {version}")

    elif eof == 0x2A:
        head = buf[127]
        encode = bytes(buf[128:160]).split(b"\x00", 1)[0]
        tail = buf[160]
        det_head = buf[161]
        det_encode = bytes(buf[162:194]).split(b"\x00", 1)[0]
        det_tail = buf[194]
        version = _u32(buf, 195)
        if version != 1:
            raise RezError(f"unsupported REZ format version {version}")
        if det_head != (head ^ 0x11) or det_tail != (tail ^ 0x11):
            warnings.append("encoded header: head/tail check bytes do not match")
        m = _ENCODE_RE.match(encode)
        if m and det_encode.decode("ascii", "replace") != str(int(m.group()) ^ 0x16B4423):
            warnings.append("encoded header: key check does not match")
        variant, base = "enc", 199

    else:
        raise RezError(f"unknown EOF marker 0x{eof:02X}")

    if len(buf) < base + _HEADER_TAIL_LEN:
        raise RezError("truncated header")

    fields = _HEADER_FIELDS.unpack_from(buf, base)
    return Header(
        variant=variant, version=version, base=base, prefix=bytes(buf[:base]),
        file_type=file_type, title=title, fields=fields,
        is_sorted=buf[base + _HEADER_FIELDS.size], warnings=warnings,
    )


def read_header(path: Path) -> Header:
    with path.open("rb") as fh:
        if path.stat().st_size < 131:
            raise RezError("file too small to be a REZ archive")
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            return parse_header(mm)


def _cstr(buf, i: int, end: int) -> tuple[str, int]:
    j = buf.find(b"\x00", i, end)
    if j < 0:
        raise RezError("unterminated string inside directory block")
    return bytes(buf[i:j]).decode("cp1252", "replace"), j + 1


def _clean_component(s: str, fallback: str) -> str:
    """Make one path component safe on Windows, macOS and Linux."""
    s = _BAD_CHARS.sub("_", s).strip(" .")
    if not s:
        s = fallback
    if s.split(".", 1)[0].upper() in _RESERVED:
        s = "_" + s
    return s


def _clean_ext(raw: bytes) -> str:
    # Stored reversed and NUL padded: b"xtd\0" -> "dtx".
    text = raw.split(b"\x00", 1)[0].decode("ascii", "replace")
    text = "".join(c for c in text if c.isascii() and (c.isalnum() or c in "_-"))
    return text[::-1]


def _parse_block(buf, pos: int, length: int, parts: tuple[str, ...],
                 resources: list[Resource], subdirs: list) -> None:
    i, end = pos, pos + length
    while i < end:
        if i + _ENTRY_HDR.size > end:
            raise RezError("truncated entry header")
        etype, epos, esize, _etime = _ENTRY_HDR.unpack_from(buf, i)
        i += _ENTRY_HDR.size

        if etype == ENTRY_RESOURCE:
            if i + 12 > end:
                raise RezError("truncated resource record")
            rez_id = _u32(buf, i)
            ext = _clean_ext(bytes(buf[i + 4:i + 8]))
            num_keys = _u32(buf, i + 8)
            i += 12
            name, i = _cstr(buf, i, end)
            _description, i = _cstr(buf, i, end)
            i += 4 * num_keys
            if i > end:
                raise RezError("resource key array overruns block")
            name = _clean_component(name, f"unnamed_{rez_id}")
            resources.append(Resource(parts, name, ext, rez_id, epos, esize))

        elif etype == ENTRY_DIRECTORY:
            name, i = _cstr(buf, i, end)
            subdirs.append((epos, esize, parts + (_clean_component(name, "unnamed_dir"),)))

        else:
            raise RezError(f"unknown entry type {etype}")


def walk(buf, header: Header) -> Layout:
    """Read every directory block with an explicit stack (no recursion limit)."""
    total = len(buf)
    if header.root_pos + header.root_size > total:
        raise RezError("root directory lies outside the file")

    layout = Layout(warnings=list(header.warnings))
    seen: set[int] = set()
    stack = [(header.root_pos, header.root_size, ())]

    while stack:
        pos, length, parts = stack.pop()
        if parts:
            layout.directories.add(parts)
        if length == 0:
            continue
        if pos in seen:
            layout.warnings.append(f"block at offset {pos} referenced twice; skipped")
            continue
        seen.add(pos)
        if pos + length > total:
            layout.warnings.append(f"block at offset {pos} is outside the file; skipped")
            continue

        subdirs: list = []
        try:
            _parse_block(buf, pos, length, parts, layout.resources, subdirs)
        except RezError as exc:
            layout.block_errors += 1
            layout.warnings.append(f"block at offset {pos}: {exc}")
        stack.extend(subdirs)

    return layout


# ===========================================================================
# Extracting
# ===========================================================================

def plan(layout: Layout, out_root: Path, total_size: int) -> list[Job]:
    """Map resources to output paths, resolving collisions (case-insensitive,
    and file-vs-folder clashes) by renaming to 'name (n).ext'."""
    dir_keys = {tuple(p.lower() for p in d) for d in layout.directories}
    used: set[tuple[tuple[str, ...], str]] = set()
    jobs: list[Job] = []

    for r in layout.resources:
        if r.pos + r.size > total_size:
            layout.warnings.append(f"'{r.name}': data lies outside the file; skipped")
            continue
        key_dir = tuple(p.lower() for p in r.dir_parts)
        ext = "." + r.ext if r.ext else ""
        full = r.name + ext
        n = 1
        while (key_dir, full.lower()) in used or key_dir + (full.lower(),) in dir_keys:
            n += 1
            full = f"{r.name} ({n}){ext}"
        used.add((key_dir, full.lower()))
        jobs.append(Job(out_root.joinpath(*r.dir_parts, full), r.pos, r.size))
    return jobs


def _write_one(view, job: Job) -> int:
    with open(job.dest, "wb") as fh:
        if job.size:
            fh.write(view[job.pos:job.pos + job.size])
    return job.size


def write_all(mm, jobs: list[Job], dirs: set[Path], workers: int):
    for d in sorted(dirs):
        d.mkdir(parents=True, exist_ok=True)
    written = 0
    errors: list[tuple[Path, Exception]] = []
    with memoryview(mm) as view, ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [(job, pool.submit(_write_one, view, job)) for job in jobs]
        for job, fut in futures:
            try:
                written += fut.result()
            except OSError as exc:
                errors.append((job.dest, exc))
    return written, errors


def extract_archive(path: Path, out_base: Path, *, list_only: bool, workers: int) -> int:
    started = time.perf_counter()
    root = out_base / path.stem

    with path.open("rb") as fh:
        if path.stat().st_size < 131:
            raise RezError("file too small to be a REZ archive")
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            header = parse_header(mm)
            layout = walk(mm, header)
            jobs = plan(layout, root, len(mm))
            for w in layout.warnings:
                print(f"warning: {path.name}: {w}", file=sys.stderr)

            if list_only:
                for job in jobs:
                    print(f"{job.size:>12}  {job.dest.relative_to(root).as_posix()}")
                print(f"{path.name}: {len(jobs)} files")
                return 0

            dirs = {root} | {j.dest.parent for j in jobs}
            dirs |= {root.joinpath(*p) for p in layout.directories}
            written, errors = write_all(mm, jobs, dirs, workers)
            damaged = layout.block_errors

    elapsed = time.perf_counter() - started
    print(f"{path.name}: {len(jobs) - len(errors)} files, "
          f"{written / 1_048_576:.1f} MB -> {root} ({elapsed:.2f}s)")
    for dest, exc in errors[:10]:
        print(f"error: writing {dest}: {exc}", file=sys.stderr)
    if len(errors) > 10:
        print(f"error: ... and {len(errors) - 10} more write errors", file=sys.stderr)
    if damaged:
        print(f"error: {path.name}: {damaged} damaged directory block(s); "
              f"output is incomplete", file=sys.stderr)
    return 1 if (errors or damaged) else 0


# ===========================================================================
# Inspecting (-v)
# ===========================================================================

def _fmt_time(v: int) -> str:
    if 0 < v < 4_102_444_800:  # plausible Unix time, before year 2100
        return dt.datetime.fromtimestamp(v, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return "not set" if v == 0 else f"raw {v}"


def describe(path: Path) -> int:
    size = path.stat().st_size
    with path.open("rb") as fh:
        if size < 131:
            raise RezError("file too small to be a REZ archive")
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            h = parse_header(mm)
            layout = walk(mm, h)

    f = h.fields
    variant_name = {
        "v1": "plain header (version 1)",
        "v2": "plain header, format 2 layout (version 2)",
        "enc": "encoded header (0x2A)",
    }[h.variant]
    ext_counts = Counter(r.ext or "(none)" for r in layout.resources)
    max_depth = max((len(p) for p in layout.directories), default=0)
    if layout.resources:
        max_depth = max(max_depth, max(len(r.dir_parts) for r in layout.resources))
    data_bytes = sum(r.size for r in layout.resources)

    print(f"File:          {path.name} ({size:,} bytes)")
    print(f"REZ version:   {h.version}")
    print(f"Format:        {variant_name}")
    print(f"File type:     {h.file_type!r}")
    print(f"Title:         {h.title!r}")
    print(f"Root dir:      offset {f[0]:,}, {f[1]:,} bytes")
    print(f"Data end:      offset {f[3]:,} (next write position)")
    print(f"Root time:     {_fmt_time(f[2])}")
    print(f"Time:          {_fmt_time(f[4])}")
    print(f"Sorted:        {'yes' if h.is_sorted else 'no'}")
    print(f"Largest:       key array {f[5]}, dir name {f[6]}, "
          f"resource name {f[7]}, comment {f[8]}")
    print(f"Directories:   {len(layout.directories)}")
    print(f"Resources:     {len(layout.resources)} ({data_bytes:,} bytes of data)")
    print(f"Max depth:     {max_depth}")
    if ext_counts:
        top = ", ".join(f"{e} {n}" for e, n in ext_counts.most_common(15))
        print(f"Extensions:    {top}")
    for w in h.warnings + layout.warnings:
        print(f"warning: {w}", file=sys.stderr)
    return 1 if layout.block_errors else 0


# ===========================================================================
# Packing (-p, -clonev)
# ===========================================================================

@dataclass(eq=False)
class Record:
    """One resource to write."""
    path: Path
    stem: str
    ext: str
    size: int
    stem_bytes: bytes
    type_bytes: bytes
    rez_id: int = 0
    pos: int = 0
    crc: int = 0


@dataclass
class Node:
    files: list[Record] = field(default_factory=list)
    dirs: dict[str, "Node"] = field(default_factory=dict)


def _split_name(filename: str) -> tuple[str, str]:
    """'IMAGE.SVG' -> ('IMAGE', 'SVG'). The type field holds at most 4 chars."""
    stem, dot, ext = filename.rpartition(".")
    if dot and stem and 1 <= len(ext) <= 4 and ext.isascii() and ext.isalnum():
        return stem, ext
    return filename, ""


def _name_bytes(s: str) -> bytes:
    return s.encode("cp1252", "replace")


def _cp1252_ok(s: str) -> bool:
    try:
        s.encode("cp1252")
        return True
    except UnicodeEncodeError:
        return False


def scan(folder: Path, exclude: Path, warnings: list[str]) -> Node:
    """Read the folder tree. Sorted, symlinks skipped, output file excluded."""
    root = Node()
    exclude_resolved = exclude.resolve()
    stack = [(folder, root)]
    while stack:
        d, node = stack.pop()
        with os.scandir(d) as it:
            entries = sorted(it, key=lambda e: e.name.lower())
        for e in entries:
            p = Path(e.path)
            if e.is_symlink():
                warnings.append(f"skipped symlink {p}")
                continue
            if e.is_dir(follow_symlinks=False):
                if not _cp1252_ok(e.name):
                    warnings.append(f"folder name not cp1252-safe, written lossy: {e.name!r}")
                child = Node()
                node.dirs[e.name] = child
                stack.append((p, child))
            elif e.is_file(follow_symlinks=False):
                if p.resolve() == exclude_resolved:
                    continue
                if not _cp1252_ok(e.name):
                    warnings.append(f"file name not cp1252-safe, written lossy: {e.name!r}")
                stem, ext = _split_name(e.name)
                node.files.append(Record(
                    path=p, stem=stem, ext=ext, size=e.stat().st_size,
                    stem_bytes=_name_bytes(stem) or b"unnamed",
                    type_bytes=ext[::-1].encode("ascii").ljust(4, b"\x00") if ext else b"\x00" * 4,
                ))
            else:
                warnings.append(f"skipped special file {p}")
    return root


def _collect(node: Node, out: list[Record]) -> None:
    """Deterministic order: files of this folder, then subfolders."""
    out.extend(node.files)
    for name in sorted(node.dirs, key=str.lower):
        _collect(node.dirs[name], out)


def _copy_file(src: Path, size: int, dst) -> int:
    crc = 0
    total = 0
    with open(src, "rb") as s:
        while True:
            chunk = s.read(CHUNK)
            if not chunk:
                break
            crc = zlib.crc32(chunk, crc)
            total += len(chunk)
            dst.write(chunk)
    if total != size:
        raise RezError(f"'{src}' changed size while packing")
    return crc & 0xFFFFFFFF


def _emit(f, node: Node, stats: dict) -> tuple[int, int]:
    """Write a directory block (children first). Returns (pos, size)."""
    parts: list[bytes] = []
    for name in sorted(node.dirs, key=str.lower):
        cpos, csize = _emit(f, node.dirs[name], stats)
        nb = _name_bytes(name)
        stats["dir_name"] = max(stats["dir_name"], len(nb) + 1)
        parts.append(_ENTRY_HDR.pack(ENTRY_DIRECTORY, cpos, csize, 0) + nb + b"\x00")

    for rec in node.files:
        stats["res_name"] = max(stats["res_name"], len(rec.stem_bytes) + 1)
        parts.append(
            _ENTRY_HDR.pack(ENTRY_RESOURCE, rec.pos, rec.size, 0)
            + _U32.pack(rec.rez_id) + rec.type_bytes + _U32.pack(0)
            + rec.stem_bytes + b"\x00" + b"\x00"   # name, empty description
        )

    blob = b"".join(parts)
    pos = f.tell()
    f.write(blob)
    return pos, len(blob)


def _new_prefix(file_type: str, title: str) -> bytes:
    def fixed(s: str) -> bytes:
        return s.encode("cp1252", "replace")[:60].ljust(60, b" ")
    return (b"\r\n" + fixed(file_type) + b"\r\n" + fixed(title) + b"\r\n"
            + b"\x1a" + _U32.pack(1))


def verify_output(path: Path, records: list[Record]) -> None:
    """Re-read the written archive and check every resource's position, size and CRC."""
    with path.open("rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        header = parse_header(mm)
        layout = walk(mm, header)
        if layout.block_errors or layout.warnings:
            raise RezError(f"verification failed: {layout.warnings or 'damaged blocks'}")
        if len(layout.resources) != len(records):
            raise RezError(f"verification failed: {len(layout.resources)} resources, "
                           f"expected {len(records)}")
        by_id = {r.rez_id: r for r in records}
        for res in layout.resources:
            rec = by_id.get(res.rez_id)
            if rec is None or res.pos != rec.pos or res.size != rec.size:
                raise RezError(f"verification failed: resource id {res.rez_id} misplaced")
            if zlib.crc32(mm[res.pos:res.pos + res.size]) & 0xFFFFFFFF != rec.crc:
                raise RezError(f"verification failed: data CRC mismatch for {res.name!r}")


def pack(folder: Path, out: Path, *, source: Header | None, file_type: str,
         title: str, verify: bool) -> tuple[int, int, float, list[str], str]:
    if not folder.is_dir():
        raise RezError(f"not a folder: {folder}")

    started = time.perf_counter()
    warnings: list[str] = []
    root = scan(folder, out, warnings)
    records: list[Record] = []
    _collect(root, records)
    for i, rec in enumerate(records):
        rec.rez_id = FIRST_RESOURCE_ID + i

    if source is None:
        prefix = _new_prefix(file_type, title)
        root_time, now, is_sorted = 0, int(time.time()), 0
    else:
        prefix = source.prefix
        root_time, now, is_sorted = source.fields[2], source.fields[4], source.is_sorted

    tmp = out.with_name(out.name + ".tmp")
    try:
        with tmp.open("wb") as f:
            f.write(prefix)
            f.write(b"\x00" * _HEADER_TAIL_LEN)  # placeholder, rewritten below
            for rec in records:
                rec.pos = f.tell()
                rec.crc = _copy_file(rec.path, rec.size, f)

            stats = {"dir_name": 0, "res_name": 0}
            root_pos, root_size = _emit(f, root, stats)
            end = f.tell()

            fields = (root_pos, root_size, root_time, end, now, 0,
                      stats["dir_name"], stats["res_name"], 1 if records else 0)
            f.seek(len(prefix))
            f.write(_HEADER_FIELDS.pack(*fields) + bytes([is_sorted]))

        if verify:
            verify_output(tmp, records)
        os.replace(tmp, out)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    total_bytes = sum(r.size for r in records)
    variant = source.variant if source else "v1"
    version = source.version if source else 1
    fmt = f"{variant}, REZ version {version}"
    return len(records), total_bytes, time.perf_counter() - started, warnings, fmt


# ===========================================================================
# CLI
# ===========================================================================

def do_extract(args) -> int:
    out_base = args.out or Path(".")
    status = 0
    for archive in args.archives:
        try:
            status |= extract_archive(archive, out_base,
                                      list_only=args.list, workers=max(1, args.jobs))
        except (RezError, OSError) as exc:
            print(f"error: {archive}: {exc}", file=sys.stderr)
            status = 1
    return status


def do_info(args) -> int:
    status = 0
    for i, archive in enumerate(args.archives):
        if i:
            print()
        try:
            status |= describe(archive)
        except (RezError, OSError) as exc:
            print(f"error: {archive}: {exc}", file=sys.stderr)
            status = 1
    return status


def do_pack(args) -> int:
    folder: Path = args.pack
    name = folder.resolve().name or "archive"
    out = args.out
    if out is None:
        out = Path(f"{name}.rez")
    elif out.is_dir():
        out = out / f"{name}.rez"

    source = None
    if args.clonev:
        source = read_header(args.clonev)
        for w in source.warnings:
            print(f"warning: {args.clonev.name}: {w}", file=sys.stderr)

    count, nbytes, secs, warnings, fmt = pack(
        folder, out, source=source,
        file_type=args.file_type, title=args.title,
        verify=not args.no_verify,
    )
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    verified = "" if args.no_verify else ", verified"
    print(f"{out.name}: {count} files, {nbytes / 1_048_576:.1f} MB, "
          f"{fmt} -> {out} ({secs:.2f}s{verified})")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Extract, inspect and pack LithTech .rez archives.",
        epilog="Extract is the default mode. -p and -v are mutually exclusive.",
    )
    ap.add_argument("archives", nargs="*", type=Path, metavar="ARCHIVE.rez",
                    help="archives to extract (or inspect with -v)")
    ap.add_argument("-v", "--info", action="store_true",
                    help="show version and metadata of the archive(s)")
    ap.add_argument("-p", "--pack", type=Path, metavar="FOLDER",
                    help="pack FOLDER into a .rez file")
    ap.add_argument("-clonev", "--clonev", type=Path, metavar="SRC.rez",
                    help="with -p: use the same format (version, header, title) as SRC.rez")
    ap.add_argument("-o", "--out", type=Path,
                    help="extract: output directory (default ./); "
                         "pack: output .rez file or directory (default FOLDER.rez)")
    ap.add_argument("-l", "--list", action="store_true",
                    help="extract: list contents without writing")
    ap.add_argument("-j", "--jobs", type=int, default=min(8, os.cpu_count() or 4),
                    help="extract: writer threads (default up to 8)")
    ap.add_argument("--file-type", default=DEFAULT_FILE_TYPE,
                    help="pack: file type string for new archives (ignored with -clonev)")
    ap.add_argument("--title", default=DEFAULT_TITLE,
                    help="pack: title string for new archives (ignored with -clonev)")
    ap.add_argument("--no-verify", action="store_true",
                    help="pack: skip the post-write verification pass")
    args = ap.parse_args(argv)

    if args.pack is not None:
        if args.archives:
            ap.error("-p packs a folder; do not also give archives")
        if args.info:
            ap.error("-v and -p cannot be combined")
        if args.list:
            ap.error("-l applies to extraction only")
        try:
            return do_pack(args)
        except (RezError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.clonev is not None:
        ap.error("-clonev needs -p FOLDER")
    if not args.archives:
        ap.error("nothing to do: give ARCHIVE.rez files, or -p FOLDER")

    if args.info:
        if args.out is not None:
            ap.error("-o is not used with -v")
        return do_info(args)
    return do_extract(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:  # e.g. piped into `head`; exit quietly
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)

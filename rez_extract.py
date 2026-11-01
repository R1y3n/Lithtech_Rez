#!/usr/bin/env python3
"""
rez_extract.py - fast, dependency-free extractor for LithTech .rez archives.

Usage
    python rez_extract.py GAME.REZ [MORE.REZ ...]     extract to ./GAME/
    python rez_extract.py GAME.REZ -o out             extract to out/GAME/
    python rez_extract.py GAME.REZ --list             list contents, write nothing

Every archive is extracted into OUT/<archive-name>/ (OUT defaults to ./).

REZ format (all integers little-endian, offsets from start of file)
    0    CR LF <60-byte file type> CR LF <60-byte title> CR LF     framing
    126  EOF byte: 0x1A (plain header) or 0x2A (encoded header)
    127  plain header: version u32, then the fields in parse_header()
    Directory blocks are flat lists of entries. Each entry starts with
    four u32s: type, pos, size, time.
      type 1 = directory: a NUL-terminated name follows. Its children are a
               block at [pos, pos+size).
      type 0 = resource:  id u32, 4-byte reversed extension, key count u32,
               NUL-terminated name, NUL-terminated description, then
               key_count * u32 keys (skipped). The data is raw bytes at
               [pos, pos+size).
"""

from __future__ import annotations

import argparse
import mmap
import os
import re
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

ENTRY_RESOURCE = 0
ENTRY_DIRECTORY = 1

_U32 = struct.Struct("<I")
_ENTRY_HDR = struct.Struct("<4I")
_HEADER_TAIL = struct.Struct("<9I")  # root pos/size/time, next write, time, 4 limits

_BAD_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + [f"COM{i}" for i in range(1, 10)]
    + [f"LPT{i}" for i in range(1, 10)]
)
_ENCODE_RE = re.compile(rb"\s*[-+]?\d+")


class RezError(Exception):
    """A problem that makes an archive (or one of its blocks) unusable."""


@dataclass
class Header:
    version: int
    title: str
    root_pos: int
    root_size: int
    warnings: list[str] = field(default_factory=list)


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


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

def parse_header(buf) -> Header:
    if len(buf) < 131:
        raise RezError("file too small to be a REZ archive")

    framing = (
        (0, (0x0D, 0x26)), (1, (0x0A, 0x23)),    # CR LF  (or '&' '#')
        (62, (0x0D, 0x21)), (63, (0x0A, 0x22)),  # CR LF  (or '!' '"')
        (124, (0x0D, 0x25)), (125, (0x0A, 0x27)),  # CR LF (or '%' "'")
    )
    for off, ok in framing:
        if buf[off] not in ok:
            raise RezError("not a REZ archive (bad header framing)")

    title = bytes(buf[64:124]).rstrip(b" \x00").decode("cp1252", "replace")
    warnings: list[str] = []
    eof = buf[126]

    if eof == 0x1A:
        version = _u32(buf, 127)
        if version == 1:
            base = 131
        elif len(buf) >= 138 and _u32(buf, 134) == 2:
            # Format 2 keeps the version 7 bytes further on.
            version, base = 2, 138
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
        base = 199

    else:
        raise RezError(f"unknown EOF marker 0x{eof:02X}")

    if len(buf) < base + _HEADER_TAIL.size + 1:
        raise RezError("truncated header")

    root_pos, root_size = _HEADER_TAIL.unpack_from(buf, base)[:2]
    return Header(version, title, root_pos, root_size, warnings)


# ---------------------------------------------------------------------------
# Directory walking
# ---------------------------------------------------------------------------

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
    # Stored reversed, NUL padded: b"xtd\0" -> "dtx". Keep only safe characters.
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
            child = _clean_component(name, "unnamed_dir")
            subdirs.append((epos, esize, parts + (child,)))

        else:
            raise RezError(f"unknown entry type {etype}")


def walk(buf, header: Header) -> Layout:
    """Iteratively read every directory block. Explicit stack, no recursion limit."""
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


# ---------------------------------------------------------------------------
# Planning and writing
# ---------------------------------------------------------------------------

def plan(layout: Layout, out_root: Path, total_size: int) -> list[Job]:
    """Turn resources into output paths. Resolves name collisions, including
    case-insensitive ones, and file/folder name clashes."""
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


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def process_archive(path: Path, out_base: Path, *, list_only: bool,
                    workers: int, verbose: bool) -> int:
    """Extract one archive. Returns 0 on success, 1 on any failure."""
    started = time.perf_counter()
    root = out_base / path.stem

    if path.stat().st_size < 131:
        raise RezError("file too small to be a REZ archive")

    with path.open("rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        header = parse_header(mm)
        layout = walk(mm, header)
        jobs = plan(layout, root, len(mm))

        if verbose:
            print(f"{path.name}: REZ version {header.version}, title {header.title!r}")
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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Extract LithTech .rez archives.")
    ap.add_argument("archives", nargs="+", type=Path, metavar="FILE.rez")
    ap.add_argument("-o", "--out", type=Path, default=Path("."),
                    help="output root; each archive goes into OUT/<name>/ (default: ./)")
    ap.add_argument("-l", "--list", action="store_true",
                    help="list the archive contents without extracting")
    ap.add_argument("-j", "--jobs", type=int, default=min(8, os.cpu_count() or 4),
                    help="parallel writer threads (default: up to 8)")
    ap.add_argument("-v", "--verbose", action="store_true", help="show header details")
    args = ap.parse_args(argv)

    status = 0
    for archive in args.archives:
        try:
            status |= process_archive(
                archive, args.out,
                list_only=args.list, workers=max(1, args.jobs), verbose=args.verbose,
            )
        except (RezError, OSError) as exc:
            print(f"error: {archive}: {exc}", file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())

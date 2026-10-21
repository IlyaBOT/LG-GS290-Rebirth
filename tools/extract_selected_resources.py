#!/usr/bin/env python3
"""Selectively restore FAT16 files from verified GS290 V10C manifest, offline.

Input image must be extracted raw .dfat.segment0.bin (not the outer .dfat).
The manifest's source_extents offsets are relative to the original Infineon
container; raw data started at offset 0xCF8, so subtract that for the image.
Every extracted file is SHA256-verified against the supplied manifest.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

def run(image, manifest, output, patterns, max_bytes):
    rows = json.loads(Path(manifest).read_text(encoding='utf-8'))['files']
    destination = Path(output)
    destination.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(image, 'rb') as src:
        for record in rows:
            path = record['path']
            if record['directory'] or record['size'] > max_bytes:
                continue
            if not any(re.search(regex, path, re.IGNORECASE) for regex in patterns):
                continue
            parts = PurePosixPath(path).parts
            if not parts or any(p in ('..', '.', '') for p in parts):
                raise ValueError(f'Unsafe path: {path}')
            left = record['size']
            collected = bytearray()
            for extent in record['source_extents']:
                read_size = min(left, extent['allocated_size'])
                off = extent['offset'] - 0xCF8
                if off < 0:
                    raise ValueError(f'Invalid extent for {path}')
                src.seek(off)
                chunk = src.read(read_size)
                if len(chunk) != read_size:
                    raise EOFError(f'Incomplete resource: {path}')
                collected.extend(chunk)
                left -= read_size
                if left == 0:
                    break
            if left:
                raise ValueError(f'Truncated resource: {path}')
            digest = hashlib.sha256(collected).hexdigest()
            if digest != record['sha256']:
                raise ValueError(f'Hash mismatch for {path}')
            target = destination.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(collected)
            count += 1
    print(f'Extracted + SHA256 verified: {count} files')

if __name__ == '__main__':
    cli = argparse.ArgumentParser()
    cli.add_argument('--image', required=True)
    cli.add_argument('--manifest', required=True)
    cli.add_argument('--output', required=True)
    cli.add_argument('--pattern', action='append', required=True)
    cli.add_argument('--max-bytes', type=int, default=40_000_000)
    a = cli.parse_args()
    run(a.image, a.manifest, a.output, a.pattern, a.max_bytes)

#!/usr/bin/env python3
"""Offline binary evidence checks for LG GS290 V10C SEA; no USB, no device I/O.

The arithmetic model is NOT a working JAR exploit and does not demonstrate RCE.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zlib

SEGMENTS = {
    'MPEH_segment0_46c00000.bin': '0f9338bb6e6a80205ebd4a1d726a46eb039bbec9409b47e3138b079cffc3fa3c',
    'MPEH_segment1_47800000.bin': 'f34f69dacfe5b570fafaa9e102196ebfa8fbeb9b01c5459cc0424661e67387a4',
}
INSTRUCTIONS = {
    0x47876D0C: 'ff4f2de9',  # ARM prologue
    0x47876E20: '0c008de2',  # add r0, sp, #12
    0x47876F14: '010087e0',  # add r0, r7, r1
    0x47876F24: '010050e1',  # cmp r0, r1
    0x47876F28: '0b00009a',  # bls
    0x47876F5C: '100058e3',  # cmp r8, #16
    0x47877020: '012057e5',  # ldrb r2, [r7, #-1]
    0x4787702C: 'f375d4eb',  # bl fill
    0x46D94800: 'ff3002e2',  # and r3, r2, #255
    0x46D80324: '040051e3',  # cmp r1, #4
}

def load_and_verify(path):
    data = Path(path).read_bytes()
    expected = SEGMENTS[Path(path).name]
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError(f"SHA mismatch for {path}: {actual}")
    return data

def run(segment_dir, resources_dir=None):
    segment_dir = Path(segment_dir)
    data = {
        0x46C00000: load_and_verify(segment_dir / 'MPEH_segment0_46c00000.bin'),
        0x47800000: load_and_verify(segment_dir / 'MPEH_segment1_47800000.bin'),
    }
    for address, expected in INSTRUCTIONS.items():
        base = 0x47800000 if address >= 0x47800000 else 0x46C00000
        observed = data[base][address - base:address - base + 4].hex()
        if observed != expected:
            raise ValueError(f"ARM opcode mismatch at {address:#x}: {observed}")
    # Simple index arithmetic, not a DEFLATE decoder or real device test.
    index = 0
    for count in (138, 138, 40, 1):
        index += count
    assert index == 317
    end = index + 6
    assert end == 323
    out = {
        'verified_segments': list(SEGMENTS),
        'verified_instruction_words': len(INSTRUCTIONS),
        'boundary_model': {'buffer_bytes': 320, 'max_hlit_plus_hdist': 318,
                           'repeat_start': index, 'repeat_count': 6,
                           'end': end, 'possible_oob_bytes': end - 320,
                           'exploitability': 'NOT PROVEN'},
    }
    if resources_dir:
        root = Path(resources_dir)
        weather = root / 'LGAPP/Obigo/wga/widgets/Weather/data/weather.js'
        if weather.is_file():
            source = weather.read_text(errors='replace')
            markers = ('http://lgelc.accu-weather.com/widget/',
                       'req.responseXML', 'this.weathertext +',
                       "eval('(' + td + ')')",
                       'widget.setPreferenceForKey(today.toJsonStr()')
            missing = [marker for marker in markers if marker not in source]
            if missing:
                raise ValueError(f"Missing weather-widget evidence: {missing!r}")
            out['weather_widget_dataflow'] = 'Static source -> storage -> eval verified'
        swfs = list((root / 'LGAPP/DMF/Game').glob('*.swf'))
        if swfs:
            marked = 0
            invalid_zlib = 0
            for p in swfs:
                content = p.read_bytes()
                if content[8:11] != b'CWS':
                    continue
                marked += 1
                try:
                    zlib.decompress(content[16:])
                except zlib.error:
                    invalid_zlib += 1
            out['swf'] = {'count': len(swfs), 'cws_at_offset_8': marked,
                          'direct_zlib_rejected': invalid_zlib}
    return out

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--segments', required=True)
    p.add_argument('--resources')
    args = p.parse_args()
    print(json.dumps(run(args.segments, args.resources), indent=2, ensure_ascii=False))

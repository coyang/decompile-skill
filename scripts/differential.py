#!/usr/bin/env python3
"""Sandboxed sample testing for int32_t f(int32_t); never a replacement approval."""
import argparse
import json
from pathlib import Path
import sys
import tempfile

from verify import Unknown, canonical, digest, regular_bytes, sandbox

WORKER = r'''
import ctypes,json,sys
inputs=json.load(open('/inputs/cases.json'))
lib=ctypes.CDLL('/inputs/library', use_errno=True)
fn=getattr(lib, inputs['function'])
fn.argtypes=[ctypes.c_int32]
fn.restype=ctypes.c_int32
out=[]
for value in inputs['values']:
    ctypes.set_errno(0)
    result=fn(value)
    out.append([value,result,ctypes.get_errno()])
print(json.dumps(out))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original')
    parser.add_argument('candidate')
    parser.add_argument('--function', required=True)
    parser.add_argument('--values', required=True, help='JSON array of signed 32-bit inputs in call order')
    parser.add_argument('--timeout', type=int, default=10)
    args = parser.parse_args()
    report = {'schema_version': 1, 'correctness': 'UNKNOWN', 'replacement': {'approved': False},
              'scope': 'one int32(int32) function; ordered calls in fresh process per artifact; return and errno only',
              'limitations': ['No claim about other inputs, hidden state, side effects, ABI correctness, undefined behavior or deployment.']}
    try:
        values = json.loads(args.values)
        if not isinstance(values, list) or not 1 <= len(values) <= 10000 or any(type(x) is not int or not -2**31 <= x < 2**31 for x in values):
            raise Unknown('values must contain 1..10000 int32 integers')
        if not 1 <= args.timeout <= 3600:
            raise Unknown('timeout must be 1..3600')
        with tempfile.TemporaryDirectory(prefix='decompile-diff-') as temporary:
            root = Path(temporary)
            results = []
            report['artifacts'] = {}
            for label, path in [('original', args.original), ('candidate', args.candidate)]:
                inputs = root / label; inputs.mkdir()
                data = regular_bytes(path)
                report['artifacts'][label + '_sha256'] = digest(data)
                (inputs / 'library').write_bytes(data)
                (inputs / 'cases.json').write_bytes(canonical({'function': args.function, 'values': values}))
                work = root / (label + '-work'); work.mkdir()
                result = json.loads(sandbox(['/usr/bin/python3', '-I', '-c', WORKER], work,
                                            [(inputs, '/inputs')], args.timeout))
                if not isinstance(result, list) or len(result) != len(values):
                    raise Unknown('incomplete sample observations')
                results.append(result)
            report['observations'] = dict(zip(('original', 'candidate'), results))
            report['correctness'] = 'TESTED' if results[0] == results[1] else 'COUNTEREXAMPLE'
            report['cases'] = len(values)
        code = 0 if report['correctness'] == 'TESTED' else 1
    except Exception as exc:
        report['reason'] = str(exc)
        code = 2
    print(json.dumps(report, indent=2))
    return code


if __name__ == '__main__':
    sys.exit(main())

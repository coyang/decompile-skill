#!/usr/bin/env python3
"""Fail-closed ELF reconstruction acceptance. No heuristic score is a proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import secrets
import struct
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time

SCHEMA = 2
MAX_OUTPUT = 2 * 1024 * 1024
MAX_FILE = 512 * 1024 * 1024
SOURCE_ROOTS = ('src', 'include', 'Makefile')
TOOLS = {'readelf': '/usr/bin/readelf', 'bwrap': '/usr/bin/bwrap'}
REQUIRED_OBLIGATIONS = {
    'proof': ['all-inputs-and-reachable-states', 'return-and-memory-effects', 'external-effects',
              'errors-exceptions-and-unwind', 'initialization-and-finalization', 'termination-and-divergence',
              'concurrency-and-atomics', 'machine-semantics-and-undefined-behavior'],
    'abi': ['all-symbols-and-versions', 'calling-conventions-and-prototypes', 'data-tls-and-ifunc',
            'layouts-vtables-and-rtti', 'loader-dependencies-and-lifecycle'],
    'integration': ['all-declared-consumers', 'target-runtime-and-loader', 'cold-start-and-rollback-contract'],
}
REQUIRED_OBSERVATIONS = ['return-values', 'memory-and-global-state', 'errors-and-exceptions',
                         'external-effects', 'initialization-and-finalization',
                         'termination-and-divergence', 'concurrency-and-atomics']


class Unknown(Exception):
    """Required evidence could not be established."""


class Rejected(Exception):
    """A concrete acceptance requirement was violated."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular_bytes(path):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
            raise Unknown(f'not a regular file within size limit: {path}')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(MAX_FILE + 1)
        after = os.fstat(fd)
        signature = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if signature(before) != signature(after) or len(data) != before.st_size:
            raise Unknown(f'file changed while reading: {path}')
        return data
    finally:
        os.close(fd)


def file_hash(path):
    return digest(regular_bytes(path))


def load_json(data):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise Unknown(f'duplicate JSON key: {key}')
            out[key] = value
        return out
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(Unknown(f'invalid JSON number: {x}')))


def inside(root, relative):
    p = Path(relative)
    if p.is_absolute() or not p.parts or '..' in p.parts:
        raise Unknown(f'expected relative contained path: {relative}')
    result = root / p
    for part in [result, *result.parents]:
        if part == root:
            break
        if part.is_symlink():
            raise Unknown(f'symlink in input path: {part}')
    if not result.resolve().is_relative_to(root.resolve()):
        raise Unknown('path escapes reconstruction')
    return result


def source_manifest(tree):
    manifest = {}
    for name in SOURCE_ROOTS:
        root = tree / name
        if root.is_symlink():
            raise Unknown(f'symlink source root: {root}')
        if not root.exists():
            raise Unknown(f'missing build input: {root}')
        for path in sorted(root.rglob('*')) if root.is_dir() else [root]:
            if path.is_symlink():
                raise Unknown(f'symlink source: {path}')
            if path.is_dir():
                continue
            data = regular_bytes(path)
            if name != 'Makefile':
                require(path.suffix in ('.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx', '.inc'), 'only C/C++ source/header inputs are supported')
            require(b'\x00' not in data and not data.startswith((b'\x7fELF', b'!<arch>')), 'binary/prebuilt source input rejected')
            data.decode('utf-8')
            manifest[path.relative_to(tree).as_posix()] = digest(data)
    if not any(p.startswith('src/') for p in manifest):
        raise Unknown('no source files')
    return manifest


def bounded(argv, timeout=30):
    """No shell. Bound wall time, address space and output; kill whole process group."""
    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE, MAX_FILE))
        resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
        resource.setrlimit(resource.RLIMIT_CPU, (max(1, int(timeout)), max(2, int(timeout) + 1)))
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(argv, stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                                   start_new_session=True, preexec_fn=limits,
                                   env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise Unknown(f'tool timed out after {timeout}s: {argv[0]}') from exc
        finally:
            # A completed parent may have left children behind.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        out.seek(0); err.seek(0)
        stdout, stderr = out.read(MAX_OUTPUT + 1), err.read(MAX_OUTPUT + 1)
        if len(stdout) >= MAX_OUTPUT or len(stderr) >= MAX_OUTPUT:
            raise Unknown('tool output limit reached')
        if code != 0:
            raise Unknown(f'tool exited {code}: {argv[0]}: {stderr.decode(errors="replace")[:1000]}')
        return stdout


def sandbox(argv, work, readonly=(), timeout=30, runtime=True):
    bwrap = TOOLS['bwrap']
    if not Path(bwrap).is_file():
        raise Unknown('bubblewrap unavailable; refusing to execute build or verifier')
    cmd = [bwrap, '--unshare-all', '--die-with-parent', '--new-session', '--cap-drop', 'ALL',
           '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LC_ALL', 'C',
           '--setenv', 'HOME', '/tmp', '--setenv', 'TMPDIR', '/tmp']
    for path in ('/usr', '/bin', '/lib', '/lib64') if runtime else ():
        if Path(path).exists():
            cmd += ['--ro-bind', path, path]
    cmd += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--bind', str(work), '/work', '--chdir', '/work']
    for source, destination in readonly:
        cmd += ['--ro-bind', str(source), destination]
    return bounded(cmd + ['--'] + argv, timeout)


def elf_info(path):
    data = regular_bytes(path)
    if len(data) < 64 or data[:4] != b'\x7fELF':
        raise Unknown('not a complete ELF header')
    tool = TOOLS['readelf']
    if not Path(tool).is_file():
        raise Unknown('readelf unavailable')
    endian = '<' if data[5] == 1 else '>' if data[5] == 2 else None
    require(endian is not None and data[4] in (1, 2), 'unsupported ELF encoding')
    if data[4] == 2:
        phoff = struct.unpack_from(endian + 'Q', data, 32)[0]
        phsize, phnum = struct.unpack_from(endian + 'HH', data, 54)
        fmt = endian + 'IIQQQQQQ'
    else:
        phoff = struct.unpack_from(endian + 'I', data, 28)[0]
        phsize, phnum = struct.unpack_from(endian + 'HH', data, 42)
        fmt = endian + 'IIIIIIII'
    require(phnum < 65535 and phoff + phsize * phnum <= len(data), 'invalid ELF program header table')
    if phnum:
        require(phsize == struct.calcsize(fmt), 'unsupported ELF program header size')
    for index in range(phnum):
        fields = struct.unpack_from(fmt, data, phoff + index * phsize)
        offset, filesz, memsz = (fields[2], fields[5], fields[6]) if data[4] == 2 else (fields[1], fields[4], fields[5])
        require(offset + filesz <= len(data), 'truncated ELF segment')
        if fields[0] == 1:
            require(memsz >= filesz, 'invalid ELF LOAD size')
    text = bounded([tool, '-h', '-l', '-d', '--dyn-syms', '--wide', str(path)]).decode(errors='replace')
    fields = {}
    for key in ('Class', 'Data', 'OS/ABI', 'ABI Version', 'Type', 'Machine', 'Flags'):
        match = re.search(r'^\s*' + re.escape(key) + r':\s*(.+)$', text, re.M)
        if not match:
            raise Unknown(f'cannot parse ELF {key}')
        fields[key] = match.group(1).strip()
    exports = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 8 and re.fullmatch(r'\d+:', parts[0]):
            if parts[4] in ('GLOBAL', 'WEAK', 'UNIQUE') and parts[6] != 'UND':
                exports.append({'name': parts[7], 'type': parts[3], 'binding': parts[4],
                                'visibility': parts[5], 'size': int(parts[2]) if parts[3] in ('OBJECT', 'TLS') else None})
    return {'header': fields, 'exports': sorted(exports, key=lambda x: x['name']),
            'needed': sorted(re.findall(r'\(NEEDED\).*?\[(.*?)\]', text)),
            'soname': re.findall(r'\(SONAME\).*?\[(.*?)\]', text),
            'search_path': re.findall(r'\((?:RUNPATH|RPATH)\).*?\[(.*?)\]', text),
            'interpreter': 'INTERP' in text,
            'pie': bool(re.search(r'\(FLAGS_1\).*\bPIE\b', text))}


def require(condition, message):
    if not condition:
        raise Unknown(message)


def hash_string(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def text_list(value):
    return isinstance(value, list) and bool(value) and all(isinstance(x, str) and x.strip() for x in value) and len(value) == len(set(value))


def timeout_value(value):
    require(type(value) is int and 1 <= value <= 3600, 'timeout_seconds must be an integer from 1 to 3600')
    return value


def environment_state(config):
    require(isinstance(config, dict) and isinstance(config.get('id'), str) and config['id'], 'environment.id required')
    actual = {'id': config['id'], 'system': platform.system(), 'machine': platform.machine(), 'release': platform.release()}
    for name in ('system', 'machine', 'release'):
        require(config.get(name) == actual[name], f'environment {name} mismatch')
    files = config.get('files')
    require(isinstance(files, dict) and bool(files), 'environment.files must pin runtime/toolchain files')
    actual['files'] = {}
    for name, expected in sorted(files.items()):
        require(Path(name).is_absolute() and hash_string(expected), 'invalid environment file pin')
        # System symlinks are resolved and recorded; later resolution changes are detected by bytes/path.
        resolved = Path(name).resolve(strict=True)
        actual['files'][name] = {'resolved': str(resolved), 'sha256': file_hash(resolved)}
        require(actual['files'][name]['sha256'] == expected, f'environment file mismatch: {name}')
    return actual


def check_policy(policy, report, tree):
    require(type(policy) is dict and type(policy.get('schema_version')) is int and policy['schema_version'] == 1, 'policy schema_version must be 1')
    require(set(policy) <= {'schema_version', 'original_sha256', 'source_sha256', 'scope', 'environment', 'deployment', 'build', 'tools', 'verifiers'}, 'unknown policy fields')
    require(policy.get('original_sha256') == report['artifacts']['original_sha256'], 'original hash not authorized by policy')
    require(policy.get('source_sha256') == report['sources']['sha256'], 'source tree hash not authorized by policy')
    scope = policy.get('scope', {})
    require(isinstance(scope.get('id'), str) and bool(scope['id']), 'scope.id required')
    require(text_list(scope.get('observations')) and text_list(scope.get('assumptions')), 'scope observations/assumptions must be explicit nonempty lists')
    environment = environment_state(policy.get('environment'))
    deployment = policy.get('deployment', {})
    require(deployment.get('strategy') == 'cold-start', 'only cold-start replacement is supported')
    require(deployment.get('loader_context_unchanged') is True, 'policy must establish unchanged loader context')
    require(deployment.get('rollback_sha256') == report['artifacts']['original_sha256'], 'rollback artifact hash mismatch')
    target = Path(deployment.get('target', ''))
    require(target.is_absolute() and not target.resolve().is_relative_to(tree), 'deployment target must be absolute and outside reconstruction')
    require(file_hash(target) == report['artifacts']['original_sha256'], 'deployment target is no longer the original artifact')
    tools = measured_tools()
    require(policy.get('tools') == tools, 'policy.tools must exactly pin gate, Python, readelf and bubblewrap')
    build = policy.get('build', {})
    require(set(build) <= {'compiler', 'compiler_sha256', 'sources', 'flags', 'timeout_seconds'}, 'unknown build fields; arbitrary build commands are unsupported')
    compiler = build.get('compiler')
    require(compiler in ('/usr/bin/gcc', '/usr/bin/g++', '/usr/bin/clang', '/usr/bin/clang++'), 'unsupported compiler path')
    require(file_hash(Path(compiler).resolve(strict=True)) == build.get('compiler_sha256'), 'compiler hash mismatch')
    require(text_list(build.get('sources')), 'build.sources must explicitly list C/C++ translation units')
    for source in build['sources']:
        require(source.startswith('src/') and Path(source).suffix in ('.c', '.cc', '.cpp', '.cxx'), 'invalid translation unit')
        inside(tree, source)
        require(source in report['sources']['files'], 'translation unit not in source manifest')
    require(set(build['sources']) == {x for x in report['sources']['files'] if x.startswith('src/') and Path(x).suffix in ('.c', '.cc', '.cpp', '.cxx')}, 'all source translation units must be built')
    flags = build.get('flags', [])
    allowed = {'-O0', '-O1', '-O2', '-O3', '-Os', '-Og', '-g0', '-fno-ident', '-fno-stack-protector',
               '-fno-asynchronous-unwind-tables', '-fno-unwind-tables', '-fvisibility=hidden',
               '-fvisibility=default', '-Wl,--build-id=none', '-lm', '-pthread'}
    require(isinstance(flags, list) and all(isinstance(x, str) and (x in allowed or re.fullmatch(r'-std=(?:gnu|c)(?:89|90|99|11|17|23)|-std=(?:gnu|c)\+\+(?:11|14|17|20|23)|-Wl,-soname,[A-Za-z0-9_.+-]+', x)) for x in flags), 'unsupported compiler flag; arbitrary plugins/scripts/objects are forbidden')
    timeout_value(build.get('timeout_seconds'))
    return environment


def run_verifier(stage, config, snapshot, work, binding, scope, symbols):
    require(isinstance(config, dict), f'{stage} verifier missing')
    path = Path(config.get('path', ''))
    require(path.is_absolute(), f'{stage} checker path must be absolute')
    checker = regular_bytes(path)
    require(digest(checker) == config.get('sha256'), f'{stage} checker hash mismatch')
    require(text_list(config.get('obligations')), f'{stage} obligations required')
    if stage == 'proof':
        require(config.get('method') in ('formal', 'exhaustive'), 'proof method must be formal or exhaustive; sampling is not proof')
    checker_file = snapshot / (stage + '-static-checker')
    checker_file.write_bytes(checker)
    checker_info = elf_info(checker_file)
    require(not checker_info['needed'] and not checker_info['interpreter'], f'{stage} checker must be a self-contained static ELF executable')
    certificate = None
    if stage == 'proof':
        require(Path(config.get('certificate', '')).is_absolute(), 'proof certificate path must be absolute')
        certificate = regular_bytes(config.get('certificate', ''))
        require(hash_string(config.get('certificate_sha256')) and digest(certificate) == config['certificate_sha256'], 'proof certificate hash mismatch')
        require(isinstance(config.get('model'), str) and config['model'].strip(), 'proof model required')
    obligations = sorted(set(REQUIRED_OBLIGATIONS[stage] + config['obligations']))
    request = {'schema_version': 1, 'nonce': secrets.token_hex(32), 'stage': stage, 'binding': binding, 'scope': scope,
               'obligations': obligations, 'symbols': symbols,
               'original': '/inputs/original', 'candidate': '/inputs/candidate'}
    if certificate is not None:
        request.update(certificate='/certificate', certificate_sha256=digest(certificate), model=config['model'], method=config['method'])
    request_bytes = canonical(request)
    request_hash = digest(request_bytes)
    stage_inputs = snapshot / stage
    stage_inputs.mkdir()
    (stage_inputs / 'checker').write_bytes(checker)
    (stage_inputs / 'checker').chmod(0o500)
    (stage_inputs / 'request.json').write_bytes(request_bytes)
    stage_work = work / stage
    stage_work.mkdir()
    mounts = [(snapshot / 'artifacts', '/inputs'), (stage_inputs / 'checker', '/checker'), (stage_inputs / 'request.json', '/request.json')]
    if certificate is not None:
        (stage_inputs / 'certificate').write_bytes(certificate)
        mounts.append((stage_inputs / 'certificate', '/certificate'))
    stdout = sandbox(['/checker', '/request.json'], stage_work, mounts, timeout_value(config.get('timeout_seconds')), runtime=False)
    result = load_json(stdout)
    require(isinstance(result, dict) and type(result.get('schema_version')) is int and result['schema_version'] == 1, f'{stage} invalid result schema')
    allowed_fields = {'schema_version', 'stage', 'request_sha256', 'verdict', 'unknowns', 'obligations', 'covered_exports', 'assumptions', 'summary'}
    if stage == 'proof':
        allowed_fields |= {'method', 'model', 'checked_certificate_sha256'}
    require(set(result) <= allowed_fields, f'{stage} unknown result fields')
    require(result.get('request_sha256') == request_hash and result.get('stage') == stage, f'{stage} stale or unbound result')
    if result.get('verdict') == 'FAIL':
        raise Rejected(f'{stage} verifier found a counterexample or contract violation: {result.get("summary", "")}')
    require(result.get('verdict') == 'PASS', f'{stage} not proven')
    require(result.get('unknowns') == [], f'{stage} has unresolved obligations')
    require(result.get('assumptions') == scope['assumptions'], f'{stage} assumptions mismatch')
    require(result.get('covered_exports') == sorted(x['name'] for x in symbols), f'{stage} incomplete exported symbol coverage')
    require(isinstance(result.get('obligations'), list) and sorted(result['obligations']) == obligations, f'{stage} incomplete obligation coverage')
    require(isinstance(result.get('summary'), str) and result['summary'].strip(), f'{stage} evidence summary required')
    if stage == 'proof':
        require(result.get('method') == config['method'], 'proof method mismatch')
        require(result.get('checked_certificate_sha256') == digest(certificate), 'certificate not checked')
        require(result.get('model') == config['model'], 'proof model mismatch')
    return {'status': 'PASS', 'checker_sha256': digest(checker), 'request_sha256': request_hash,
            'response_sha256': digest(stdout), 'response': result}


def evaluate(args, report):
    original = Path(args.original).absolute()
    tree = Path(args.tree).resolve(strict=True)
    require(tree.is_dir(), 'reconstruction tree is not a directory')
    require(args.candidate is not None, '--candidate is required; build output is never guessed')
    candidate = inside(tree, args.candidate)
    report['artifacts'] = {'original': str(original), 'candidate': str(candidate),
                           'original_sha256': file_hash(original), 'candidate_sha256': file_hash(candidate)}
    manifest = source_manifest(tree)
    report['sources'] = {'sha256': digest(canonical(manifest)), 'files': manifest}
    with tempfile.TemporaryDirectory(prefix='decompile-accept-') as temporary:
        root = Path(temporary)
        snapshots = root / 'snapshots'; snapshots.mkdir()
        artifacts = snapshots / 'artifacts'; artifacts.mkdir()
        for name, path in (('original', original), ('candidate', candidate)):
            (artifacts / name).write_bytes(regular_bytes(path))
            require(file_hash(artifacts / name) == report['artifacts'][name + '_sha256'], 'artifact changed while snapshotting')
        original_info = elf_info(artifacts / 'original')
        candidate_info = elf_info(artifacts / 'candidate')
        report['elf'] = {'original': original_info, 'candidate': candidate_info}
        identical = (report['artifacts']['original_sha256'] == report['artifacts']['candidate_sha256']
                     and regular_bytes(artifacts / 'original') == regular_bytes(artifacts / 'candidate'))
        if identical:
            report['correctness'] = {'status': 'PROVED_IDENTICAL', 'method': 'full-byte-comparison',
                                     'scope': 'same complete ELF bytes; same loading/execution environment assumed'}
        if not args.policy or not args.policy_sha256:
            raise Unknown('approval requires an independently pinned --policy and --policy-sha256')
        policy_path = Path(args.policy).absolute()
        require(not policy_path.resolve().is_relative_to(tree), 'policy must be outside reconstruction tree')
        policy_bytes = regular_bytes(policy_path)
        require(hash_string(args.policy_sha256) and digest(policy_bytes) == args.policy_sha256, 'policy digest mismatch')
        policy = load_json(policy_bytes)
        report['policy_sha256'] = digest(policy_bytes)
        environment = check_policy(policy, report, tree)
        report['environment'] = environment
        report['scope'] = policy['scope']
        require(original_info['header']['Type'].startswith('DYN') and not original_info['pie'], 'replacement approval supports shared libraries only, not objects/archives/executables')
        if original_info['header'] != candidate_info['header']:
            raise Rejected('ELF class/architecture/ABI header differs')
        # Function code sizes may legitimately differ. Data/TLS sizes, visibility and versions may not.
        if original_info['exports'] != candidate_info['exports']:
            raise Rejected('dynamic exported symbol contract differs (names/versions/types/bindings/visibility/data sizes)')
        for key in ('needed', 'soname', 'search_path', 'pie'):
            if original_info[key] != candidate_info[key]:
                raise Rejected(f'loader contract differs: {key}')
        build_dir = root / 'build'; build_dir.mkdir()
        for name in SOURCE_ROOTS:
            source = tree / name
            if source.is_dir():
                shutil.copytree(source, build_dir / name, symlinks=True)
            else:
                shutil.copy2(source, build_dir / name)
        require(source_manifest(build_dir) == manifest, 'source changed while snapshotting')
        build_output = inside(build_dir, args.candidate)
        require(not build_output.exists(), 'candidate must not be included among source inputs')
        build_output.parent.mkdir(parents=True, exist_ok=True)
        build_config = policy['build']
        build_argv = [build_config['compiler'], '-shared', '-fPIC', '-Iinclude', *build_config['sources'], *build_config.get('flags', []), '-o', args.candidate]
        build_log = sandbox(build_argv, build_dir, timeout=build_config['timeout_seconds'])
        require(file_hash(build_output) == report['artifacts']['candidate_sha256'] and regular_bytes(build_output) == regular_bytes(artifacts / 'candidate'), 'clean sandbox build does not reproduce the exact candidate')
        report['build'] = {'status': 'PASS', 'argv': build_argv, 'stdout_sha256': digest(build_log),
                           'candidate_sha256': file_hash(build_output)}
        report['source_reconstruction'] = {'status': 'BUILT_EXACT_CANDIDATE', 'scope': 'all declared translation units built with pinned compiler and restricted flags; no claim about other builds'}
        binding = {'original_sha256': report['artifacts']['original_sha256'],
                   'candidate_sha256': report['artifacts']['candidate_sha256'],
                   'source_sha256': report['sources']['sha256'], 'policy_sha256': report['policy_sha256'],
                   'environment_sha256': digest(canonical(environment)), 'tools_sha256': digest(canonical(report['tools']))}
        if identical:
            report['abi'] = {'status': 'PASS', 'method': 'byte-identity'}
            report['integration'] = {'status': 'PASS', 'method': 'byte-identity-under-pinned-cold-start-context',
                                      'note': 'No new runtime behavior tested; existing behavior is preserved, including existing bugs.'}
        else:
            require(policy['scope'].get('profile') == 'elf-observational-equivalence-v1', 'nonidentical proof requires full elf-observational-equivalence-v1 profile')
            require(set(REQUIRED_OBSERVATIONS).issubset(policy['scope']['observations']), 'full observation profile cannot be narrowed')
            require(text_list(policy['scope'].get('consumers')), 'complete declared consumer inventory required')
            checkers = policy.get('verifiers', {})
            work = root / 'verifiers'; work.mkdir()
            for stage in ('proof', 'abi', 'integration'):
                config = checkers.get(stage)
                if isinstance(config, dict):
                    require(not Path(config.get('path', '')).resolve().is_relative_to(tree), 'trusted checker must be outside reconstruction')
                result = run_verifier(stage, config, snapshots, work, binding, policy['scope'], original_info['exports'])
                report[stage] = result
                if stage == 'proof':
                    report['correctness'] = {'status': 'PROVED_CONTRACT', 'method': config['method'], 'scope': policy['scope'],
                                             'trust': 'independently approved checker; completeness of its model is a policy-owner responsibility'}
        require(measured_tools() == report['tools'], 'verification tools changed during run')
        require(file_hash(Path(policy['build']['compiler']).resolve(strict=True)) == policy['build']['compiler_sha256'], 'compiler changed during run')
        require(environment_state(policy['environment']) == environment, 'environment changed during verification')
        require(source_manifest(tree) == manifest, 'source inputs changed during verification')
        for name, path in (('original', original), ('candidate', candidate)):
            require(file_hash(path) == binding[name + '_sha256'], 'artifact changed during verification')
        require(file_hash(policy_path) == report['policy_sha256'], 'policy changed during verification')
        require(file_hash(policy['deployment']['target']) == binding['original_sha256'], 'deployment target changed during verification')
        report['replacement'] = {'approved': True, 'status': 'APPROVED', 'strategy': 'cold-start',
                                 'target': policy['deployment']['target'], 'binding': binding,
                                 'scope': policy['scope'], 'rollback_sha256': binding['original_sha256'],
                                 'conditions': ['Re-run verifier on target host immediately before replacement.',
                                                'Install only the exact candidate digest; no hot swapping.',
                                                'This JSON is an audit receipt, not a signed deployment capability.']}


def measured_tools():
    paths = [*TOOLS.values(), str(Path(__file__).resolve()), str(Path(sys.executable).resolve())]
    return {path: file_hash(Path(path).resolve(strict=True)) for path in sorted(paths)}


def output_conflicts(args):
    output = Path(args.json_path).absolute()
    tree = Path(args.tree).resolve()
    protected = [Path(args.original), Path(__file__), Path(sys.executable), *map(Path, TOOLS.values())]
    if output.is_symlink() or output.resolve().is_relative_to(tree):
        return True
    if args.policy:
        protected.append(Path(args.policy))
        try:
            policy = load_json(regular_bytes(args.policy))
            if isinstance(policy, dict):
                protected += [Path(policy.get('deployment', {}).get('target', '')), Path(policy.get('build', {}).get('compiler', ''))]
                protected += [Path(x) for x in policy.get('environment', {}).get('files', {})]
                protected += [Path(x) for x in policy.get('tools', {})]
                for checker in policy.get('verifiers', {}).values():
                    protected += [Path(checker.get('path', '')), Path(checker.get('certificate', ''))]
        except Exception:
            # A malformed policy can never approve; protect its own pathname regardless.
            pass
    for path in protected:
        if output.resolve() == path.resolve():
            return True
        if output.exists() and path.exists() and os.path.samefile(output, path):
            return True
    return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original')
    parser.add_argument('tree')
    parser.add_argument('--candidate', help='explicit relative path to already built ELF in TREE')
    parser.add_argument('--policy')
    parser.add_argument('--policy-sha256')
    parser.add_argument('--json', required=True, dest='json_path')
    parser.add_argument('--workdir', help='accepted for migration; never reuse cached evidence')
    parser.add_argument('--v6', action='store_true', help='retired; never used for acceptance')
    args = parser.parse_args(argv)
    report = {'schema_version': SCHEMA, 'created_unix': int(time.time()),
              'correctness': {'status': 'UNKNOWN'}, 'source_reconstruction': {'status': 'UNKNOWN'}, 'replacement': {'approved': False, 'status': 'UNKNOWN'},
              'limitations': ['No general equivalence solver is bundled.',
                              'Scope and trusted verifier correctness are not inferred by this orchestrator.',
                              'Finite tests, source markers and similarity scores cannot authorize replacement.']}
    code = 2
    try:
        # Refuse reports that can overwrite inputs, including a policy or deployment target.
        output = Path(args.json_path).absolute()
        tree = Path(args.tree).resolve()
        require(not output.resolve().is_relative_to(tree), '--json output must be outside reconstruction tree')
        require(output.resolve() != Path(args.original).resolve(), 'report would overwrite original')
        if args.policy:
            require(output.resolve() != Path(args.policy).resolve(), 'report would overwrite policy')
        require(not output_conflicts(args), 'report path conflicts with an input or policy-referenced file')
        report['tools'] = measured_tools()
        evaluate(args, report)
        code = 0
    except Rejected as exc:
        report['replacement'] = {'approved': False, 'status': 'REJECTED'}
        report['reason'] = str(exc)
        code = 1
    except (Unknown, OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        report['reason'] = str(exc)
    except Exception as exc:
        report['reason'] = f'internal verifier error: {type(exc).__name__}: {exc}'
    # Do not overwrite input paths even while reporting an error.
    output = Path(args.json_path).absolute()
    unsafe = output_conflicts(args)
    if unsafe:
        report['replacement'] = {'approved': False, 'status': 'UNKNOWN'}
        report['reason'] = 'report path conflicts with protected input'
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 2
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile('w', dir=output.parent, prefix='.acceptance-', delete=False) as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            temp_name = stream.name
        os.replace(temp_name, output)
    except OSError as exc:
        print(f'cannot write report: {exc}', file=sys.stderr)
        return 2
    print(f"correctness={report['correctness']['status']} replacement={report['replacement']['status']}")
    if 'reason' in report:
        print(report['reason'])
    return code


if __name__ == '__main__':
    sys.exit(main())

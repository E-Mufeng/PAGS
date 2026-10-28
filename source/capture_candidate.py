"""PAGS-only Stop binding + upstream writer + Git; claims stay untrusted.

Not a new memory/search engine or malicious-local-process safety boundary.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import inspect
from itertools import islice
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

from filelock import WindowsFileLock
from jsonschema import validate, ValidationError
from pags_gate import project_identity
from history_projection import TECHNICAL_SIGNAL, SUMMARY_CHARS, _redact

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = {'type': 'object', 'additionalProperties': False,
          'required': ['summary', 'conditions', 'evidence'], 'properties': {
              'summary': {'type': 'string', 'minLength': 8, 'maxLength': 1200},
              'conditions': {'type': 'string', 'minLength': 3, 'maxLength': 600},
              'evidence': {'type': 'array', 'minItems': 1, 'maxItems': 5,
                           'items': {'type': 'string', 'minLength': 1, 'maxLength': 256}}}}


def native_path(value):
    """Compare native Windows extended drive paths without widening scope."""
    resolved = Path(value).resolve()
    text = str(resolved)
    if os.name == 'nt' and text.startswith('\\\\?\\'):
        text = text[4:]
        if not re.match(r'^[A-Za-z]:\\', text):
            raise ValueError('unsupported native path namespace')
        resolved = Path(text)
    return resolved


def git(repo, *args, keep_whitespace=False):
    result = subprocess.run(['git', '-c', 'user.name=PAGS capture', '-c', 'user.email=pags@localhost',
                             '-C', str(repo), *args], capture_output=True, timeout=20,
                            env=dict(os.environ, GIT_CONFIG_GLOBAL='NUL', GIT_CONFIG_NOSYSTEM='1'))
    if result.returncode and not (result.returncode == 1 and args[0] == 'grep'):
        raise ValueError('candidate Git operation failed; inspect unpublished/unversioned input')
    text = result.stdout.decode('utf-8').replace('\r\n', '\n')
    return text if keep_whitespace else text.strip()


def require_committed(repo, directory, names):
    for name in names:
        file = directory / name
        if not file.is_file():
            raise ValueError('candidate file missing; explicit recovery required')
        committed = git(repo, 'show', 'HEAD:' + file.relative_to(repo).as_posix(), keep_whitespace=True)
        if committed != file.read_text(encoding='utf-8'):
            raise ValueError('candidate is not the committed version; explicit recovery required')


def content_hash(project, proposal):
    return hashlib.sha256(json.dumps([project, proposal], sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def canonical_metadata(repo, directory):
    require_committed(repo, directory, ('PAGS.json', 'MEMORY.md'))
    meta = json.loads((directory / 'PAGS.json').read_text(encoding='utf-8'))
    try:
        for key in ('source_session_id', 'source_turn_id'):
            uuid.UUID(meta[key])
        project = meta['source_project_id']
        if not isinstance(project, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', project):
            raise ValueError('invalid canonical source project')
        identity = hashlib.sha256(json.dumps([project, meta['source_session_id'], meta['source_turn_id']], separators=(',', ':')).encode()).hexdigest()
        if meta.get('id') != directory.name or identity != directory.name or meta.get('status') != 'candidate' or meta.get('trust') != 'untrusted':
            raise ValueError('canonical native identity/trust mismatch')
        validate(meta['proposal'], SCHEMA)
        if 'content_hash' in meta and meta['content_hash'] != content_hash(project, meta['proposal']):
            raise ValueError('canonical fingerprint does not match its proposal')
    except (KeyError, TypeError, ValidationError) as error:
        raise ValueError('canonical source metadata invalid') from error
    return meta


def sanitized_fingerprint(metadata):
    result = subprocess.run([os.environ.get('PAGS_NODE', 'node'), str(ROOT / 'source/upstream_candidate_write.mjs')],
        input=json.dumps({'directory': str(ROOT / 'runtime'), 'metadata': metadata, 'redact_only': True}).encode(),
        capture_output=True, timeout=20)
    if result.returncode:
        raise ValueError('pinned upstream redaction failed')
    sanitized = json.loads(result.stdout)
    if sanitized.get('qmd') != 'off':
        raise ValueError('unexpected redaction mode')
    return content_hash(sanitized['metadata']['source_project_id'], sanitized['metadata']['proposal'])


def equivalent_candidate(repo, metadata):
    """Git's fixed-string matching locates exact fingerprints, not a search engine."""
    digest = content_hash(metadata['source_project_id'], metadata['proposal'])
    glob = ':(glob)candidates/*/PAGS.json'
    indexed = git(repo, 'grep', '-l', '-F', '-e', '"content_hash": "' + digest + '"', 'HEAD', '--', glob).splitlines()
    legacy = git(repo, 'grep', '-L', '-F', '-e', '"content_hash"', 'HEAD', '--', glob).splitlines()
    if len(legacy) > 16 or len(indexed) > 16:
        raise ValueError('candidate review budget exceeded; explicit maintenance required')
    for row in sorted(set(indexed + legacy)):
        path = row.removeprefix('HEAD:')
        if not re.fullmatch(r'candidates/[0-9a-f]{64}/PAGS\.json', path):
            raise ValueError('unexpected canonical candidate path')
        previous = json.loads(git(repo, 'show', 'HEAD:' + path))
        if previous.get('source_project_id') != metadata['source_project_id']:
            continue
        if previous.get('status') != 'candidate' or previous.get('trust') != 'untrusted':
            raise ValueError('unexpected canonical candidate trust state')
        if content_hash(previous['source_project_id'], previous['proposal']) == digest:
            directory = repo / Path(path).parent
            canonical_metadata(repo, directory)
            return directory.name, digest
    return None, digest


def verify_turn_message(transcript, event, cwd):
    """Bounded exact-rollout tail; reject when the current context is not present."""
    limit = 2 * 1024 * 1024
    with transcript.open('rb') as stream:
        size = stream.seek(0, os.SEEK_END)
        offset = max(0, size - limit)
        stream.seek(offset)
        if offset:
            stream.readline()  # Drop only the partial first line in the bounded tail.
        raw = stream.read(limit)
    context, final = None, None
    calls, completed = set(), set()
    result_evidence = {}
    for line in raw.decode('utf-8').splitlines():
        row = json.loads(line)
        payload = row.get('payload', {})
        if row.get('type') == 'turn_context':
            context, final = payload, None
            calls, completed = set(), set()
            result_evidence = {}
        elif row.get('type') == 'response_item' and payload.get('type') in ('function_call', 'custom_tool_call'):
            # Pair only observed calls/results inside this exact native turn.
            call_id = payload.get('call_id')
            if isinstance(call_id, str) and call_id:
                calls.add(call_id)
        elif row.get('type') == 'response_item' and payload.get('type') in ('function_call_output', 'custom_tool_call_output'):
            call_id = payload.get('call_id')
            if isinstance(call_id, str) and call_id in calls:
                completed.add(call_id)
                # Bind observations without copying output, secrets or claimed outcomes.
                result_evidence.pop(call_id, None)  # Reinsert at the last-output position.
                result_evidence[call_id] = {
                    'call_id_sha256': hashlib.sha256(call_id.encode('utf-8')).hexdigest(),
                    'json_line_sha256': hashlib.sha256(line.encode('utf-8')).hexdigest()}
        elif row.get('type') == 'response_item' and payload.get('role') == 'assistant' and payload.get('phase') == 'final_answer':
            final = ''.join(item['text'] for item in payload.get('content', []) if item.get('type') == 'output_text')
    if not context or context.get('turn_id') != event['turn_id'] or not isinstance(context.get('cwd'), str) or not context['cwd'].strip() or native_path(context['cwd']) != cwd or final != event['last_assistant_message']:
        raise ValueError('exact current turn/final message not verified in bounded rollout tail')
    return {'paired_tool_results': len(completed),
            'bound_tool_results': list(result_evidence.values())[-8:],
            'omitted_tool_results': max(0, len(result_evidence) - 8),
            'final_sha256': hashlib.sha256(final.encode('utf-8')).hexdigest()}


def automatic_proposal(message, observation):
    """Reuse historical rule triage/redaction for one current-turn candidate.

    Extracts source claims, not verified lessons; never infers success or cause.
    """
    if not observation['paired_tool_results'] or not TECHNICAL_SIGNAL.search(message):
        return None
    # Reuse the pinned upstream redactor BEFORE truncating a possible secret.
    safe = _redact(message)
    return {'summary': '[Automatic unverified excerpt] ' + safe[:SUMMARY_CHARS],
            'conditions': 'Current source task only. Tool results were observed, not judged successful. '
                          'Requires value, privacy, factual and applicability review; response end is not project completion.',
            'evidence': ['Redacted final SHA256: ' + hashlib.sha256(safe.encode('utf-8')).hexdigest(),
                         'Exact native session/turn and original final SHA256 are bound in PAGS metadata.']}


def prefetch_observations(root, event, project):
    """Link existing same-turn receipts, not inferred relevance or root causes."""
    source = json.dumps([event['session_id'], event['turn_id']], separators=(',', ':'))
    prefix = hashlib.sha256(source.encode('utf-8')).hexdigest()
    paths = list(islice((root / 'evidence/retrieval-receipts').glob(prefix + '-*.json'), 9))
    if len(paths) > 8:
        raise ValueError('same-turn prefetch evidence budget exceeded')
    result = []
    for path in sorted(paths):
        with path.open('rb') as stream:
            raw = stream.read(16385)
        if len(raw) > 16384:
            raise ValueError('prefetch receipt size exceeds evidence budget')
        row = json.loads(raw)
        if any(row.get(key) != event[key] for key in ('session_id', 'turn_id')):
            raise ValueError('prefetch receipt native source mismatch')
        if row.get('status') not in ('hit', 'miss', 'error', 'skipped'):
            raise ValueError('unknown prefetch observation status')
        if (row['status'] in ('hit', 'miss') or 'project_id' in row) and row.get('project_id') != project:
            raise ValueError('prefetch receipt workspace mismatch')
        ids = row.get('match_ids', [])
        if not isinstance(ids, list) or len(ids) > 2 or any(
                not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value)
                for value in ids):
            raise ValueError('invalid observed experience IDs')
        revision, count = row.get('revision'), row.get('query_count')
        if revision is not None and (not isinstance(revision, str) or not re.fullmatch(r'[0-9a-f]{40}', revision)):
            raise ValueError('invalid observed approved revision')
        if count is not None and (type(count) is not int or not 0 <= count <= 2):
            raise ValueError('invalid observed prefetch query count')
        if row['status'] in ('hit', 'miss') and (revision is None or count not in (1, 2)):
            raise ValueError('incomplete retrieval observation')
        if (row['status'] == 'hit') != bool(ids):
            raise ValueError('prefetch status and match IDs disagree')
        result.append({'receipt': path.relative_to(root).as_posix(),
                       'receipt_sha256': hashlib.sha256(raw).hexdigest(),
                       'status': row['status'], 'revision': revision,
                       'query_count': count, 'match_ids': ids})
    # Missing includes intentional greeting/continuation skips and old unkeyed receipts;
    # it is not evidence that retrieval missed, failed or was never attempted.
    return {'status': 'recorded' if result else 'not_recorded', 'attempts': result,
            'interpretation': 'retrieval observation only; exposure, use, causation and truth require review'}


def capture(event, root=ROOT, home=None, *, allow_unregistered=False):
    message = event.get('last_assistant_message')
    if not isinstance(message, str):
        raise ValueError('Stop message absent; capture capability not verified')
    begin, end = 'PAGS_CANDIDATE_BEGIN', 'PAGS_CANDIDATE_END'
    if event.get('hook_event_name') != 'Stop' or event.get('stop_hook_active') is not False:
        raise ValueError('not the expected terminal Stop event')
    structured = begin in message or end in message
    if len(message) > 65536 or (structured and (message.count(begin) != 1 or message.count(end) != 1)):
        raise ValueError('ambiguous or oversized proposal')
    try:
        # A malformed explicit proposal is an error, never silently replaced.
        if structured:
            proposal = json.loads(message.split(begin, 1)[1].split(end, 1)[0].strip())
            validate(proposal, SCHEMA)
        for key in ('session_id', 'turn_id'):
            uuid.UUID(event[key])
        if not isinstance(event['cwd'], str) or not event['cwd'].strip():
            raise ValueError('explicit native event cwd required')
        cwd = native_path(event['cwd'])
        project_id = project_identity(root / 'PROJECTS.json', cwd,
                                      allow_unregistered=allow_unregistered)
        home = native_path(home if home is not None else os.environ['CODEX_HOME'])
        transcript_value = event['transcript_path']
        # Official Stop input permits null; never invent another session's source.
        if transcript_value is None:
            return {'skipped': 'native_transcript_unavailable', 'candidate_saved': False,
                    'source_verified': False}
        if not isinstance(transcript_value, str) or not transcript_value.strip():
            raise ValueError('explicit native transcript path required')
        transcript = native_path(transcript_value)
        if not transcript.is_relative_to(home):
            raise ValueError('transcript outside isolated home')
        with transcript.open(encoding='utf-8') as stream:
            first = stream.readline(65537)
        if len(first) > 65536:
            raise ValueError('source metadata too large')
        source = json.loads(first)
        if source.get('type') != 'session_meta' or source['payload'].get('id') != event['session_id'] or not isinstance(source['payload'].get('cwd'), str) or not source['payload']['cwd'].strip() or native_path(source['payload']['cwd']) != cwd:
            raise ValueError('source session/cwd mismatch')
        observation = verify_turn_message(transcript, event, cwd)
        if not structured:
            proposal = automatic_proposal(message, observation)
            if proposal is None:
                return {'skipped': 'no_rule_selected_execution_excerpt', 'candidate_saved': False,
                        'source_verified': True}
            validate(proposal, SCHEMA)
    except (KeyError, TypeError, OSError, ValidationError) as error:
        raise ValueError('invalid proposal or exact native source binding') from error
    identity = hashlib.sha256(json.dumps([project_id, event['session_id'], event['turn_id']], separators=(',', ':')).encode()).hexdigest()
    claim_hash = hashlib.sha256(json.dumps(proposal, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
    repo = root / 'knowledge'
    if not repo.is_dir() or root.resolve() != root or not root.is_relative_to(ROOT):
        raise ValueError('registered PAGS authority required')
    metadata = {'id': identity, 'status': 'candidate', 'trust': 'untrusted',
                'source_project_id': project_id, 'source_session_id': event['session_id'],
                'source_turn_id': event['turn_id'], 'source_transcript_path': str(transcript),
                'source_scope_basis': 'workspace_path_not_project_proof' if project_id.startswith('local-') else 'registered_path',
                'source_workspace_path': str(cwd),
                'claim_hash': claim_hash, 'proposal': proposal, 'requires_independent_evidence_review': True,
                'capture_mode': 'structured_proposal' if structured else 'automatic_excerpt',
                'source_final_sha256': observation['final_sha256'],
                'observed_tool_results': observation['paired_tool_results'],
                'source_tool_observations': observation['bound_tool_results'],
                'source_tool_observations_omitted': observation['omitted_tool_results'],
                'source_tool_observation_basis': 'last observed output per paired call; latest eight; UTF-8 JSON lines without line endings; hashes only; outcomes not assessed',
                'source_prefetch_observations': prefetch_observations(root, event, project_id)}
    # 3.13.1 is the isolated runtime; newer user-site versions expose an extra
    # constructor switch. Both use the explicit native backend, never SoftFileLock.
    lock_options = {'fallback_to_soft': False} if 'fallback_to_soft' in inspect.signature(WindowsFileLock).parameters else {}
    with WindowsFileLock(repo / '.git' / 'pags-capture.lock', timeout=10, **lock_options):
        if git(repo, 'symbolic-ref', 'HEAD').casefold() == 'refs/heads/approved':
            raise ValueError('candidate capture requires a working branch separate from approved')
        approved = git(repo, 'rev-parse', 'refs/heads/approved')
        destination = repo / 'candidates' / identity
        if destination.exists():
            source_only = (destination / 'SOURCE.json').is_file()
            names = ('SOURCE.json',) if source_only else ('PAGS.json', 'MEMORY.md')
            require_committed(repo, destination, names)
            previous = json.loads((destination / names[0]).read_text(encoding='utf-8'))
            if any(previous.get(key) != metadata[key] for key in (
                    'id', 'source_project_id', 'source_session_id', 'source_turn_id', 'status', 'trust')):
                raise ValueError('stored candidate native identity or trust mismatch')
            if previous['claim_hash'] != claim_hash:
                raise ValueError('conflicting proposal for the same source turn')
            if source_only:
                canonical = previous.get('duplicate_of')
                if not isinstance(canonical, str) or not re.fullmatch(r'[0-9a-f]{64}', canonical):
                    raise ValueError('invalid canonical candidate reference')
                directory = repo / 'candidates' / canonical
                original = canonical_metadata(repo, directory)
                current_fingerprint = sanitized_fingerprint(metadata)
                if original['source_project_id'] != project_id or previous.get('content_hash') != current_fingerprint or current_fingerprint != content_hash(original['source_project_id'], original['proposal']):
                    raise ValueError('canonical source scope/content mismatch')
                return {'id': identity, 'canonical_id': canonical, 'duplicate': True}
            original = canonical_metadata(repo, destination)
            if content_hash(original['source_project_id'], original['proposal']) != sanitized_fingerprint(metadata):
                raise ValueError('canonical replay content does not match exact native proposal')
            return {'id': identity, 'duplicate': True}
        with tempfile.TemporaryDirectory(prefix='pags-capture-', dir=root / 'runtime') as staging:
            result = subprocess.run([os.environ.get('PAGS_NODE', 'node'), str(ROOT / 'source/upstream_candidate_write.mjs')],
                                    input=json.dumps({'directory': staging, 'metadata': metadata}).encode(),
                                    capture_output=True, timeout=20)
            if result.returncode:
                raise ValueError('pinned upstream candidate writer failed')
            written = json.loads(result.stdout)
            if written.get('qmd') != 'off' or not (Path(staging) / 'MEMORY.md').is_file():
                raise ValueError('writer result incomplete')
            canonical, digest = equivalent_candidate(repo, written['metadata'])
            written['metadata']['content_hash'] = digest
            if canonical:
                # Keep the additional exact native source, not another full proposal.
                binding = {k: v for k, v in written['metadata'].items() if k != 'proposal'}
                binding['duplicate_of'] = canonical
                (Path(staging) / 'MEMORY.md').unlink()
                name, stored = 'SOURCE.json', binding
            else:
                name, stored = 'PAGS.json', written['metadata']
            (Path(staging) / name).write_text(json.dumps(stored, ensure_ascii=False, indent=2), encoding='utf-8')
            destination.parent.mkdir(exist_ok=True)
            os.rename(staging, destination)
        relative = destination.relative_to(repo).as_posix()
        git(repo, 'add', '--', relative)
        git(repo, 'commit', '--only', '-m', 'Untrusted PAGS candidate from exact native turn', '--', relative)
        if git(repo, 'rev-parse', 'refs/heads/approved') != approved:
            raise ValueError('approved ref unexpectedly changed')
        return {'id': identity, 'canonical_id': canonical or identity, 'duplicate': bool(canonical), 'redacted': written['redacted']}


def write_capture_receipt(event, result=None, error=None):
    """Operational metadata only; never a candidate or trusted experience."""
    event = event if isinstance(event, dict) else {}
    ids = {}
    for key in ('session_id', 'turn_id'):
        try:
            ids[key] = str(uuid.UUID(event[key]))
        except (KeyError, TypeError, ValueError, AttributeError):
            ids[key] = None
    # Keep code locations, not exception text: validators can embed secrets in
    # their messages. Preserve chained failure locations instead of only a type.
    failures, current = [], error
    while current is not None and len(failures) < 4:
        frames, trace = [], current.__traceback__
        while trace is not None:
            filename = Path(trace.tb_frame.f_code.co_filename)
            if filename.parent == ROOT / 'source':
                frames.append({'file': filename.name, 'function': trace.tb_frame.f_code.co_name,
                               'line': trace.tb_lineno})
            trace = trace.tb_next
        failures.append({'type': type(current).__name__, 'locations': frames})
        current = current.__cause__
    receipt = {'at': datetime.now(timezone.utc).isoformat(), **ids,
               'hook_event_name': event.get('hook_event_name') if event.get('hook_event_name') == 'Stop' else None,
               'status': 'error' if error else ('skipped' if 'skipped' in result else 'captured'),
               'result': result, 'error_type': type(error).__name__ if error else None,
               'failure_chain': failures,
               'collector_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               'stop_hook_active': event.get('stop_hook_active') if isinstance(event.get('stop_hook_active'), bool) else None,
               # Exact native path representation is needed to diagnose a
               # containment rejection; never include prompts or tool output.
               'binding_input': {key: value for key in ('cwd', 'transcript_path')
                                 if isinstance((value := event.get(key)), str) and len(value) <= 1024},
               'configured_home': os.environ.get('CODEX_HOME'),
               'source_verified': bool(result and (result.get('id') or result.get('source_verified'))),
               'model_requests_started': 0}
    directory = ROOT / 'evidence' / 'capture-receipts'
    directory.mkdir(exist_ok=True)
    # Retain each attempt; never overwrite a prior failure with a later success.
    destination = directory / ((ids['session_id'] or 'unknown') + '-' + uuid.uuid4().hex + '.json')
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=directory,
                                     suffix='.tmp', delete=False) as stream:
        temporary = Path(stream.name)
        json.dump(receipt, stream, ensure_ascii=True, indent=2)
    try:
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--auto-project', action='store_true')
    args = parser.parse_args()
    event = None
    try:
        # Native Hook JSON is UTF-8. A redirected Windows text stdin can use
        # the locale code page and corrupt cwd/message before source binding.
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise ValueError('oversized event')
        event = json.loads(raw)
        result = capture(event, allow_unregistered=args.auto_project)
        write_capture_receipt(event, result=result)
        # stdout is the native Hook protocol, not a capture-success receipt.
        print('{}')
    except Exception as error:
        try:
            write_capture_receipt(event, error=error)
        except Exception:
            print('PAGS capture receipt unavailable', file=sys.stderr)
        print('PAGS candidate capture or receipt failed; inspect exact-turn evidence', file=sys.stderr)
        raise SystemExit(1)

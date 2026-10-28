"""PAGS-only bounded Codex JSONL projection; no store, commands or model calls.

Generic parsing/redaction/storage stay with stdlib, pinned upstream and Git.
"""
import hashlib
import json
from pathlib import Path
import os
import re
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
CODEX_HOME = Path(os.environ.get('CODEX_HOME', str(Path.home() / '.codex')))
SOURCE_ROOTS = (CODEX_HOME / 'sessions', CODEX_HOME / 'archived_sessions')
MAX_LINE = 1024 * 1024
SUMMARY_CHARS = 1140
TECHNICAL_SIGNAL = re.compile(r'pytest|npm|\bGit\b|\bAPI\b|test|测试|修复|配置|构建', re.I)


def _uuid(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('historical UUID must be a nonempty string')
    return str(uuid.UUID(value))


def _cursor_checksum(state):
    """Public accidental-corruption check, not authentication or authorization."""
    body = {k: v for k, v in state.items() if k != 'checkpoint_sha256'}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _invalidate(state):
    state['turn'] = None
    state['context'] = None


def _fork_start(meta):
    """Observed native paginated-subagent profile, not an inferred UUID prefix."""
    start = meta.get('subagent_history_start_ordinal')
    if start is None:
        return None
    source = meta.get('source')
    agent = source.get('subagent') if isinstance(source, dict) else None
    spawn = agent.get('thread_spawn') if isinstance(agent, dict) else None
    if (type(start) is not int or start < 1 or not isinstance(spawn, dict)
            or _uuid(meta.get('forked_from_id')) != _uuid(spawn.get('parent_thread_id'))
            or meta.get('parent_thread_id', meta['forked_from_id']) != meta['forked_from_id']):
        raise ValueError('unverified native fork ownership metadata')
    return start


def _verify_ownership(state, stream, meta, sid, header_size):
    start = _fork_start(meta)
    inherited = state.get('inherited_prelude', False)
    marker = state.get('ownership')
    if type(inherited) is not bool:
        raise ValueError('invalid inherited-history flag')
    if start is None:
        if inherited or marker is not None:
            raise ValueError('unexpected fork ownership state')
        return
    if inherited:
        if marker is not None or state.get('turn') is not None or state.get('context') is not None:
            raise ValueError('inherited history cannot own a candidate turn')
        return
    try:
        if not isinstance(marker, dict):
            raise ValueError('fork cursor missing exact native ownership event')
        begin, length = marker['offset'], marker['length']
        if (type(begin) is not int or type(length) is not int or not 0 < length <= MAX_LINE
                or not header_size <= begin < state['offset'] or begin + length > state['offset']
                or type(marker['line_number']) is not int
                or not 2 <= marker['line_number'] <= state['line_number']):
            raise ValueError('invalid fork ownership event range')
        stream.seek(begin - 1)
        if stream.read(1) != b'\n':
            raise ValueError('fork ownership event not at a line boundary')
        line = stream.read(length)
        if not line.endswith(b'\n') or hashlib.sha256(line).hexdigest() != marker['sha256']:
            raise ValueError('fork ownership event hash mismatch')
        event = json.loads(line)
        if (event.get('ordinal') != start or event.get('type') != 'event_msg'
                or event['payload'].get('type') != 'thread_settings_applied'
                or event['payload'].get('thread_id') != sid):
            raise ValueError('fork ownership event identity mismatch')
        context = state.get('context')
        if context is not None and context['offset'] < begin + length:
            raise ValueError('inherited turn context predates child ownership')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('malformed fork ownership marker') from error


def _validate_cursor(state, stream, path, header_size, size, meta, sid):
    if state.get('schema') != 2 or state.get('source_path') != str(path):
        raise ValueError('unbound legacy or different-source historical cursor')
    if state.get('checkpoint_sha256') != _cursor_checksum(state):
        raise ValueError('historical checkpoint checksum mismatch')
    offset = state.get('offset')
    if type(offset) is not int or not header_size <= offset <= size:
        raise ValueError('historical cursor offset outside source')
    if type(state.get('line_number')) is not int or state['line_number'] < 1:
        raise ValueError('invalid historical cursor line number')
    if type(state.get('discarding')) is not bool:
        raise ValueError('invalid historical cursor discard flag')
    stream.seek(offset - 1)
    boundary = stream.read(1) == b'\n'
    if not state['discarding']:
        if (offset != size and not boundary) or state.get('discard_start') is not None:
            raise ValueError('historical cursor not at an event boundary')
    else:
        begin = state.get('discard_start')
        if (type(begin) is not int or not header_size <= begin < offset < size
                or offset - begin <= MAX_LINE or boundary or state.get('turn') is not None
                or state.get('context') is not None):
            raise ValueError('invalid oversized-event cursor')
        stream.seek(begin - 1)
        if stream.read(1) != b'\n' or b'\n' in stream.read(MAX_LINE + 1):
            raise ValueError('oversized-event start mismatch')
    _verify_ownership(state, stream, meta, sid, header_size)
    context = state.get('context')
    if state.get('turn') is None:
        if context is not None:
            raise ValueError('context marker without a turn')
        return
    try:
        turn = _uuid(state['turn'])
        if turn != state['turn'] or not isinstance(context, dict):
            raise ValueError('invalid turn/context')
        begin, length = context['offset'], context['length']
        if (type(begin) is not int or type(length) is not int
                or not header_size <= begin < offset or not 0 < length <= MAX_LINE
                or begin + length > offset or type(context['line_number']) is not int
                or not 2 <= context['line_number'] <= state['line_number']):
            raise ValueError('invalid context marker range')
        stream.seek(begin - 1)
        if stream.read(1) != b'\n':
            raise ValueError('context marker not at an event boundary')
        line = stream.read(length)
        if not line.endswith(b'\n') or hashlib.sha256(line).hexdigest() != context['sha256']:
            raise ValueError('context marker hash mismatch')
        event = json.loads(line)
        if (event['type'] != 'turn_context' or event['payload']['cwd'] != meta['cwd']
                or _uuid(event['payload']['turn_id']) != turn):
            raise ValueError('turn/context source binding mismatch')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('invalid historical context marker') from error


def _redact(text):
    metadata = {'proposal': {'summary': text, 'conditions': 'Historical unverified source',
                             'evidence': ['No execution or approval']}}
    result = subprocess.run([os.environ.get('PAGS_NODE', 'node'), str(ROOT / 'source/upstream_candidate_write.mjs')],
        input=json.dumps({'directory': str(ROOT / 'runtime'), 'metadata': metadata,
                         'redact_only': True}).encode(), capture_output=True, timeout=20)
    if result.returncode:
        raise ValueError('pinned historical redactor failed')
    output = json.loads(result.stdout)
    if output.get('qmd') != 'off':
        raise ValueError('unexpected model/index mode')
    return output['metadata']['proposal']['summary']


def read_segment(item, cursor=None, budget=16 * 1024 * 1024):
    """One explicit manifest source, epoch-bound cursor, at most four excerpts."""
    if type(budget) is not int or not MAX_LINE + 1 <= budget <= 32 * 1024 * 1024:
        raise ValueError('invalid historical byte budget')
    path = Path(item['path']).resolve()
    if not any(path.is_relative_to(root.resolve()) for root in SOURCE_ROOTS):
        raise ValueError('historical source outside original-home roots')
    epoch = [item['observed_bytes'], item['observed_mtime_ns']]
    stat = path.stat()
    if [stat.st_size, stat.st_mtime_ns] != epoch:
        raise ValueError('historical source epoch changed')
    snippets, skipped, finals, inherited_skipped = [], 0, 0, 0
    with path.open('rb') as stream:
        header = stream.readline(1024 * 1024 + 1)
        if len(header) > 1024 * 1024 or hashlib.sha256(header).hexdigest() != item['metadata_sha256']:
            raise ValueError('historical source header mismatch')
        first = json.loads(header)
        meta = first.get('payload', {}) if isinstance(first, dict) else {}
        if not isinstance(meta, dict) or not isinstance(first, dict) or first.get('type') != 'session_meta' or not isinstance(meta.get('cwd'), str) or not meta['cwd'].strip():
            raise ValueError('historical session/cwd missing')
        sid = _uuid(meta.get('id'))
        if sid.casefold() not in path.name.casefold():
            raise ValueError('historical filename/session mismatch')
        fork_start = _fork_start(meta)
        state = dict(cursor) if cursor is not None else {'schema': 2, 'source_path': str(path),
            'epoch': epoch, 'header_sha256': item['metadata_sha256'], 'offset': len(header),
            'line_number': 1, 'turn': None, 'context': None, 'discarding': False, 'discard_start': None,
            'inherited_prelude': fork_start is not None, 'ownership': None}
        if state['epoch'] != epoch or state['header_sha256'] != item['metadata_sha256']:
            raise ValueError('historical cursor belongs to another epoch')
        if cursor is not None:
            _validate_cursor(state, stream, path, len(header), stat.st_size, meta, sid)
        stream.seek(state['offset'])
        start = state['offset']
        digest = hashlib.sha256()
        while stream.tell() < stat.st_size:
            remaining = budget - (stream.tell() - start)
            wanted = min(MAX_LINE + 1, stat.st_size - stream.tell())
            if state['discarding']:
                wanted = min(wanted, remaining)
            elif remaining < wanted:
                break
            if wanted <= 0:
                break
            offset = stream.tell()
            line = stream.readline(wanted)
            if not line:
                raise ValueError('historical source ended before observed boundary')
            digest.update(line)
            complete = line.endswith(b'\n') or stream.tell() == stat.st_size
            if state['discarding'] or len(line) > MAX_LINE:
                if not state['discarding']:
                    skipped += 1
                    state['discard_start'] = offset
                _invalidate(state)
                state['discarding'] = not complete
                if complete:
                    state['line_number'] += 1
                    state['discard_start'] = None
                continue
            state['line_number'] += 1
            try:
                event = json.loads(line)
            except (ValueError, UnicodeError):
                skipped += 1
                _invalidate(state)
                continue
            if not isinstance(event, dict) or not isinstance(event.get('payload', {}), dict):
                skipped += 1
                _invalidate(state)
                continue
            payload = event.get('payload', {})
            if state.get('inherited_prelude'):
                ordinal = event.get('ordinal')
                if type(ordinal) is not int:
                    raise ValueError('native fork prelude missing explicit ordinal')
                if ordinal < fork_start:
                    inherited_skipped += 1
                    _invalidate(state)
                    continue
                if (ordinal != fork_start or event.get('type') != 'event_msg'
                        or payload.get('type') != 'thread_settings_applied' or payload.get('thread_id') != sid):
                    raise ValueError('declared native child ownership boundary absent or mismatched')
                state['inherited_prelude'] = False
                state['ownership'] = {'offset': offset, 'length': len(line),
                    'line_number': state['line_number'], 'sha256': hashlib.sha256(line).hexdigest()}
                _invalidate(state)
                continue
            if event.get('type') == 'session_meta':
                raise ValueError('multiple historical session blocks require review')
            if event.get('type') == 'turn_context':
                _invalidate(state)
                try:
                    turn = _uuid(payload.get('turn_id'))
                    if payload.get('cwd') == meta['cwd']:
                        state['turn'] = turn
                        state['context'] = {'offset': offset, 'length': len(line),
                            'line_number': state['line_number'], 'sha256': hashlib.sha256(line).hexdigest()}
                except (KeyError, ValueError, TypeError):
                    pass
            if event.get('type') != 'response_item' or payload.get('role') != 'assistant' or payload.get('phase') != 'final_answer':
                continue
            finals += 1
            content = payload.get('content')
            if (not isinstance(content, list) or any(not isinstance(x, dict)
                    or not isinstance(x.get('type'), str)
                    or (x['type'] == 'output_text' and not isinstance(x.get('text'), str)) for x in content)):
                skipped += 1
                _invalidate(state)
                continue
            if not state['turn'] or len(snippets) == 4:
                continue
            text = ''.join(x['text'] for x in content if x['type'] == 'output_text')
            if not TECHNICAL_SIGNAL.search(text):
                continue
            safe = _redact(text)[:SUMMARY_CHARS]
            snippets.append({'session_id': sid, 'turn_id': state['turn'], 'cwd': meta['cwd'],
                'byte_offset': offset, 'line_number': state['line_number'],
                'event_sha256': hashlib.sha256(line).hexdigest(), 'text': safe,
                'context': dict(state['context']), 'ownership': state.get('ownership'),
                'trust': 'untrusted', 'source_kind': ('historical_subagent'
                    if isinstance(meta.get('source'), dict) and isinstance(meta['source'].get('subagent'), dict)
                    else 'historical_session' if meta.get('source') in ('cli', 'exec', 'vscode')
                    else 'historical_unknown')})
            if len(snippets) == 4:
                break
        state['offset'] = stream.tell()
        if state['offset'] == stat.st_size and state.get('inherited_prelude'):
            raise ValueError('native child ownership boundary never observed')
        state['checkpoint_sha256'] = _cursor_checksum(state)
    after = path.stat()
    if [after.st_size, after.st_mtime_ns] != epoch:
        raise ValueError('historical source changed during segment')
    return {'status': 'complete' if state['offset'] == stat.st_size else 'partial',
        'cursor': state, 'segment_start': start, 'segment_end': state['offset'],
        'segment_sha256': digest.hexdigest(), 'bytes_read': state['offset'] - start,
        'header_verification_bytes': len(header), 'snippets': snippets,
        'skipped_events': skipped, 'final_events': finals,
        'inherited_events_skipped': inherited_skipped,
        'limit': 'At most4 technical excerpts; keyword triage is not value/privacy/claim verification.'}

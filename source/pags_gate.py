"""PAGS-only semantic admission; Git owns storage/versioning, rg owns search.

No write API, database, model call, background service or Windows safety layer.
Review metadata is necessary, not sufficient proof of a true technical claim.
The Coordinator must verify real evidence before advancing the approved ref.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import time
from datetime import datetime, timezone

import yaml

ROOT = Path(__file__).resolve().parents[1]
RG = Path(os.environ.get('PAGS_RG', 'rg'))
IDENTITY = re.compile(r'^[A-Za-z0-9_-]{1,128}$')
REDACTOR = ROOT / 'vendor/myagentmemory/core.js'
REDACTOR_SHA256 = '636d664064ddf08764b72d47d94dba84bad6abf50f982932d0c1d2c7b9a9c348'


class GateError(ValueError):
    pass


def project_identity(registry_path, cwd, *, allow_unregistered=False):
    """Bind to host cwd, not a model-selected project or latest session.

    Global opt-in derives a workspace scope without editing any project/registry.
    A historical path is not a declaration of the current task's project.
    This identity is routing only, never proof of project ownership or sharing.
    """
    actual = os.path.normcase(str(Path(cwd).resolve()))
    registry = json.loads(Path(registry_path).read_text(encoding='utf-8'))
    rows = [p for p in registry['projects']
            if os.path.normcase(str(Path(p['path']).resolve())) == actual]
    if len(rows) > 1:
        raise GateError('ambiguous exact project binding')
    if rows and not (allow_unregistered and rows[0].get('kind') == 'historical_metadata_only'):
        identity = rows[0]['project_id']
        if not isinstance(identity, str) or not IDENTITY.fullmatch(identity) or identity.startswith('local-'):
            raise GateError('invalid registered identity')
        return identity
    if not allow_unregistered:
        raise GateError('exact project binding rejected')
    return 'local-' + hashlib.sha256(actual.encode('utf-8')).hexdigest()


def timestamp(value):
    if not isinstance(value, str):
        raise GateError('timestamp must be explicit ISO timezone text')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as error:
        raise GateError('invalid timestamp') from error
    if result.tzinfo is None:
        raise GateError('timestamp has no timezone')
    return result


class Vault:
    def __init__(self, root, *, hard_deadline=None):
        if hard_deadline is not None and (type(hard_deadline) not in (int, float) or not math.isfinite(hard_deadline)):
            raise GateError('invalid caller deadline')
        self.hard_deadline = hard_deadline
        self.root = Path(os.path.abspath(root))
        if not self.root.is_relative_to(ROOT) or self.root.resolve() != self.root:
            raise GateError('vault outside PAGS or indirect path')
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL='NUL', GIT_CONFIG_NOSYSTEM='1')
        self.deadline = self.next_deadline()
        actual = self.git('rev-parse', '--absolute-git-dir').decode().strip()
        if Path(actual).resolve() != self.root / '.git':
            raise GateError('not the registered vault Git root')

    def next_deadline(self):
        normal = time.monotonic() + 20
        return min(normal, self.hard_deadline) if self.hard_deadline is not None else normal

    def git(self, *arguments, stdin=None):
        # MXC permits object reads but rejects chdir outside the native task.
        # Use Git's normal explicit object-directory interface, no permissions change.
        p = self.run(['git', '--no-pager', '--git-dir=' + str(self.root / '.git'), *arguments], stdin)
        if p.returncode:
            raise GateError('Git operation failed')
        return p.stdout

    def run(self, argv, stdin=None):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise GateError('query deadline exceeded')
        try:
            return subprocess.run(argv, env=self.env, input=stdin, capture_output=True, timeout=min(15, remaining))
        except subprocess.TimeoutExpired as error:
            raise GateError('query deadline exceeded') from error

    def record(self, revision, path, oid, project, blobs):
        blob = blobs[path]
        try:
            text = blob.decode('utf-8')
            if not text.startswith(('---\n', '---\r\n')):
                raise GateError('frontmatter must start the record')
            lines = text.splitlines(keepends=True)
            end = next(i for i in range(1, len(lines)) if lines[i].strip('\r\n') == '---')
            head, body = ''.join(lines[1:end]), ''.join(lines[end + 1:]).strip()
            meta = yaml.safe_load(head)
        except (ValueError, StopIteration, UnicodeError, yaml.YAMLError) as error:
            raise GateError('invalid record frontmatter') from error
        identity = Path(path).stem
        if not isinstance(meta, dict) or meta.get('id') != identity:
            raise GateError('record identity mismatch')
        if meta.get('status') != 'approved':
            return None
        scopes = meta.get('projects')
        if not isinstance(scopes, list) or not scopes or len(scopes) > 8 or not all(isinstance(x, str) and IDENTITY.fullmatch(x) for x in scopes):
            raise GateError('invalid project scopes')
        origin = meta.get('source_project_id')
        if not isinstance(origin, str) or not IDENTITY.fullmatch(origin) or origin == 'shared':
            raise GateError('missing or invalid exact source project')
        if project not in scopes and 'shared' not in scopes:
            return None
        verified, expiry = timestamp(meta.get('verified_at')), timestamp(meta.get('expires_at'))
        now = datetime.now(timezone.utc)
        if verified > now or expiry <= now:
            return None
        for key in ('source_session_id', 'source_turn_id', 'conditions'):
            if not isinstance(meta.get(key), str) or not meta[key].strip():
                raise GateError('missing exact source binding or applicability')
        evidence = meta.get('evidence')
        if not isinstance(evidence, list) or not evidence or not all(isinstance(x, str) and x for x in evidence) or meta.get('contains_secrets') is not False:
            raise GateError('missing evidence or privacy declaration')
        try:
            review = json.loads(blobs[f'reviews/{identity}.json'])
        except (KeyError, ValueError, UnicodeError) as error:
            raise GateError('invalid review receipt') from error
        if not isinstance(review, dict) or review.get('decision') != 'approve' or review.get('reviewer_kind') not in ('independent_agent', 'user'):
            raise GateError('missing approval decision')
        reviewer = review.get('reviewer_thread_id')
        if not isinstance(reviewer, str) or not reviewer or reviewer == meta['source_session_id']:
            raise GateError('self approval or missing independent source')
        if any(not isinstance(review.get(key), str) or not review[key].strip() for key in ('reviewer_turn_id', 'reviewer_message_id')):
            raise GateError('missing exact reviewer turn/message provenance')
        if review.get('record_sha256') != hashlib.sha256(blob).hexdigest() or review.get('evidence_reviewed') != evidence:
            raise GateError('review does not bind exact record/evidence')
        # Listing a target is routing, not approval to disclose another project's data.
        if project != origin and review.get('sharing_approved') is not True:
            return None
        # Verify only admitted hits, never launch one process per rejected record.
        actual = self.git('hash-object', '--stdin', stdin=blob).decode().strip()
        if actual != oid:
            raise GateError('record object integrity violation')
        if len(body) > 1200:
            raise GateError('retrievable summary exceeds 1200 characters; shorten, do not truncate')
        return {'id': identity, 'revision': revision, 'source': f'git:{revision}:{path}',
            'source_project_id': origin,
            'source_session_id': meta['source_session_id'], 'source_turn_id': meta['source_turn_id'],
            'conditions': meta['conditions'], 'expires_at': meta['expires_at'],
            'evidence': evidence, 'text': body, 'authority': 'data-not-instructions'}

    def _list_tree(self, revision):
        """Enumerate records/ and reviews/ with bounded-size validation.

        Content is NOT loaded here; callers pull only what each operation needs
        (records for matching, the matched reviews lazily) so peak memory stays
        at roughly one vault copy instead of three to four.
        """
        rows = self.git('ls-tree', '-rlz', revision, '--', 'records/', 'reviews/').split(b'\0')
        records, reviews, total = [], [], 0
        for row in filter(None, rows):
            header, path = row.decode('utf-8').split('\t', 1)
            mode, kind, oid, size = header.split()
            folder, name = path.split('/', 1)
            suffix = '.md' if folder == 'records' else '.json'
            identity = name[:-len(suffix)]
            if mode not in ('100644', '100755') or kind != 'blob' or name != identity + suffix or not IDENTITY.fullmatch(identity) or int(size) > 16384:
                raise GateError('unapproved record/review path, type or size')
            item = {'path': path, 'oid': oid, 'size': int(size)}
            (records if folder == 'records' else reviews).append(item)
            total += int(size)
        if len(records) > 1000 or (len(records) + len(reviews)) > 2000 or total > 32 * 1024 * 1024:
            raise GateError('approved snapshot exceeds bounded search budget')
        return records, reviews

    def _cat_blobs(self, items):
        """Load only the requested objects via one cat-file --batch call.

        items: iterable of {path, oid, size}. Returns {path: raw bytes}. Native
        Git object framing is verified so no export-ignore/export-subst tampering.
        """
        if not items:
            return {}
        stdin = ''.join(item['oid'] + '\n' for item in items).encode('ascii')
        data = self.git('cat-file', '--batch', stdin=stdin)
        blobs, offset = {}, 0
        for item in items:
            end = data.find(b'\n', offset)
            if data[offset:end] != f'{item["oid"]} blob {item["size"]}'.encode('ascii'):
                raise GateError('Git object framing mismatch')
            offset = end + 1
            blobs[item['path']] = data[offset:offset + item['size']]
            offset += item['size']
            if data[offset:offset + 1] != b'\n':
                raise GateError('Git object length mismatch')
            offset += 1
        if offset != len(data):
            raise GateError('unexpected Git object data')
        return blobs

    def read(self, project, identity, revision):
        """Expand one selected approved record; reject stale or foreign requests."""
        if not isinstance(project, str) or not IDENTITY.fullmatch(project):
            raise GateError('exact host scope required')
        if not isinstance(identity, str) or not IDENTITY.fullmatch(identity):
            raise GateError('invalid record identity')
        if not isinstance(revision, str) or not re.fullmatch(r'[0-9a-f]{40}', revision):
            raise GateError('exact approved revision required')
        self.deadline = self.next_deadline()
        current = self.git('rev-parse', 'refs/heads/approved').decode().strip()
        if revision != current:
            raise GateError('approved revision changed; retrieve current metadata first')
        records, reviews = self._list_tree(current)
        path = f'records/{identity}.md'
        target = next((r for r in records if r['path'] == path), None)
        if target is None:
            raise GateError('record unavailable for this host scope')
        review_item = next((r for r in reviews if r['path'] == f'reviews/{identity}.json'), None)
        if review_item is None:
            raise GateError('record unavailable for this host scope')
        blobs = self._cat_blobs([target, review_item])
        record = self.record(current, path, target['oid'], project, blobs)
        if record is None:
            raise GateError('record unavailable for this host scope')
        if hashlib.sha256(REDACTOR.read_bytes()).hexdigest() != REDACTOR_SHA256:
            raise GateError('pinned upstream redactor changed')
        check = self.run([os.environ.get('PAGS_NODE', 'node'), str(ROOT / 'source/privacy_check.mjs')],
                         json.dumps([blobs[path].decode('utf-8')], ensure_ascii=False).encode('utf-8'))
        if check.returncode or json.loads(check.stdout) != [False]:
            raise GateError('privacy check rejected record')
        if len(json.dumps(record, ensure_ascii=True).encode('ascii')) > 8192:
            raise GateError('record response budget exceeded')
        return record

    def search(self, project, terms, *, metadata_only=False):
        if not isinstance(project, str) or not IDENTITY.fullmatch(project):
            raise GateError('exact registered project ID required')
        self.deadline = self.next_deadline()
        if not isinstance(terms, list) or not 1 <= len(terms) <= 8 or not all(isinstance(t, str) and 1 <= len(t) <= 128 and not any(ord(c) < 32 for c in t) for t in terms):
            raise GateError('one to eight bounded literal query terms required')
        revision = self.git('rev-parse', 'refs/heads/approved').decode().strip()
        records, reviews = self._list_tree(revision)
        records.sort(key=lambda r: r['path'])
        paths = [r['path'] for r in records]
        oids = {r['path']: r['oid'] for r in records}
        review_by_id = {r['path'][len('reviews/'):-len('.json')]: r for r in reviews}
        # A bounded one-line projection per record, kept as bytes to avoid a
        # decode/encode round-trip that would double peak memory on multibyte text.
        # Only record bodies are loaded here; review JSON is pulled lazily per hit.
        blobs = self._cat_blobs(records)
        try:
            projection = (b'\n'.join(blobs[p].replace(b'\r', b' ').replace(b'\n', b' ') for p in paths) + b'\n')
        except UnicodeError as error:
            raise GateError('invalid UTF-8 snapshot') from error
        selected = set(range(1, len(paths) + 1))
        for term in terms:
            p = self.run([str(RG), '-n', '-i', '-F', '--color', 'never', '--max-columns', '1', '-e', term], projection)
            if p.returncode not in (0, 1):
                raise GateError('ripgrep error, not a valid miss')
            selected &= {int(line.split(b':', 1)[0]) for line in p.stdout.splitlines()}
        matches, private_inputs = [], []
        for index in sorted(selected):
            if not 1 <= index <= len(paths):
                raise GateError('unknown projected record')
            path = paths[index - 1]
            identity = path[len('records/'):-len('.md')]
            combined = {path: blobs[path]}
            review_item = review_by_id.get(identity)
            if review_item is not None:
                rb = self._cat_blobs([review_item])
                combined[review_item['path']] = rb[review_item['path']]
            result = self.record(revision, path, oids[path], project, combined)
            if result:
                if metadata_only:
                    header = {key: result[key] for key in (
                        'id', 'revision', 'source', 'source_project_id', 'source_session_id',
                        'source_turn_id', 'conditions', 'expires_at')}
                    header['title'] = result['text'].splitlines()[0].lstrip('# ').strip()[:160]
                    header['validation_status'] = 'approved'
                    result = header
                matches.append(result)
                private_inputs.append(blobs[path].decode('utf-8'))
                if len(matches) == 3:
                    break
        del blobs
        if private_inputs:
            if hashlib.sha256(REDACTOR.read_bytes()).hexdigest() != REDACTOR_SHA256:
                raise GateError('pinned upstream redactor changed')
            check = self.run([os.environ.get('PAGS_NODE', 'node'), str(ROOT / 'source/privacy_check.mjs')], json.dumps(private_inputs, ensure_ascii=False).encode('utf-8'))
            if check.returncode or json.loads(check.stdout) != [False] * len(private_inputs):
                raise GateError('privacy check rejected record')
        result = {'revision': revision, 'matches': matches}
        if len(json.dumps(result, ensure_ascii=True).encode('ascii')) > 8192:
            raise GateError('total response budget exceeded')
        if time.monotonic() > self.deadline:
            raise GateError('query deadline exceeded')
        return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--vault', default=str(ROOT / 'knowledge'))
    parser.add_argument('--project-id', required=True)
    parser.add_argument('terms', nargs='+')
    args = parser.parse_args()
    try:
        # Canonical JSON escapes preserve Unicode through Windows shell pipes.
        print(json.dumps(Vault(args.vault).search(args.project_id, args.terms), ensure_ascii=True))
    except GateError as error:
        parser.exit(1, f'PAGS gate error: {error}\n')

"""PAGS-only candidate policy. JSON files, no database or search implementation.

Identity contexts are issued separately from submissions. Sources are hashed,
not declared correct. There is deliberately no candidate promotion operation.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets

from safe_files import SafeFiles, BoundaryError, absolute, writer_mutex

PILOT = Path(__file__).resolve().parents[1]


ContractError = BoundaryError


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def bounded_text(value, name, maximum=4096):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ContractError(f"invalid {name}")
    return value.strip()


def identifier(value, name):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
        raise ContractError(f"invalid {name}")
    return value


def create_json(path, value):
    # Exclusive immutable creation, NOT replacement.
    SafeFiles(PILOT).create_new(path, encoded(value) + b"\n")


def regular_leaf(path):
    if path.is_symlink() or (path.exists() and (path.resolve() != path or not path.is_file() or path.stat().st_nlink != 1)):
        raise ContractError("reparse or hardlinked storage leaf")


def read_json(path):
    return json.loads(SafeFiles(PILOT).read(path, 65536))


class CandidateStore:
    def __init__(self, root):
        self.root = absolute(root)
        self.safe = SafeFiles(self.root)
        if not self.root.is_relative_to(PILOT):
            raise ContractError("store outside isolated pilot")
        self.store = self.root / "store"
        self.candidates = self.store / "candidates"
        self.contexts = self.store / "contexts"
        self.verified = self.store / "verified"
        for directory in [self.store, self.candidates, self.contexts, self.verified]:
            self.safe.ensure_directory(directory)

    @contextmanager
    def locked(self):
        # Kernel mutex serializes cooperating writers across processes. Sentinel
        # is handle-validated; it is not the actual lock primitive.
        with writer_mutex(self.store), self.safe.pin(self.store):
            path = self.store / ".writer.lock"
            if not path.exists():
                self.safe.create_new(path, b"0")
            self.safe.read(path, 1)
            yield

    @staticmethod
    def context_key(session, turn):
        return digest([identifier(session, "session_id"), identifier(turn, "turn_id")])

    def begin(self, project, session, turn):
        project = absolute(project)
        SafeFiles(project)
        if not project.is_dir() or not project.is_relative_to(self.root):
            raise ContractError("project outside isolated store scope")
        project_id = hashlib.sha256(os.path.normcase(str(project)).encode("utf-8")).hexdigest()
        key = self.context_key(session, turn)
        path = self.contexts / (key + ".json")
        with self.locked():
            if path.exists():
                existing = read_json(path)
                if existing["project_id"] != project_id:
                    raise ContractError("session/turn already bound to another project")
                return existing
            context = {"project_id": project_id, "project_root": str(project),
                       "session_id": session, "turn_id": turn, "nonce": secrets.token_hex(24)}
            create_json(path, context)
            return context

    def submit(self, payload):
        fields = {"schema_version", "project_id", "session_id", "turn_id", "nonce",
                  "title", "lesson", "conditions", "evidence"}
        if not isinstance(payload, dict) or set(payload) != fields:
            raise ContractError("unexpected or missing submission fields")
        if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
            raise ContractError("invalid schema_version")
        if len(encoded(payload)) > 65536:
            raise ContractError("submission exceeds 64 KiB")
        key = self.context_key(payload["session_id"], payload["turn_id"])
        with self.locked():
            context_path = self.contexts / (key + ".json")
            if not context_path.is_file():
                raise ContractError("unknown exact session/turn; no history lookup")
            context = read_json(context_path)
            for field in ["project_id", "session_id", "turn_id", "nonce"]:
                if not isinstance(payload[field], str) or not secrets.compare_digest(payload[field], context[field]):
                    raise ContractError(f"mismatched {field}")
            project = absolute(context["project_root"])
            source_files = SafeFiles(project)
            if not project.is_relative_to(self.root):
                raise ContractError("project scope changed")
            actual_project = hashlib.sha256(os.path.normcase(str(project)).encode("utf-8")).hexdigest()
            if actual_project != context["project_id"]:
                raise ContractError("canonical project identity changed")
            sources = payload["evidence"]
            if not isinstance(sources, list) or not 1 <= len(sources) <= 8:
                raise ContractError("evidence must be a nonempty bounded list")
            evidence = []
            for item in sources:
                bounded_text(item, "evidence path", 512)
                relative = Path(item)
                if relative.is_absolute() or relative.drive:
                    raise ContractError("source must be project-relative")
                source = project / relative
                try:
                    content = source_files.read(source, 1048576)
                except (OSError, RuntimeError) as error:
                    raise ContractError("missing or rejected evidence handle") from error
                evidence.append({"path": str(source.relative_to(project)),
                                 "sha256": hashlib.sha256(content).hexdigest()})
            record = {"schema_version": 1, "project_id": context["project_id"],
                      "session_id": context["session_id"], "turn_id": context["turn_id"],
                      "title": bounded_text(payload["title"], "title", 200),
                      "lesson": bounded_text(payload["lesson"], "lesson"),
                      "conditions": bounded_text(payload["conditions"], "conditions"),
                      "evidence": sorted(evidence, key=lambda x: x["path"]),
                      "status": "candidate", "verification": "not_performed"}
            identity = digest(record)
            path = self.candidates / (identity + ".json")
            if path.exists():
                if read_json(path) != dict(record, id=identity):
                    raise ContractError("existing candidate integrity mismatch")
                return {"id": identity, "duplicate": True, "status": "candidate"}
            create_json(path, dict(record, id=identity))
            return {"id": identity, "duplicate": False, "status": "candidate"}

    def verified_documents(self):
        # No reviewed admission mechanism exists in this pilot. Directory names
        # or hand-written Markdown never confer verified status.
        with self.safe.pin(self.verified):
            return []

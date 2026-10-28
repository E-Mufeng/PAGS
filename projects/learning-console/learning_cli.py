"""List project learning cards from an explicit local JSON file."""
import argparse
import json
from pathlib import Path
import re
import sys

PROJECT_ID = "pags-learning"


class InvalidPractice(ValueError):
    """Invalid optional question, with no input content in the error."""


def unique_object(pairs):
    """Reject duplicate decoded keys in every JSON object without exposing data."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load_cards(path, *, byte_limit=None):
    if byte_limit is None:
        with Path(path).open(encoding="utf-8-sig") as stream:
            document = json.load(stream, object_pairs_hook=unique_object)
    else:
        with Path(path).open('rb') as stream:
            raw = stream.read(byte_limit + 1)
        if len(raw) > byte_limit:
            raise ValueError('learning input exceeds selected-card budget')
        document = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique_object)
    if not isinstance(document, dict) or type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise ValueError("expected schema_version 1")
    cards = document.get("cards")
    if not isinstance(cards, list):
        raise ValueError("cards must be a list")
    seen = set()
    for card in cards:
        if not isinstance(card, dict):
            raise ValueError("card must be an object")
        for field in ("id", "title", "source_project_id"):
            if not isinstance(card.get(field), str) or not card[field].strip():
                raise ValueError(f"invalid {field}")
        if card["id"] in seen:
            raise ValueError("duplicate id")
        seen.add(card["id"])
        question = card.get("optional_question")
        if question is not None:
            if not isinstance(question, str) or not question.strip():
                raise InvalidPractice()
            try:
                question.encode("utf-8", errors="strict")
            except UnicodeError:
                raise InvalidPractice() from None
        scopes = card.get("applicable_projects")
        if not isinstance(scopes, list) or any(not isinstance(s, str) or not s.strip() for s in scopes):
            raise ValueError("invalid applicable_projects")
    return cards


def is_applicable(card, project_id=PROJECT_ID):
    scopes = card["applicable_projects"]
    return (project_id in scopes or "*" in scopes) and (
        card["source_project_id"] == project_id or card.get("sharing_approved") is True
    )


def learning_status(card):
    response = card.get("user_response")
    if not isinstance(response, dict) or response.get("actor") != "user":
        return "待验证"
    if not isinstance(response.get("text"), str) or not response["text"].strip():
        return "待验证"
    review = response.get("verification")
    if isinstance(review, dict) and review.get("reviewer") == "human" and review.get("passed") is True:
        return "已验证"
    return "已作答（待验证）"


def list_cards(cards, with_practice=False, *, project_id=PROJECT_ID):
    return [{"id": c["id"], "title": c["title"], "status": learning_status(c),
             "source_project_id": c["source_project_id"],
             **({"optional_question": c.get("optional_question")} if with_practice else {})}
            for c in cards if is_applicable(c, project_id)]


def linked_learning(root, project_id, record, vault):
    """Read only explicit links for one already-admitted experience; never write progress."""
    directory = Path(root) / 'learning'
    index_path = directory / 'index.json'
    if directory.resolve() != directory or index_path.resolve() != index_path:
        raise ValueError('indirect learning index')
    with index_path.open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError('learning link index exceeds budget')
    index = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object)
    if type(index.get('schema_version')) is not int or index['schema_version'] != 1 or not isinstance(index.get('experiences'), dict):
        raise ValueError('invalid learning link index')
    entries = index['experiences'].get(record['id'], [])
    if not isinstance(entries, list) or len(entries) > 2:
        raise ValueError('at most two selected learning links permitted')
    cards, seen = [], set()
    current_oid = None
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'file', 'card_id'}:
            raise ValueError('invalid selected learning link')
        name, identity = entry['file'], entry['card_id']
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}\.json', name) or not isinstance(identity, str):
            raise ValueError('invalid learning filename or identity')
        path = directory / name
        if path.resolve() != path:
            raise ValueError('learning source outside owned directory')
        matches = [card for card in load_cards(path, byte_limit=65536) if card['id'] == identity]
        if len(matches) != 1:
            raise ValueError('selected learning card missing or ambiguous')
        card = matches[0]
        if not is_applicable(card, project_id):
            continue  # Shared technical experience does not share a private personal card.
        if card['id'] in seen:
            raise ValueError('duplicate selected learning topic')
        seen.add(card['id'])
        reference = card.get('experience_reference')
        match = re.fullmatch(r'git:([0-9a-f]{40}):records/([A-Za-z0-9_-]{1,128})\.md', reference or '')
        if not match or match[2] != record['id']:
            raise ValueError('learning reference does not bind selected experience')
        if current_oid is None:
            current_oid = vault.git('rev-parse', record['revision'] + ':records/' + record['id'] + '.md').decode('ascii').strip()
        original_oid = vault.git('rev-parse', match[1] + ':records/' + record['id'] + '.md').decode('ascii').strip()
        same_bytes = original_oid == current_oid
        row = list_cards([card], with_practice=True, project_id=project_id)[0]
        row['stored_learning_status'] = row['status']
        row['status'] = '待用户验证' if row['status'] == '待验证' else '存档状态待用户来源核验'
        row.update(experience_reference=reference, current_experience=record['source'],
                   reference_status='same_record_bytes' if same_bytes else 'changed_record_requires_review')
        if not same_bytes:
            row['status'] = '来源版本已变化，待复核'
            row['optional_question'] = None
        cards.append(row)
    return {'experience_id': record['id'], 'cards': cards, 'optional': True,
            'assessment': 'stored evidence only; this read does not infer, reset or update mastery'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="explicit local JSON input")
    parser.add_argument("--json", action="store_true", help="output JSON")
    parser.add_argument("--auto-project", action="store_true",
                        help="bind actual host cwd using the existing PAGS registry")
    parser.add_argument("--with-practice", action="store_true", help="include existing optional questions")
    parser.add_argument("--output", type=Path, help="export UTF-8 JSON to a new file")
    args = parser.parse_args(argv)
    try:
        project_id = PROJECT_ID
        if args.auto_project:
            root = Path(__file__).resolve().parents[2]
            sys.path.insert(0, str(root / "source"))
            from pags_gate import project_identity
            project_id = project_identity(root / "PROJECTS.json", Path.cwd(),
                                          allow_unregistered=True)
        rows = list_cards(load_cards(args.input), with_practice=args.with_practice,
                          project_id=project_id)
    except InvalidPractice:
        print("Invalid optional_question: expected null or a non-empty UTF-8 string.", file=sys.stderr)
        return 2
    except (ImportError, KeyError, TypeError, OSError, UnicodeError, ValueError):
        # Never echo malformed input or foreign card content in errors.
        print("无法读取学习清单：请检查本地 JSON 文件及字段格式。", file=sys.stderr)
        return 2
    report_data = {"project_id": project_id, "cards": rows}
    if args.auto_project:
        report_data["scope_basis"] = ("workspace_path_not_project_proof"
                                      if project_id.startswith("local-") else "registered_exact_cwd")
    report = json.dumps(report_data, ensure_ascii=False)
    if args.output is not None:
        try:
            if args.output.resolve() == args.input.resolve():
                raise ValueError("output matches input")
            # Validate all bytes before exclusive creation can leave a new file.
            payload = (report + "\n").encode("utf-8", errors="strict")
            with args.output.open("xb") as stream:
                stream.write(payload)
        except (OSError, UnicodeError, ValueError):
            print("Cannot export report: use a new writable output file distinct from input.",
                  file=sys.stderr)
            return 2
    if args.json:
        print(report)
    elif rows:
        for row in rows:
            print(f"{row['id']} | {row['title']} | {row['status']}")
            if args.with_practice and row["optional_question"] is not None:
                print(f"  {row['optional_question']}")
    else:
        print("当前项目没有适用的学习卡。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

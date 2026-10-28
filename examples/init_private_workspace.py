"""Initialize empty local data only; do not modify an existing installation."""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
registry = root / 'PROJECTS.json'
vault = root / 'knowledge'
if registry.exists() or vault.exists():
    raise SystemExit('Local registry or vault already exists; no changes made.')
registry.write_text(json.dumps({'projects': []}, indent=2), encoding='utf-8')
vault.mkdir()
subprocess.run(['git', 'init', '--initial-branch=approved', str(vault)], check=True)
subprocess.run(['git', '-C', str(vault), '-c', 'user.name=PAGS local',
                '-c', 'user.email=pags@localhost', 'commit', '--allow-empty',
                '-m', 'Initialize empty private experience vault'], check=True)
print('Empty local data initialized; no hooks, models or global settings changed.')

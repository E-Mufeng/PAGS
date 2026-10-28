"""Fixed-project read tool over official MCP SDK; no store, HTTP or write API.

Trusted host selects identity at startup. Model input never selects project,
vault, Git revision or filesystem paths. This is a trusted-local-user semantic
boundary, not resistance to malicious same-user processes or raw filesystem access.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field

from pags_gate import ROOT, Vault, GateError, project_identity


class SearchRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    terms: list[str] = Field(min_length=1, max_length=8)


class ReadRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(pattern=r'^[A-Za-z0-9_-]{1,128}$')
    revision: str = Field(pattern=r'^[0-9a-f]{40}$')
    with_learning: bool = Field(default=False, strict=True)


def create_server(project_id=None):
    if project_id is None:
        project_id = project_identity(ROOT / 'PROJECTS.json', Path.cwd(), allow_unregistered=True)
    else:
        bound = project_identity(ROOT / 'PROJECTS.json', Path.cwd())
        if bound != project_id:
            raise ValueError('project binding rejected')
    server = MCPServer('PAGS read-only experience', version='0.2.0')

    @server.tool(structured_output=False, annotations=ToolAnnotations(
        readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def search_experience(request: SearchRequest) -> str:
        """Find at most three reviewed titles, conditions and source pointers. No experience body is returned. Literal terms use AND; start with one mechanism term. Skip greetings or idle chat."""
        try:
            result = Vault(ROOT / 'knowledge').search(project_id, request.terms, metadata_only=True)
            answer = json.dumps({'project_id': project_id, 'server_pid': os.getpid(),
                'scope_basis': 'workspace_path_not_project_proof' if project_id.startswith('local-') else 'registered_path',
                'revision': result['revision'], 'matches': result['matches'], 'view': 'metadata'}, ensure_ascii=True)
            if len(answer.encode('ascii')) > 8192:
                raise GateError('payload budget exceeded')
            return answer
        except Exception:
            # Error stays an error; do not hide it as an empty successful search.
            # SDK's ordinary-exception wire handling does not return local paths.
            raise ValueError('PAGS retrieval rejected') from None

    @server.tool(structured_output=False, annotations=ToolAnnotations(
        readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def read_experience(request: ReadRequest) -> str:
        """Read one selected experience at its current revision. Optional with_learning reads at most two scoped linked cards; never updates mastery or executes advice."""
        try:
            vault = Vault(ROOT / 'knowledge')
            record = vault.read(project_id, request.id, request.revision)
            payload = {'project_id': project_id, 'record': record}
            if request.with_learning:
                spec = importlib.util.spec_from_file_location('pags_learning_view', ROOT / 'projects/learning-console/learning_cli.py')
                learning = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(learning)
                payload['learning'] = learning.linked_learning(ROOT, project_id, record, vault)
            answer = json.dumps(payload, ensure_ascii=True)
            if len(answer.encode('ascii')) > 8192:
                raise GateError('payload budget exceeded')
            return answer
        except Exception:
            if request.with_learning:
                raise ValueError('PAGS detail/optional learning read rejected; inspect scoped source/version links') from None
            raise ValueError('PAGS detail retrieval rejected; search current metadata first') from None

    return server


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    binding = parser.add_mutually_exclusive_group(required=True)
    binding.add_argument('--project-id')
    binding.add_argument('--auto-project', action='store_true')
    args = parser.parse_args()
    try:
        server = create_server(args.project_id)
    except (ValueError, KeyError, OSError):
        parser.exit(1, 'PAGS project binding rejected\n')
    server.run(transport='stdio')

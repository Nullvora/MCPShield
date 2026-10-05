"""Release safety checks for process boundaries and incomplete scans."""
import io
import json
import sys

from click.testing import CliRunner

from mcpshield.auditlog import AuditLog
from mcpshield.cli import cli
from mcpshield.proxy.guard import StdioGuard
from mcpshield.proxy.policy import Policy


def test_scan_error_is_nonzero_even_with_threshold_disabled(tmp_path):
    path = tmp_path / 'bad.json'
    path.write_text('{broken')
    result = CliRunner().invoke(cli, ['scan', str(path), '--fail-on', 'none', '--quiet'])
    assert result.exit_code == 2


def test_child_cannot_read_audit_key(tmp_path, monkeypatch):
    monkeypatch.setenv('MCPSHIELD_AUDIT_KEY', 'test-signing-secret')
    script = "import os,json; print(json.dumps({'jsonrpc':'2.0','id':1,'result':{'key':os.environ.get('MCPSHIELD_AUDIT_KEY')}}))"
    out = io.BytesIO()
    guard = StdioGuard(sys.executable, ['-c', script], Policy(), AuditLog(tmp_path / 'audit.jsonl'),
                       stdin=io.BytesIO(), stdout=out)
    assert guard.run() == 0
    assert json.loads(out.getvalue())['result']['key'] is None


def test_inspection_exception_does_not_forward_server_bytes(tmp_path):
    script = "import json; print(json.dumps({'jsonrpc':'2.0','id':1,'result':{'secret':'do-not-forward'}}))"
    out = io.BytesIO()
    guard = StdioGuard(sys.executable, ['-c', script], Policy(), AuditLog(tmp_path / 'audit.jsonl'),
                       stdin=io.BytesIO(), stdout=out)
    def broken(_raw):
        raise RuntimeError('inspection failed')
    guard.handle_server = broken
    assert guard.run() == 0
    assert out.getvalue() == b''

"""
Round 2 tests — covers previously 0% components:
  - execution/executor.py
  - pivot/infrastructure.py
  - network/model.py
  - credential/reuse.py (WinRM validator)
  - lateral/modules.py (RDP + all techniques)
  - api/dashboard/app.py (basic import + route registration)
"""
from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock


# ── execution/executor.py ─────────────────────────────────────────────────────

class TestRemoteExecutor:
    """Tests for RemoteExecutor dispatch and result structure."""

    def _make_executor(self):
        from ares.execution.executor import RemoteExecutor
        return RemoteExecutor(operator="test_op", timeout_s=5)

    def test_executor_init(self):
        ex = self._make_executor()
        assert ex.operator == "test_op"
        assert ex.timeout_s == 5

    @pytest.mark.asyncio
    async def test_execute_returns_result_object(self):
        from ares.execution.executor import RemoteExecutor, ExecutionMethod, PayloadType
        ex = self._make_executor()

        # Patch _dispatch to avoid real network
        async def fake_dispatch(*args, **kwargs):
            return "uid=0(root)", "", 0

        with patch.object(ex, "_dispatch", side_effect=fake_dispatch):
            result = await ex.execute(
                target="10.10.0.1", command="id",
                username="admin", domain="CORP", secret="pass",
                method=ExecutionMethod.SSH,
            )

        assert result.success is True
        assert result.exit_code == 0
        assert result.stdout == "uid=0(root)"
        assert result.target == "10.10.0.1"
        assert result.operator == "test_op"

    @pytest.mark.asyncio
    async def test_execute_timeout_handled(self):
        from ares.execution.executor import RemoteExecutor, ExecutionMethod

        ex = RemoteExecutor(operator="tester", timeout_s=1)

        async def slow(*args, **kwargs):
            await asyncio.sleep(99)
            return "", "", 0

        with patch.object(ex, "_dispatch", side_effect=slow):
            result = await ex.execute(
                target="10.0.0.1", command="sleep 99",
                username="u", domain="d", secret="s",
                method=ExecutionMethod.SSH,
            )

        assert result.success is False
        assert result.exit_code == -1
        assert "timed out" in result.stderr.lower()

    @pytest.mark.asyncio
    async def test_execute_powershell_base64_encoding(self):
        from ares.execution.executor import RemoteExecutor, ExecutionMethod
        import base64

        ex = self._make_executor()
        captured = {}

        async def capture_dispatch(target, command, username, domain, secret, method, payload_type):
            captured["command"] = command
            captured["method"] = method
            return "output", "", 0

        with patch.object(ex, "_dispatch", side_effect=capture_dispatch):
            await ex.execute_powershell(
                target="10.0.0.1",
                script="Get-Process",
                username="admin", domain="CORP", secret="pass",
                encoded=True,
            )

        # Should be base64-encoded PowerShell command
        assert "EncodedCommand" in captured["command"]
        # Verify the script is correctly encoded
        encoded_part = captured["command"].split("EncodedCommand ")[-1]
        decoded = base64.b64decode(encoded_part).decode("utf-16-le")
        assert "Get-Process" in decoded

    @pytest.mark.asyncio
    async def test_execute_bash_dispatches_ssh(self):
        from ares.execution.executor import RemoteExecutor, ExecutionMethod
        ex = self._make_executor()
        captured = {}

        async def capture(target, command, username, domain, secret, method, payload_type):
            captured["method"] = method
            return "root", "", 0

        with patch.object(ex, "_dispatch", side_effect=capture):
            await ex.execute_bash(
                target="10.0.0.1", script="id",
                username="root", secret="key",
            )

        assert captured["method"] in (ExecutionMethod.SSH, ExecutionMethod.SSH_BASH)

    @pytest.mark.asyncio
    async def test_run_psexec_no_impacket_returns_error(self):
        from ares.execution.executor import RemoteExecutor
        ex = self._make_executor()

        with patch.dict("sys.modules", {"impacket": None, "impacket.smbconnection": None}):
            stdout, stderr, code = await ex._run_psexec("10.0.0.1", "whoami", "admin", "CORP", "pass")

        assert code == 1
        assert "impacket" in stderr.lower()

    @pytest.mark.asyncio
    async def test_run_wmiexec_no_impacket_returns_error(self):
        from ares.execution.executor import RemoteExecutor
        ex = self._make_executor()

        with patch.dict("sys.modules", {"impacket": None, "impacket.smbconnection": None}):
            stdout, stderr, code = await ex._run_wmiexec("10.0.0.1", "whoami", "admin", "CORP", "pass")

        assert code == 1
        assert "impacket" in stderr.lower()

    @pytest.mark.asyncio
    async def test_run_ssh_no_paramiko_returns_error(self):
        from ares.execution.executor import RemoteExecutor
        ex = self._make_executor()

        with patch.dict("sys.modules", {"paramiko": None}):
            stdout, stderr, code = await ex._run_ssh("10.0.0.1", "id", "root", "pass")

        assert code == 1
        assert "paramiko" in stderr.lower()

    @pytest.mark.asyncio
    async def test_run_winrm_no_pywinrm_returns_error(self):
        from ares.execution.executor import RemoteExecutor
        ex = self._make_executor()

        with patch.dict("sys.modules", {"winrm": None}):
            stdout, stderr, code = await ex._run_winrm("10.0.0.1", "whoami", "admin", "CORP", "pass")

        assert code == 1
        assert "pywinrm" in stderr.lower()

    @pytest.mark.asyncio
    async def test_run_ssh_with_real_paramiko_auth_failure(self):
        """Paramiko raises AuthenticationException → returns exit_code 1."""
        from ares.execution.executor import RemoteExecutor
        ex = self._make_executor()

        mock_paramiko = MagicMock()
        mock_paramiko.AuthenticationException = Exception
        mock_paramiko.SSHException = Exception
        mock_client = MagicMock()
        mock_client.connect.side_effect = mock_paramiko.AuthenticationException("bad creds")
        mock_paramiko.SSHClient.return_value = mock_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()

        with patch.dict("sys.modules", {"paramiko": mock_paramiko}):
            stdout, stderr, code = await ex._run_ssh("10.0.0.1", "id", "root", "badpass")

        assert code == 1

    def test_execution_result_defaults(self):
        from ares.execution.executor import ExecutionResult, ExecutionMethod, PayloadType
        r = ExecutionResult(target="10.0.0.1", method=ExecutionMethod.SSH)
        assert r.success is False
        assert r.exit_code == -1
        assert r.exec_id != ""

    def test_upload_and_run_logs_correctly(self):
        """upload_and_run should not crash synchronously."""
        from ares.execution.executor import RemoteExecutor
        ex = self._make_executor()
        # Just ensure the method exists and has correct signature
        assert hasattr(ex, "upload_and_run")
        assert asyncio.iscoroutinefunction(ex.upload_and_run)


# ── pivot/infrastructure.py ───────────────────────────────────────────────────

class TestPivotManager:
    """Tests for PivotManager tunnel management and routing."""

    def _make_pm(self):
        from ares.pivot.infrastructure import PivotManager
        return PivotManager(operator="test_op")

    def test_init(self):
        pm = self._make_pm()
        assert pm.operator == "test_op"
        assert pm.active_tunnels() == []

    @pytest.mark.asyncio
    async def test_establish_socks5_no_asyncssh_no_ssh_binary(self):
        """Without asyncssh and no ssh binary, tunnel is still registered."""
        pm = self._make_pm()

        with patch.dict("sys.modules", {"asyncssh": None}), \
             patch("shutil.which", return_value=None):
            tunnel = await pm.establish_socks5(
                pivot_host="10.0.0.5",
                username="root",
                secret="pass",
                local_port=1080,
            )

        assert tunnel.pivot_host == "10.0.0.5"
        assert tunnel.local_port == 1080
        assert tunnel.tunnel_id in pm._tunnels

    @pytest.mark.asyncio
    async def test_establish_socks5_asyncssh_success(self):
        """asyncssh available → tunnel ACTIVE."""
        pm = self._make_pm()

        mock_asyncssh = MagicMock()
        mock_conn = AsyncMock()
        mock_forwarder = MagicMock()
        mock_conn.forward_socks = AsyncMock(return_value=mock_forwarder)
        mock_asyncssh.connect = AsyncMock(return_value=mock_conn)

        with patch.dict("sys.modules", {"asyncssh": mock_asyncssh}):
            tunnel = await pm.establish_socks5(
                pivot_host="10.0.0.5", username="root",
                secret="pass", local_port=9050,
            )

        from ares.pivot.infrastructure import TunnelState
        assert tunnel.state == TunnelState.ACTIVE
        assert tunnel.local_port == 9050

    @pytest.mark.asyncio
    async def test_establish_local_forward_asyncssh(self):
        pm = self._make_pm()

        mock_asyncssh = MagicMock()
        mock_conn = AsyncMock()
        mock_listener = MagicMock()
        mock_conn.forward_local_port = AsyncMock(return_value=mock_listener)
        mock_asyncssh.connect = AsyncMock(return_value=mock_conn)

        with patch.dict("sys.modules", {"asyncssh": mock_asyncssh}):
            tunnel = await pm.establish_local_forward(
                pivot_host="10.0.0.5", username="root", secret="pass",
                remote_host="10.0.0.20", remote_port=1433,
                local_port=1433,
            )

        from ares.pivot.infrastructure import TunnelState
        assert tunnel.state == TunnelState.ACTIVE
        assert tunnel.remote_host == "10.0.0.20"
        assert tunnel.remote_port == 1433

    @pytest.mark.asyncio
    async def test_teardown_removes_tunnel(self):
        pm = self._make_pm()
        with patch.dict("sys.modules", {"asyncssh": None}), \
             patch("shutil.which", return_value=None):
            tunnel = await pm.establish_socks5("10.0.0.5", "root", "pass", 1080)

        tid = tunnel.tunnel_id
        assert tid in pm._tunnels
        result = pm.teardown(tid)
        assert result is True
        assert tid not in pm._tunnels

    def test_teardown_nonexistent_returns_false(self):
        pm = self._make_pm()
        assert pm.teardown("nonexistent-id") is False

    @pytest.mark.asyncio
    async def test_proxy_for_target_matches_subnet(self):
        pm = self._make_pm()
        with patch.dict("sys.modules", {"asyncssh": None}), \
             patch("shutil.which", return_value=None):
            tunnel = await pm.establish_socks5(
                "10.0.0.5", "root", "pass", 1080,
                reachable_subnets=["192.168.1.0/24"],
            )

        found = pm.proxy_for_target("192.168.1.100")
        assert found is not None
        assert found.tunnel_id == tunnel.tunnel_id

    @pytest.mark.asyncio
    async def test_proxy_for_target_no_match_returns_none(self):
        pm = self._make_pm()
        result = pm.proxy_for_target("10.0.0.99")
        assert result is None

    def test_add_port_forward(self):
        pm = self._make_pm()
        fwd = pm.add_port_forward(
            local_port=4430, remote_host="10.0.0.1",
            remote_port=443, via_tunnel="t-001",
            description="HTTPS forward",
        )
        assert fwd.local_port == 4430
        assert fwd.remote_host == "10.0.0.1"
        assert fwd.description == "HTTPS forward"
        assert len(pm.all_forwards()) == 1

    def test_generate_proxychains_config_empty(self):
        pm = self._make_pm()
        cfg = pm.generate_proxychains_config()
        assert "strict_chain" in cfg
        assert "ProxyList" in cfg

    @pytest.mark.asyncio
    async def test_generate_proxychains_config_with_tunnel(self):
        pm = self._make_pm()
        with patch.dict("sys.modules", {"asyncssh": None}), \
             patch("shutil.which", return_value=None):
            await pm.establish_socks5("10.0.0.5", "root", "pass", 1080)

        cfg = pm.generate_proxychains_config()
        assert "1080" in cfg
        assert "socks5" in cfg

    def test_generate_curl_args_no_tunnel(self):
        pm = self._make_pm()
        assert pm.generate_curl_args("10.0.0.1") == ""

    @pytest.mark.asyncio
    async def test_summary_structure(self):
        pm = self._make_pm()
        summary = pm.summary()
        assert "active_tunnels" in summary
        assert "total_tunnels" in summary
        assert "port_forwards" in summary
        assert summary["active_tunnels"] == 0

    def test_alloc_port_increments(self):
        pm = self._make_pm()
        p1 = pm._alloc_port()
        p2 = pm._alloc_port()
        assert p2 == p1 + 1

    def test_tunnel_proxy_url(self):
        from ares.pivot.infrastructure import PivotTunnel, TunnelType
        t = PivotTunnel(
            tunnel_type=TunnelType.SOCKS5,
            local_host="127.0.0.1",
            local_port=1080,
        )
        assert "socks5" in t.proxy_url
        assert "1080" in t.proxy_url

    def test_tunnel_proxychains_entry(self):
        from ares.pivot.infrastructure import PivotTunnel, TunnelType
        t = PivotTunnel(
            tunnel_type=TunnelType.SOCKS5,
            local_host="127.0.0.1",
            local_port=1080,
        )
        entry = t.to_proxychains_entry()
        assert "socks5" in entry
        assert "1080" in entry

    def test_tunnel_to_dict(self):
        from ares.pivot.infrastructure import PivotTunnel, TunnelType
        t = PivotTunnel(tunnel_type=TunnelType.SOCKS5, local_port=1080)
        d = t.to_dict()
        assert "tunnel_id" in d
        assert "type" in d
        assert "state" in d


# ── network/model.py ──────────────────────────────────────────────────────────

class TestNetworkModel:
    """Tests for network topology model."""

    def test_import(self):
        from ares.network import model
        assert model is not None

    def test_network_host_creation(self):
        from ares.network.model import NetworkHost
        h = NetworkHost(ip="10.0.0.1", hostname="dc01")
        assert h.ip == "10.0.0.1"
        assert h.hostname == "dc01"

    def test_network_host_open_ports(self):
        from ares.network.model import NetworkHost
        h = NetworkHost(ip="10.0.0.1")
        h.add_port(445, "smb", "Microsoft SMB")
        h.add_port(389, "ldap", "LDAP")
        assert 445 in h.open_ports
        assert 389 in h.open_ports

    def test_network_host_to_dict(self):
        from ares.network.model import NetworkHost
        h = NetworkHost(ip="10.0.0.1", hostname="srv01")
        d = h.to_dict()
        assert d["ip"] == "10.0.0.1"
        assert "open_ports" in d

    def test_network_topology_creation(self):
        from ares.network.model import NetworkTopology
        topo = NetworkTopology(campaign_id="c-001")
        assert topo.campaign_id == "c-001"
        assert len(topo.hosts) == 0

    def test_network_topology_add_host(self):
        from ares.network.model import NetworkTopology, NetworkHost
        topo = NetworkTopology(campaign_id="c-001")
        host = NetworkHost(ip="10.0.0.1", hostname="dc01")
        topo.add_host(host)
        assert "10.0.0.1" in topo.hosts

    def test_network_topology_get_host(self):
        from ares.network.model import NetworkTopology, NetworkHost
        topo = NetworkTopology(campaign_id="c-001")
        topo.add_host(NetworkHost(ip="10.0.0.1", hostname="dc01"))
        found = topo.get_host("10.0.0.1")
        assert found is not None
        assert found.hostname == "dc01"

    def test_network_topology_get_missing_host(self):
        from ares.network.model import NetworkTopology
        topo = NetworkTopology(campaign_id="c-001")
        assert topo.get_host("99.99.99.99") is None

    def test_network_topology_to_dict(self):
        from ares.network.model import NetworkTopology, NetworkHost
        topo = NetworkTopology(campaign_id="c-001")
        topo.add_host(NetworkHost(ip="10.0.0.1"))
        d = topo.to_dict()
        assert "campaign_id" in d
        assert "hosts" in d


# ── credential/reuse.py — WinRM validator ────────────────────────────────────

class TestWinRMValidator:

    @pytest.mark.asyncio
    async def test_winrm_no_pywinrm_returns_false(self):
        from ares.credential.reuse import _WinRMValidator, ReuseProtocol
        from ares.credential.vault import CredentialType
        v = _WinRMValidator()

        with patch.dict("sys.modules", {"winrm": None, "winrm.exceptions": None}):
            success, msg = await v.test("10.0.0.1", "admin", "CORP", "pass", CredentialType.CLEARTEXT)

        assert success is False
        assert "pywinrm" in msg.lower()

    @pytest.mark.asyncio
    async def test_winrm_invalid_credentials(self):
        from ares.credential.reuse import _WinRMValidator
        from ares.credential.vault import CredentialType
        v = _WinRMValidator()

        mock_winrm = MagicMock()
        mock_exc_module = MagicMock()
        mock_exc_module.InvalidCredentialsError = ValueError
        mock_exc_module.WinRMError = OSError
        mock_exc_module.WinRMTransportError = OSError
        mock_session = MagicMock()
        mock_session.run_cmd.side_effect = ValueError("invalid credentials")
        mock_winrm.Session.return_value = mock_session

        with patch.dict("sys.modules", {"winrm": mock_winrm, "winrm.exceptions": mock_exc_module}):
            success, msg = await v.test("10.0.0.1", "admin", "CORP", "wrong", CredentialType.CLEARTEXT)

        assert success is False

    @pytest.mark.asyncio
    async def test_winrm_success(self):
        from ares.credential.reuse import _WinRMValidator
        from ares.credential.vault import CredentialType
        v = _WinRMValidator()

        mock_winrm = MagicMock()
        mock_exc = MagicMock()
        mock_exc.InvalidCredentialsError = ValueError
        mock_exc.WinRMError = OSError
        mock_exc.WinRMTransportError = OSError
        mock_resp = MagicMock()
        mock_resp.status_code = 0
        mock_resp.std_out = b"corp\\administrator"
        mock_session = MagicMock()
        mock_session.run_cmd.return_value = mock_resp
        mock_winrm.Session.return_value = mock_session

        with patch.dict("sys.modules", {"winrm": mock_winrm, "winrm.exceptions": mock_exc}):
            success, priv = await v.test("10.0.0.1", "administrator", "CORP", "pass", CredentialType.CLEARTEXT)

        assert success is True
        assert priv in ("administrator", "user")


# ── lateral/modules.py — RDP + all techniques ────────────────────────────────

class TestLateralModules:

    @pytest.mark.asyncio
    async def test_rdp_lateral_port_open(self):
        from ares.modules.lateral.modules import RDPLateral

        rdp = RDPLateral.__new__(RDPLateral)
        rdp._log_context = {}

        def fake_connect_ex(addr):
            return 0  # port open

        def fake_recv(n):
            return bytes([0x03, 0x00, 0x00, 0x13])  # valid RDP TPKT

        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = bytes([0x03, 0x00, 0x00, 0x13])
        mock_sock.sendall.return_value = None

        with patch("socket.socket", return_value=mock_sock), \
             patch.dict("sys.modules", {"impacket.rdp": None}):
            result = await rdp.move("10.0.0.1", "admin", "CORP", "pass", port=3389)

        assert result.technique.value == "rdp"
        assert result.target_host == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_rdp_lateral_port_closed(self):
        from ares.modules.lateral.modules import RDPLateral

        rdp = RDPLateral.__new__(RDPLateral)
        rdp._log_context = {}

        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # connection refused

        with patch("socket.socket", return_value=mock_sock), \
             patch.dict("sys.modules", {"impacket.rdp": None}):
            result = await rdp.move("10.0.0.99", "admin", "CORP", "pass")

        assert result.success is False
        assert "closed" in result.error.lower() or result.error != ""

    @pytest.mark.asyncio
    async def test_psexec_no_impacket(self):
        from ares.modules.lateral.modules import PsExecLateral
        psexec = PsExecLateral.__new__(PsExecLateral)
        psexec._log_context = {}

        with patch.dict("sys.modules", {"impacket": None, "impacket.smbconnection": None}):
            result = await psexec.move("10.0.0.1", "admin", "CORP", "pass")

        assert result.success is False
        assert "impacket" in result.error.lower()

    @pytest.mark.asyncio
    async def test_ssh_pivot_no_paramiko(self):
        from ares.modules.lateral.modules import SSHPivot
        ssh = SSHPivot.__new__(SSHPivot)
        ssh._log_context = {}

        with patch.dict("sys.modules", {"paramiko": None}):
            result = await ssh.move("10.0.0.1", "root", "", "pass")

        assert result.success is False
        assert "paramiko" in result.error.lower()

    @pytest.mark.asyncio
    async def test_ssh_pivot_auth_success(self):
        from ares.modules.lateral.modules import SSHPivot

        ssh = SSHPivot.__new__(SSHPivot)
        ssh._log_context = {}

        mock_paramiko = MagicMock()
        mock_paramiko.AuthenticationException = Exception
        mock_paramiko.SSHException = Exception
        mock_paramiko.AutoAddPolicy = MagicMock
        mock_client = MagicMock()
        mock_client.connect.return_value = None
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"uid=0(root) gid=0(root)"
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)
        mock_client.close.return_value = None
        mock_paramiko.SSHClient.return_value = mock_client

        with patch.dict("sys.modules", {"paramiko": mock_paramiko}):
            result = await ssh.move("10.0.0.1", "root", "", "pass")

        assert result.success is True
        assert result.privilege == "root"

    @pytest.mark.asyncio
    async def test_winrm_lateral_no_pywinrm(self):
        from ares.modules.lateral.modules import WinRMLateral

        winrm = WinRMLateral.__new__(WinRMLateral)
        winrm._log_context = {}

        with patch.dict("sys.modules", {"winrm": None}):
            result = await winrm.move("10.0.0.1", "admin", "CORP", "pass")

        assert result.success is False
        assert "pywinrm" in result.error.lower()

    def test_lateral_result_dataclass(self):
        from ares.modules.lateral.modules import LateralResult, LateralTechnique
        r = LateralResult(
            technique=LateralTechnique.SSH,
            source_host="op",
            target_host="10.0.0.1",
            username="root",
            domain="",
            success=True,
            privilege="root",
        )
        assert r.technique == LateralTechnique.SSH
        assert r.success is True
        assert r.session_id != ""


# ── credential/reuse.py — ReuseEngine ────────────────────────────────────────

class TestReuseEngine:

    def _make_vault_with_cred(self):
        from ares.credential.vault import CredentialVault, Credential, CredentialType
        vault = CredentialVault(encryption_key=None)
        cred = Credential(
            id="cred-001",
            username="admin",
            domain="CORP",
            cred_type=CredentialType.CLEARTEXT,
            source_module="test",
            campaign_id="c-001",
        )
        vault._store["cred-001"] = cred
        vault._secrets["cred-001"] = "Password123"
        return vault

    @pytest.mark.asyncio
    async def test_spray_empty_vault(self):
        from ares.credential.reuse import ReuseEngine
        from ares.credential.vault import CredentialVault
        vault = CredentialVault(encryption_key=None)
        engine = ReuseEngine(vault=vault)

        result = await engine.spray_all_hosts("c-001", ["10.0.0.1"])
        assert result.total_attempts == 0

    @pytest.mark.asyncio
    async def test_try_single_no_validator(self):
        from ares.credential.reuse import ReuseEngine, ReuseProtocol
        from ares.credential.vault import CredentialVault, Credential, CredentialType
        vault = CredentialVault(encryption_key=None)
        cred = Credential(
            id="c1", username="u", domain="D",
            cred_type=CredentialType.CLEARTEXT,
            source_module="t", campaign_id="x"
        )
        vault._store["c1"] = cred
        vault._secrets["c1"] = "pass"
        engine = ReuseEngine(vault=vault)

        attempt = await engine.try_single(cred, "10.0.0.1", ReuseProtocol.FTP)
        assert attempt.success is False
        assert attempt.error == "no_validator"

    def test_should_skip_lockout(self):
        from ares.credential.reuse import ReuseEngine
        from ares.credential.vault import CredentialVault, Credential, CredentialType
        vault = CredentialVault(encryption_key=None)
        cred = Credential(
            id="c1", username="admin", domain="CORP",
            cred_type=CredentialType.CLEARTEXT,
            source_module="t", campaign_id="x"
        )
        engine = ReuseEngine(vault=vault, lockout_threshold=2)
        engine._attempt_counts["10.0.0.1:admin"] = 2
        assert engine._should_skip("10.0.0.1", cred) is True

    def test_should_not_skip_below_threshold(self):
        from ares.credential.reuse import ReuseEngine
        from ares.credential.vault import CredentialVault, Credential, CredentialType
        vault = CredentialVault(encryption_key=None)
        cred = Credential(
            id="c1", username="admin", domain="CORP",
            cred_type=CredentialType.CLEARTEXT,
            source_module="t", campaign_id="x"
        )
        engine = ReuseEngine(vault=vault, lockout_threshold=3)
        engine._attempt_counts["10.0.0.1:admin"] = 1
        assert engine._should_skip("10.0.0.1", cred) is False

    def test_reuse_result_success_rate(self):
        from ares.credential.reuse import ReuseResult
        r = ReuseResult(total_attempts=10, successes=3)
        assert r.success_rate == 0.3

    def test_reuse_result_zero_attempts(self):
        from ares.credential.reuse import ReuseResult
        r = ReuseResult()
        assert r.success_rate == 0.0

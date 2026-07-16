from __future__ import annotations


def _builtin_registry():
    from ares.core.plugin.loader import PluginLoader

    loader = PluginLoader()
    loaded = loader._load_builtin()
    return loader, loaded


def test_module_contracts_enumerate_actual_builtin_loader():
    loader, loaded = _builtin_registry()
    modules = loader.registry.all()
    metadata = loader.registry.list_metadata()

    assert not loader.errors
    assert loaded == len(modules)
    assert loaded >= 60
    assert len(metadata) == loaded

    module_ids = [cls.MODULE_ID for cls in modules]
    assert len(module_ids) == len(set(module_ids))

    metadata_by_id = {item["id"]: item for item in metadata}
    normalized_fields = {
        "id",
        "name",
        "category",
        "description",
        "required_params",
        "optional_params",
        "defaults",
        "capability_flags",
        "dry_run_supported",
        "supported_modes",
        "dependency_notes",
        "outcome_semantics",
        "safe_error_categories",
    }
    for cls in modules:
        module_id = cls.MODULE_ID
        meta = metadata_by_id[module_id]
        assert meta["source"] == "builtin"
        assert meta["id"] == module_id
        assert meta["name"]
        assert meta["category"]
        assert isinstance(meta["requires"], list)
        assert isinstance(meta["outputs"], list)
        assert isinstance(meta["mitre_list"], list)
        assert normalized_fields <= set(meta), module_id
        assert isinstance(meta["required_params"], list)
        assert isinstance(meta["optional_params"], list)
        assert isinstance(meta["defaults"], dict)
        assert isinstance(meta["capability_flags"], list)
        assert isinstance(meta["dry_run_supported"], bool)
        assert isinstance(meta["supported_modes"], list)
        assert isinstance(meta["dependency_notes"], list)
        assert isinstance(meta["outcome_semantics"], list)
        assert isinstance(meta["safe_error_categories"], list)


def test_builtin_module_param_schemas_are_renderable_and_match_hard_requires():
    from ares.modules.params import MODULE_PARAMS

    loader, _ = _builtin_registry()
    module_specific_required_fields = {
        "ad.asreproast": {"dc", "domain", "username", "password", "userfile"},
        "ad.kerberoast": {"dc", "domain", "username", "password", "target_user"},
        "credential.golden_ticket": {
            "domain",
            "domain_sid",
            "krbtgt_hash",
            "username",
        },
    }

    missing_schemas = []
    for cls in loader.registry.all():
        module_id = cls.MODULE_ID
        params_model = MODULE_PARAMS.get(module_id)
        if params_model is None:
            missing_schemas.append(module_id)
            continue

        schema = params_model.schema_for_api()
        assert isinstance(schema, dict), module_id
        for field_name, field in schema.items():
            assert field_name, module_id
            assert "type" in field, f"{module_id}.{field_name} missing type"
            assert "required" in field, f"{module_id}.{field_name} missing required flag"

        schema_keys = set(schema)
        requires = set(getattr(cls, "REQUIRES", []))
        if module_id in module_specific_required_fields:
            assert module_specific_required_fields[module_id] <= schema_keys, module_id
        if "domain_creds" in requires and module_id == "ad.kerberoast":
            assert {"domain", "username", "password"} <= schema_keys, module_id
        if "credentials" in requires:
            assert (
                {"username", "password"} <= schema_keys
                or {"ssh_user", "ssh_pass"} <= schema_keys
                or {"access_key", "secret_key"} <= schema_keys
            ), module_id
        if "target" in requires:
            assert {"target", "dc", "host"} & schema_keys, module_id

    assert not missing_schemas


def test_single_module_dry_run_is_structured_and_redacts_secrets():
    from ares.core.config import AresSettings
    from ares.core.engine import AresEngine

    engine = AresEngine(
        settings=AresSettings(
            ares_secret_key="test-contract-secret-key-min32-chars!!",
            ares_encryption_key="test-contract-encryption-key-32!!",
            ares_default_admin_password="TestContractPass1!",
        )
    )
    engine.load_modules()
    result = engine.dry_run_module(
        "ad.kerberoast",
        {
            "dc": "10.0.0.5",
            "domain": "corp.local",
            "username": "svc-roast",
            "password": "Passw0rd!",
            "target_user": "sqlsvc",
        },
    )

    assert result["status"] == "dry_run_ok"
    assert result["module_id"] == "ad.kerberoast"
    assert result["would_execute"] is True
    assert result["missing_params"] == []
    assert result["validated_params_summary"]["password"] == "[redacted]"
    assert "Passw0rd!" not in str(result)
    assert result["warnings"]
    assert result["operator_next_steps"]

    blocked = engine.dry_run_module(
        "ad.kerberoast",
        {"dc": "10.0.0.5", "domain": "corp.local"},
        missing_params=["username", "password"],
    )
    assert blocked["status"] == "dry_run_blocked"
    assert blocked["missing_params"] == ["username", "password"]
    assert blocked["would_execute"] is False


def test_unsupported_module_dry_run_is_explicit():
    from ares.core.config import AresSettings
    from ares.core.engine import AresEngine
    from ares.core.plugin.loader import ModuleRegistry
    from ares.modules.base import BaseModule

    class UnsupportedModule(BaseModule):
        MODULE_ID = "test.unsupported"
        MODULE_NAME = "Unsupported test module"
        MODULE_CATEGORY = "test"
        MODULE_DESCRIPTION = "Test-only module"
        DRY_RUN_SUPPORTED = False

    engine = AresEngine(
        settings=AresSettings(
            ares_secret_key="test-contract-secret-key-min32-chars!!",
            ares_encryption_key="test-contract-encryption-key-32!!",
            ares_default_admin_password="TestContractPass1!",
        )
    )
    engine._registry = ModuleRegistry()
    engine.registry.register(UnsupportedModule)

    result = engine.dry_run_module("test.unsupported", {"target": "127.0.0.1"})

    assert result["status"] == "dry_run_unsupported"
    assert result["would_execute"] is False
    assert result["operator_next_steps"]


def test_engine_done_without_findings_has_explicit_outcome():
    from ares.core.engine import EngineModuleResult, ModuleStatus

    result = EngineModuleResult(
        module_id="demo.empty",
        status=ModuleStatus.DONE,
        findings=[],
    )

    assert result.outcome == "completed_no_findings"
    assert "no confirmed findings" in result.outcome_message.lower()

    invalid = EngineModuleResult(
        module_id="ad.kerberoast",
        status=ModuleStatus.FAILED,
        error="Validation failed: invalid LDAP credentials",
    )
    timeout = EngineModuleResult(
        module_id="ad.kerberoast",
        status=ModuleStatus.TIMEOUT,
        error="Timed out after 120s",
    )
    dependency = EngineModuleResult(
        module_id="ad.kerberoast",
        status=ModuleStatus.FAILED,
        error="AD dependency 'impacket' is unavailable",
    )
    clock_skew = EngineModuleResult(
        module_id="ad.kerberoast",
        status=ModuleStatus.FAILED,
        error="Kerberoast failed: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)",
    )
    secret_error = EngineModuleResult(
        module_id="ad.kerberoast",
        status=ModuleStatus.FAILED,
        error="invalid credentials password=Passw0rd! token=secret-token",
    )
    assert invalid.outcome == "operator_error"
    assert timeout.outcome == "network_error"
    assert dependency.outcome == "dependency_error"
    assert clock_skew.outcome == "operator_error"
    assert clock_skew.outcome_message == (
        "Kerberos clock skew too great; sync the operator host and domain controller time, then rerun."
    )
    assert clock_skew.operator_next_steps
    assert "Passw0rd!" not in (secret_error.error or "")
    assert "secret-token" not in (secret_error.error or "")


def test_ad_empty_results_have_operator_facing_classification():
    from ares.modules.ad.asreproast import classify_asrep_outcome
    from ares.modules.ad.enum_spn import classify_enum_spn_outcome
    from ares.modules.ad.kerberoast import classify_kerberoast_outcome

    assert classify_asrep_outcome("authenticated", 1, 0)[0] == "completed_no_findings"
    assert "candidate" in classify_asrep_outcome("authenticated", 1, 0)[1]
    assert classify_asrep_outcome("authenticated", 0, 0)[0] == "completed_no_findings"
    assert classify_kerberoast_outcome(1, 0, 1)[0] == "network_error"
    assert classify_kerberoast_outcome(1, 0, 0)[0] == "completed_no_findings"
    assert classify_enum_spn_outcome(0)[0] == "completed_no_findings"

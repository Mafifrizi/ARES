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

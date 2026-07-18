from __future__ import annotations


def test_execution_chains_cover_every_builtin_module():
    from ares.core.execution_chains import list_execution_chains
    from ares.core.plugin.loader import PluginLoader

    loader = PluginLoader()
    loader._load_builtin()
    builtin_ids = {module.MODULE_ID for module in loader.registry.all()}
    chain_ids = {
        module_id
        for chain in list_execution_chains()
        for stage in chain["stages"]
        for module_id in stage["module_ids"]
    }

    assert len(list_execution_chains()) >= 7
    assert chain_ids <= builtin_ids
    assert chain_ids == builtin_ids


def test_execution_chains_have_ordered_stages_and_final_goals():
    from ares.core.execution_chains import list_execution_chains

    chains = list_execution_chains()
    assert {chain["id"] for chain in chains} >= {
        "ad-kerberos-exposure-chain",
        "ad-domain-enumeration-chain",
        "web-api-exposure-chain",
        "cloud-exposure-chain",
        "credential-secret-exposure-chain",
        "opsec-safety-chain",
        "reporting-evidence-chain",
        "standalone-utilities",
    }
    for chain in chains:
        stages = chain["stages"]
        assert [stage["order"] for stage in stages] == list(range(1, len(stages) + 1))
        assert sum(stage["final_goal"] for stage in stages) == 1
        for stage in stages:
            assert stage["title"]
            assert stage["purpose"]
            assert stage["next_action"]

"""C-LIVE worker boundary: serialized stdin is never dispatch authority."""

from __future__ import annotations

import pickle

import pytest

from ares.core.execution_admission import _mint_test_dispatch_context
from ares.worker._subprocess_worker import (
    _PRIVATE_WORKER_CONSUMER,
    _run_module_in_process,
    run_module,
)


CAMPAIGN_ID = "11111111-1111-4111-8111-111111111111"
MODULE_ID = "test.worker_probe"


async def _assert_serialized_worker_payload_is_always_rejected() -> None:
    result = await run_module(
        {
            "campaign_id": CAMPAIGN_ID,
            "module_id": MODULE_ID,
            "params": {"target": "127.0.0.1"},
            "capabilities": ["cap_unsafe"],
        }
    )
    assert result == {
        "success": False,
        "error": "subprocess stdin execution requires a non-serializable coordinator capability",
        "code": "EXECUTION_ADMISSION_REQUIRED",
        "findings": [],
        "raw": {},
    }


def _assert_worker_capability_cannot_be_serialized() -> None:
    context = _mint_test_dispatch_context(
        _PRIVATE_WORKER_CONSUMER,
        CAMPAIGN_ID,
        MODULE_ID,
    )
    with pytest.raises(TypeError, match="not serializable"):
        pickle.dumps(context)


async def _assert_private_in_process_worker_capability_is_single_use() -> None:
    effects: list[str] = []

    async def executor(payload):
        effects.append(payload["module_id"])
        return {"success": True, "findings": [], "raw": {"ok": True}}

    payload = {"campaign_id": CAMPAIGN_ID, "module_id": MODULE_ID, "params": {}}
    context = _mint_test_dispatch_context(
        _PRIVATE_WORKER_CONSUMER,
        CAMPAIGN_ID,
        MODULE_ID,
        ordinal=1,
    )
    result = await _run_module_in_process(payload, context, executor)
    assert result["success"] is True
    assert effects == [MODULE_ID]

    with pytest.raises(PermissionError, match="already used"):
        await _run_module_in_process(payload, context, executor)
    assert effects == [MODULE_ID]


async def _assert_private_worker_rejects_cross_module_context_before_effect() -> None:
    effects = 0

    async def executor(payload):
        nonlocal effects
        effects += 1
        return {"success": True}

    context = _mint_test_dispatch_context(
        _PRIVATE_WORKER_CONSUMER,
        CAMPAIGN_ID,
        MODULE_ID,
        ordinal=2,
    )
    with pytest.raises(PermissionError):
        await _run_module_in_process(
            {"campaign_id": CAMPAIGN_ID, "module_id": "test.other", "params": {}},
            context,
            executor,
        )
    assert effects == 0


@pytest.mark.parametrize(
    "case",
    [
        "missing-capability",
        "fabricated-serialized-capability",
        "valid-coordinator-capability-single-use",
    ],
)
@pytest.mark.asyncio
async def test_subprocess_worker_sealed_admission(case: str) -> None:
    if case == "missing-capability":
        await _assert_serialized_worker_payload_is_always_rejected()
    elif case == "fabricated-serialized-capability":
        _assert_worker_capability_cannot_be_serialized()
        await _assert_private_worker_rejects_cross_module_context_before_effect()
    else:
        await _assert_private_in_process_worker_capability_is_single_use()

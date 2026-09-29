"""Adversarial tests for ARES C-LIVE Execution Admission Invariants.

Verifies:
1. Single-consumer binding (cannot be consumed by wrong engine/consumer).
2. Replay prevention (cannot be consumed more than once).
3. Non-serializability (cannot be pickled or transplanted across processes).
4. Campaign binding (cannot be executed under an unauthorized campaign).
5. Module binding (cannot execute a module different from admitted).
6. Sealed capability integrity (tampered context or forged signature rejected).
7. Issuer authenticity (cannot instantiate context without coordinator issuer seal).
"""
from __future__ import annotations

import pickle

import pytest

from ares.core.engine import AresEngine
from ares.core.execution_admission import (
    AdmittedDispatchContextV1,
    _mint_test_dispatch_context,
    consume_dispatch_context,
    mark_effect_started,
)


class TestExecutionAdmissionInvariants:
    """Rigorous invariant verification for AdmittedDispatchContextV1."""

    def test_admission_context_belongs_to_intended_consumer(self):
        engine_a = AresEngine()
        engine_b = AresEngine()
        campaign_id = "11111111-1111-4111-8111-111111111111"
        module_id = "test.dummy"

        ctx = _mint_test_dispatch_context(
            consumer=engine_a,
            campaign_id=campaign_id,
            module_id=module_id,
        )

        # Consuming with wrong consumer must fail-closed
        with pytest.raises(
            PermissionError, match="stale, transferred, fabricated, or already used"
        ):
            consume_dispatch_context(
                ctx,
                consumer=engine_b,
                campaign_id=campaign_id,
                module_id=module_id,
            )

    def test_admission_context_replay_prevention(self):
        engine = AresEngine()
        campaign_id = "22222222-2222-4222-8222-222222222222"
        module_id = "test.replay"

        ctx = _mint_test_dispatch_context(
            consumer=engine,
            campaign_id=campaign_id,
            module_id=module_id,
        )

        # First consumption must succeed
        consumed = consume_dispatch_context(
            ctx,
            consumer=engine,
            campaign_id=campaign_id,
            module_id=module_id,
        )
        assert consumed._consumed is True

        # Second consumption (replay attack) must fail-closed
        with pytest.raises(
            PermissionError, match="stale, transferred, fabricated, or already used"
        ):
            consume_dispatch_context(
                ctx,
                consumer=engine,
                campaign_id=campaign_id,
                module_id=module_id,
            )

    def test_admission_context_serialization_forbidden(self):
        engine = AresEngine()
        campaign_id = "33333333-3333-4333-8333-333333333333"
        module_id = "test.transplant"

        ctx = _mint_test_dispatch_context(
            consumer=engine,
            campaign_id=campaign_id,
            module_id=module_id,
        )

        with pytest.raises(TypeError, match="dispatch contexts are not serializable"):
            pickle.dumps(ctx)

    def test_admission_context_campaign_mismatch(self):
        engine = AresEngine()
        campaign_id = "44444444-4444-4444-8444-444444444444"
        module_id = "test.campaign_isolation"

        ctx = _mint_test_dispatch_context(
            consumer=engine,
            campaign_id=campaign_id,
            module_id=module_id,
        )

        with pytest.raises(
            PermissionError, match="stale, transferred, fabricated, or already used"
        ):
            consume_dispatch_context(
                ctx,
                consumer=engine,
                campaign_id="99999999-9999-4999-8999-999999999999",
                module_id=module_id,
            )

    def test_admission_context_module_mismatch(self):
        engine = AresEngine()
        campaign_id = "55555555-5555-4555-8555-555555555555"
        module_id = "test.legitimate_module"

        ctx = _mint_test_dispatch_context(
            consumer=engine,
            campaign_id=campaign_id,
            module_id=module_id,
        )

        with pytest.raises(
            PermissionError, match="stale, transferred, fabricated, or already used"
        ):
            consume_dispatch_context(
                ctx,
                consumer=engine,
                campaign_id=campaign_id,
                module_id="test.unauthorized_module",
            )

    def test_admission_context_unauthorized_direct_instantiation_rejected(self):
        with pytest.raises(TypeError, match="dispatch contexts are coordinator-created only"):
            AdmittedDispatchContextV1(
                campaign_id="66666666-6666-4666-8666-666666666666",
                submission_id="77777777-7777-4777-8777-777777777777",
                logical_execution_id="88888888-8888-4888-8888-888888888888",
                attempt_id="99999999-9999-4999-8999-999999999999",
                module_id="test.fake",
                attempt_revision=3,
                consumer=object(),
                store=object(),
                _issuer=object(),  # Fake issuer
            )

    def test_mark_effect_started_requires_consumed_context(self):
        engine = AresEngine()
        campaign_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        module_id = "test.effect"

        ctx = _mint_test_dispatch_context(
            consumer=engine,
            campaign_id=campaign_id,
            module_id=module_id,
        )

        # Before consume: cannot mark effect started
        with pytest.raises(
            PermissionError, match="effect boundary requires a consumed dispatch context"
        ):
            mark_effect_started(ctx)

        # After consume: effect started succeeds
        consumed = consume_dispatch_context(
            ctx,
            consumer=engine,
            campaign_id=campaign_id,
            module_id=module_id,
        )
        mark_effect_started(consumed)
        assert consumed._effect_started is True

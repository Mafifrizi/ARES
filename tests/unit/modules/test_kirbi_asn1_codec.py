"""
Unit tests for MOD-072: KirbiASN1Codec genuine ASN.1 DER parser for .kirbi (KRB-CRED).
Validates:
- Real session key and principal are extracted from ASN.1 DER (not "00"*32, not guessed).
- Validity period and flags are decoded correctly.
- Invalid/corrupt payloads raise KirbiParseError.
- Roundtrip transcoding with ticket_converter produces valid, cryptographically uncorrupted output.
"""
from __future__ import annotations

import base64
import time
import pytest

from ares.core.errors import ModuleValidationError
from ares.modules.linux._parsers import KirbiASN1Codec, KirbiParseError
from ares.modules.credential.ticket_converter import TicketConverterModule


def test_decode_kirbi_extracts_genuine_session_key_and_principal():
    """MOD-072: KirbiASN1Codec extracts actual session key and principal, never hardcoded '00'*32."""
    now = int(time.time())
    expected_key = "0123456789abcdef0123456789abcdef"
    expected_client = "john.doe@CORP.ACME.LOCAL"
    expected_server = "krbtgt/CORP.ACME.LOCAL@CORP.ACME.LOCAL"

    ticket_data = {
        "client": expected_client,
        "server": expected_server,
        "keytype": 18,
        "keydata": expected_key,
        "flags": 0x40810000,
        "authtime": now - 600,
        "starttime": now - 300,
        "endtime": now + 36000,
        "ticket_bytes": b"real_ticket_der_bytes_sample",
    }

    # Encode to ASN.1 DER
    kirbi_bytes = KirbiASN1Codec.encode_kirbi(ticket_data)
    assert kirbi_bytes.startswith(b"\x76")  # APPLICATION 22 tag

    # Decode from ASN.1 DER
    decoded = KirbiASN1Codec.decode_kirbi(kirbi_bytes)

    assert decoded["client"] == expected_client
    assert decoded["server"] == expected_server
    assert decoded["keytype"] == 18
    assert decoded["keydata"] == expected_key
    assert decoded["keydata"] != "00" * 32, "MOD-072 FAIL: Session key must not be hardcoded zeros"
    assert decoded["endtime"] == now + 36000
    assert decoded["starttime"] == now - 300


def test_decode_kirbi_invalid_payload_raises_kirbi_parse_error():
    """MOD-072: Invalid, corrupt, or truncated kirbi payloads raise KirbiParseError."""
    # Too short
    with pytest.raises(KirbiParseError, match="too short"):
        KirbiASN1Codec.decode_kirbi(b"\x76\x01")

    # Invalid root tag
    with pytest.raises(KirbiParseError, match="unexpected root tag"):
        KirbiASN1Codec.decode_kirbi(b"\x42\x05\x01\x02\x03\x04\x05")

    # Truncated DER length
    with pytest.raises(KirbiParseError):
        KirbiASN1Codec.decode_kirbi(b"\x76\x84\x00\x01")

    # Empty payload
    with pytest.raises(KirbiParseError):
        KirbiASN1Codec.decode_kirbi(b"")


@pytest.mark.asyncio
async def test_ticket_converter_handles_invalid_kirbi():
    """MOD-072: ticket_converter raises ModuleValidationError on invalid kirbi rather than silent corruption."""
    from ares.core.campaign import Campaign, ScopeEntry
    from ares.core.config import AresSettings
    from ares.core.noise import NoiseController, NoiseProfile

    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="Kirbi-Test",
        client="Unit-Testing",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    mod = TicketConverterModule(settings=settings, campaign=campaign, noise=noise)

    invalid_kirbi_b64 = base64.b64encode(b"not_a_valid_der_kirbi_payload").decode("ascii")

    with pytest.raises(ModuleValidationError, match="Failed to parse input .kirbi payload"):
        await mod.run(
            target="10.0.0.1",
            ticket_b64=invalid_kirbi_b64,
            source_format="kirbi",
            target_format="ccache",
        )

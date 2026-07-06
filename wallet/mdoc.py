### Digital Credentials API (OpenID4VP-over-DC-API / mso_mdoc) ###
#
# Ported from w.py, which exercises the same mdoc-building logic against
# digital-credentials.dev over plain HTTPS. Here the "request" JSON is the
# one carried inside a FRAME_JSON hybrid frame (matching the shape passed to
# navigator.credentials.get({digital: {requests: [...]}})) instead of an
# /api/getRequest HTTP response, and the built vp_token goes back over the
# tunnel instead of to /api/validateResponse.
#
# The response envelope sent back over the tunnel is
# {"response": {"digital": {"data": {"protocol": ..., "data": {"vp_token": {cred_id: [mdoc_b64]}}}}}}
# -- confirmed against a real device-log capture of CMWallet's own response.
# Notable gotchas found by trial and error / that capture:
#   - top-level "response" wrapper is required (device-log: "no 'response'
#     element in response")
#   - "digital" wrapper is required (device-log: "no 'digital' element")
#   - there's a second "data" layer: digital.data.{protocol, data}, not
#     digital.{protocol, data} directly (device-log: "response missing both
#     'error' and 'data'" when that layer was missing)
#   - each vp_token entry is a LIST of matched-credential mdocs (DCQL query
#     ids can match multiple credentials), not a bare string.

import base64
import datetime
import hashlib
import logging
import uuid

import cbor2

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def cbor_tag24(obj) -> bytes:
    """#6.24(bstr .cbor obj) -- the 'encoded CBOR data item' wrapper mdoc uses everywhere."""
    return cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(obj)))


def cose_sign1_ec(priv: ec.EllipticCurvePrivateKey, protected: dict, payload,
                   external_payload_for_sig: bytes) -> list:
    """Build a COSE_Sign1 [protected, unprotected, payload, signature] array.
    `external_payload_for_sig` is what actually gets signed (== payload,
    unless payload is detached/None as for DeviceAuth)."""
    protected_bytes = cbor2.dumps(protected)
    sig_structure = ["Signature1", protected_bytes, b"", external_payload_for_sig]
    to_sign = cbor2.dumps(sig_structure)
    der_sig = priv.sign(to_sign, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return [protected_bytes, {}, payload, raw_sig]


def ec_pub_to_cose_key(pub: ec.EllipticCurvePublicKey) -> dict:
    nums = pub.public_numbers()
    return {
        1: 2,  # kty: EC2
        -1: 1,  # crv: P-256
        -2: nums.x.to_bytes(32, "big"),
        -3: nums.y.to_bytes(32, "big"),
    }


def parse_dcql(request_data: dict):
    """Pull out (credential_id, doctype, namespace -> [claim names]) from a DCQL query."""
    dcql = request_data.get("dcql_query") or request_data
    cred = dcql["credentials"][0]
    cred_id = cred["id"]
    doctype = cred["meta"]["doctype_value"]
    wanted: dict[str, list[str]] = {}
    for claim in cred.get("claims", []):
        ns, name = claim["path"]
        wanted.setdefault(ns, []).append(name)
    nonce = request_data.get("nonce")
    return cred_id, doctype, wanted, nonce


# Sample values for a fictional mDL -- edit to taste.
SAMPLE_VALUES = {
    "family_name": "Doe",
    "given_name": "Jane",
    "birth_date": cbor2.CBORTag(1004, "1990-01-01"),  # full-date
    "age_over_18": True,
    "age_over_21": True,
    "portrait": b"\x89PNG\r\n\x1a\n",  # placeholder bytes; real portrait would be a JPEG
}


def build_mdoc(doctype: str, wanted: dict[str, list[str]],
                issuer_key: ec.EllipticCurvePrivateKey, issuer_cert_der: bytes,
                device_pub: ec.EllipticCurvePublicKey):
    name_spaces_bytes = {}
    value_digests = {}

    for ns, claim_names in wanted.items():
        items_bytes = []
        digests = {}
        for digest_id, name in enumerate(claim_names):
            if name not in SAMPLE_VALUES:
                continue
            item = {
                "digestID": digest_id,
                "random": uuid.uuid4().bytes + uuid.uuid4().bytes,  # 32 bytes of "salt"
                "elementIdentifier": name,
                "elementValue": SAMPLE_VALUES[name],
            }
            item_bytes = cbor_tag24(item)
            items_bytes.append(cbor2.CBORTag(24, cbor2.dumps(item)))
            digests[digest_id] = hashlib.sha256(item_bytes).digest()
        name_spaces_bytes[ns] = items_bytes
        value_digests[ns] = digests

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    mso = {
        "version": "1.0",
        "digestAlgorithm": "SHA-256",
        "valueDigests": value_digests,
        "deviceKeyInfo": {"deviceKey": ec_pub_to_cose_key(device_pub)},
        "docType": doctype,
        "validityInfo": {
            "signed": cbor2.CBORTag(0, now.isoformat().replace("+00:00", "Z")),
            "validFrom": cbor2.CBORTag(0, now.isoformat().replace("+00:00", "Z")),
            "validUntil": cbor2.CBORTag(0, (now + datetime.timedelta(days=365)).isoformat().replace("+00:00", "Z")),
        },
    }
    mso_bytes = cbor_tag24(mso)  # this IS the COSE payload

    protected = {1: -7}  # alg: ES256
    issuer_auth = cose_sign1_ec(issuer_key, protected, payload=mso_bytes,
                                 external_payload_for_sig=mso_bytes)
    issuer_auth[1] = {33: [issuer_cert_der]}  # x5chain in unprotected header

    return {
        "docType": doctype,
        "issuerSigned": {"nameSpaces": name_spaces_bytes, "issuerAuth": issuer_auth},
    }


def sign_device_auth(document_no_device_signed: dict, doctype: str,
                      session_transcript: list, device_priv: ec.EllipticCurvePrivateKey):
    device_name_spaces = {}  # no additional device-signed claims
    device_ns_bytes = cbor_tag24(device_name_spaces)

    device_auth_struct = ["DeviceAuthentication", session_transcript, doctype,
                           cbor2.CBORTag(24, cbor2.loads(device_ns_bytes).value)]
    device_auth_bytes = cbor_tag24(device_auth_struct)

    protected = {1: -7}
    device_signature = cose_sign1_ec(device_priv, protected, payload=None,
                                      external_payload_for_sig=device_auth_bytes)

    document_no_device_signed["deviceSigned"] = {
        "nameSpaces": cbor2.CBORTag(24, cbor2.loads(device_ns_bytes).value),
        "deviceAuth": {"deviceSignature": device_signature},
    }
    return document_no_device_signed


def compute_session_transcript(origin: str, nonce: str, jwk_thumbprint=None):
    """OpenID4VP-over-DC-API / ISO 18013-7 Annex C session transcript."""
    handover_info = [origin, nonce, jwk_thumbprint]
    handover_info_bytes = cbor2.dumps(handover_info)
    handover_hash = hashlib.sha256(handover_info_bytes).digest()
    dc_api_handover = ["OpenID4VPDCAPIHandover", handover_hash]
    return [None, None, dc_api_handover]


def make_sample_issuer():
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Sample Test mDL Issuer"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NL"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(Encoding.DER)


def build_dc_api_response(request_json: dict) -> dict:
    """Build the vp_token response for a FRAME_JSON digital-credentials request
    (as produced by navigator.credentials.get({digital: {requests: [...]}})).
    Only handles a single mso_mdoc DCQL request, unencrypted/unsigned, like w.py."""
    origin = request_json["origin"]
    digital_request = request_json["request"]["digital"]["requests"][0]
    protocol = digital_request["protocol"]
    request_data = digital_request["data"]

    cred_id, doctype, wanted, nonce = parse_dcql(request_data)
    logging.info("DC API request: doctype=%s wanted=%s nonce=%s", doctype, wanted, nonce)

    issuer_key, issuer_cert_der = make_sample_issuer()
    device_key = ec.generate_private_key(ec.SECP256R1())

    document = build_mdoc(doctype, wanted, issuer_key, issuer_cert_der, device_key.public_key())
    session_transcript = compute_session_transcript(origin, nonce)
    document = sign_device_auth(document, doctype, session_transcript, device_key)

    device_response = {"version": "1.0", "documents": [document], "status": 0}
    mdoc_b64 = b64url(cbor2.dumps(device_response))

    vp_token = {cred_id: [mdoc_b64]}
    return {"protocol": protocol, "data": {"vp_token": vp_token}}

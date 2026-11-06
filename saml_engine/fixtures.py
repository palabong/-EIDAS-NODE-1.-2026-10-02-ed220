"""
Realistic eIDAS 2.0 SAML Test Fixtures and Key Pairs
Includes RSA and ECDSA self-signed certificates and generators for positive
and negative security vectors (tampering, expiration, replay, audience mismatch, XSW).
"""

import os
import fcntl
import base64
import hashlib
import subprocess
import tempfile
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple

# =============================================================================
# ENVIRONMENT / SECRET MANAGER OR EPHEMERAL SANDBOX KEYPAIRS (ZERO REPO SECRETS)
# =============================================================================

EPHEMERAL_SAML_DIR = os.path.join(
    tempfile.gettempdir(), f"bilanx_ephemeral_saml_{os.getuid()}"
)
EPHEMERAL_TRUSTED_CERTS_DIR = os.path.join(EPHEMERAL_SAML_DIR, "certs")


def _read_optional_file(file_path: Optional[str]) -> Optional[str]:
    if not file_path:
        return None
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    return None


def _load_or_generate_fixture_keypair(
    env_prefix: str,
    file_stem: str,
    algorithm: str,
    subject: str,
    export_to_trusted_idp_dir: bool = False,
) -> Tuple[str, str]:
    """
    Loads SAML signing keypair from environment variables or Secret Manager file mounts,
    falling back to dynamically generated ephemeral keypairs in OS temp storage for
    local development, sandbox demos, and automated CI test suites.
    """
    env_key = os.environ.get(f"{env_prefix}_KEY_PEM", "").strip()
    env_cert = os.environ.get(f"{env_prefix}_CERT_PEM", "").strip()
    if env_key and env_cert:
        return env_key, env_cert

    path_key = _read_optional_file(os.environ.get(f"{env_prefix}_KEY_PATH"))
    path_cert = _read_optional_file(os.environ.get(f"{env_prefix}_CERT_PATH"))
    if path_key and path_cert:
        return path_key, path_cert

    os.makedirs(EPHEMERAL_SAML_DIR, mode=0o700, exist_ok=True)
    os.makedirs(EPHEMERAL_TRUSTED_CERTS_DIR, mode=0o700, exist_ok=True)
    lock_path = os.path.join(EPHEMERAL_SAML_DIR, ".keygen.lock")
    key_path = os.path.join(EPHEMERAL_SAML_DIR, f"{file_stem}.key")
    cert_path = os.path.join(EPHEMERAL_SAML_DIR, f"{file_stem}.crt")
    trusted_cert_copy = os.path.join(EPHEMERAL_TRUSTED_CERTS_DIR, f"{file_stem}.crt")

    with open(lock_path, "w", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            if not (os.path.exists(key_path) and os.path.exists(cert_path)):
                if algorithm == "rsa":
                    cmd = [
                        "openssl", "req", "-x509",
                        "-newkey", "rsa:2048",
                        "-nodes",
                        "-keyout", key_path,
                        "-out", cert_path,
                        "-days", "365",
                        "-subj", subject,
                    ]
                elif algorithm == "ec":
                    cmd = [
                        "openssl", "req", "-x509",
                        "-newkey", "ec",
                        "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes",
                        "-keyout", key_path,
                        "-out", cert_path,
                        "-days", "365",
                        "-subj", subject,
                    ]
                else:
                    raise ValueError(f"Unsupported fixture key algorithm: {algorithm}")

                subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                os.chmod(key_path, 0o600)

            with open(key_path, "r", encoding="utf-8") as kf:
                key_pem = kf.read().strip()
            with open(cert_path, "r", encoding="utf-8") as cf:
                cert_pem = cf.read().strip()

            if export_to_trusted_idp_dir and not os.path.exists(trusted_cert_copy):
                with open(trusted_cert_copy, "w", encoding="utf-8") as tf:
                    tf.write(cert_pem + "\n")
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    return key_pem, cert_pem


IDP_RSA_KEY_PEM, IDP_RSA_CERT_PEM = _load_or_generate_fixture_keypair(
    env_prefix="SAML_IDP_RSA",
    file_stem="idp_rsa",
    algorithm="rsa",
    subject="/C=EU/O=EU/CN=eIDAS Ephemeral Test IdP",
    export_to_trusted_idp_dir=True,
)

IDP_EC_KEY_PEM, IDP_EC_CERT_PEM = _load_or_generate_fixture_keypair(
    env_prefix="SAML_IDP_EC",
    file_stem="idp_ec",
    algorithm="ec",
    subject="/C=EU/O=EU/CN=eIDAS Ephemeral Test EC IdP",
    export_to_trusted_idp_dir=True,
)

SP_RSA_KEY_PEM, SP_RSA_CERT_PEM = _load_or_generate_fixture_keypair(
    env_prefix="SAML_SP_RSA",
    file_stem="sp_rsa",
    algorithm="rsa",
    subject="/C=EU/O=Project Bilanx/CN=Bilanx eIDAS SP Node",
    export_to_trusted_idp_dir=False,
)

def _clean_cert_b64(cert_pem: str) -> str:
    lines = [l.strip() for l in cert_pem.strip().splitlines() if not l.startswith("-----")]
    return "".join(lines)

IDP_RSA_CERT_B64 = _clean_cert_b64(IDP_RSA_CERT_PEM)
IDP_EC_CERT_B64 = _clean_cert_b64(IDP_EC_CERT_PEM)
SP_RSA_CERT_B64 = _clean_cert_b64(SP_RSA_CERT_PEM)

# =============================================================================
# DYNAMIC SIGNED SAML RESPONSE GENERATOR
# =============================================================================

def build_signed_saml_response(
    response_id: Optional[str] = None,
    assertion_id: Optional[str] = None,
    in_response_to: str = "_BWujh-SYHdY7qT35CXZ8y.yk5tSK793zQoiavTqXe.i_AuVw0f9RTOEQOihenSv",
    issuer: str = "http://cef-eid-build-1:8080/EidasNode/ServiceMetadata",
    destination: str = "http://cef-eid-build-1:8080/EidasNode/ColleagueResponse",
    audience: str = "http://sp.local:9090/SP/Metadata",
    issue_instant: Optional[datetime] = None,
    not_before: Optional[datetime] = None,
    not_on_or_after: Optional[datetime] = None,
    person_identifier: str = "IT/IT/TINIT-PLGDNL85M01H501Z",
    family_name: str = "Palagi",
    given_name: str = "Daniele",
    date_of_birth: str = "1985-08-01",
    loa: str = "http://eidas.europa.eu/LoA/substantial",
    status_code: str = "urn:oasis:names:tc:SAML:2.0:status:Success",
    key_pem: str = IDP_RSA_KEY_PEM,
    cert_pem: str = IDP_RSA_CERT_PEM,
    algorithm: str = "rsa-sha256",  # 'rsa-sha256' or 'ecdsa-sha256'
    tamper_content: bool = False,
    tamper_signature_value: bool = False,
    omit_dob: bool = False,
    omit_person_id: bool = False,
    extra_outer_assertion: bool = False,  # For XSW attack simulation
    omit_conditions: bool = False,
    empty_attributes: bool = False,
    response_issuer: Optional[str] = None,
    assertion_issuer: Optional[str] = None,
) -> str:
    """
    Constructs a standards-compliant eIDAS 2.0 signed SAML Response.
    Performs real XML canonicalization (C14N), SHA-256 digest calculation,
    and OpenSSL RSA/ECDSA signing of the enveloped Assertion.
    """
    now = datetime.now(timezone.utc)
    resp_id = response_id or f"_resp_{int(now.timestamp())}_{os.urandom(4).hex()}"
    asrt_id = assertion_id or f"_asrt_{int(now.timestamp())}_{os.urandom(4).hex()}"

    t_issue = (issue_instant or now).strftime("%Y-%m-%dT%H:%M:%SZ")
    t_nb = (not_before or (now - timedelta(seconds=60))).strftime("%Y-%m-%dT%H:%M:%SZ")
    t_noa = (not_on_or_after or (now + timedelta(seconds=300))).strftime("%Y-%m-%dT%H:%M:%SZ")

    resp_issuer = response_issuer or issuer
    asrt_issuer = assertion_issuer or issuer

    sig_method_uri = (
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        if algorithm == "rsa-sha256"
        else "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
    )

    cert_b64 = _clean_cert_b64(cert_pem)

    # 1. Build attributes list
    attr_xml_parts = []
    if not empty_attributes:
        if not omit_person_id:
            attr_xml_parts.append(
                f'<saml2:Attribute FriendlyName="PersonIdentifier" Name="http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{person_identifier}</saml2:AttributeValue></saml2:Attribute>'
            )
        attr_xml_parts.append(
            f'<saml2:Attribute FriendlyName="CurrentFamilyName" Name="http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{family_name}</saml2:AttributeValue></saml2:Attribute>'
        )
        attr_xml_parts.append(
            f'<saml2:Attribute FriendlyName="CurrentGivenName" Name="http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{given_name}</saml2:AttributeValue></saml2:Attribute>'
        )
        if not omit_dob:
            attr_xml_parts.append(
                f'<saml2:Attribute FriendlyName="DateOfBirth" Name="http://eidas.europa.eu/attributes/naturalperson/DateOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{date_of_birth}</saml2:AttributeValue></saml2:Attribute>'
            )

    attributes_xml = "".join(attr_xml_parts)

    conditions_xml = "" if omit_conditions else (
        f'<saml2:Conditions NotBefore="{t_nb}" NotOnOrAfter="{t_noa}">'
        f'<saml2:AudienceRestriction><saml2:Audience>{audience}</saml2:Audience></saml2:AudienceRestriction>'
        f'</saml2:Conditions>'
    )

    # 2. Build canonical Assertion (WITHOUT Signature) for Digest Calculation
    assertion_c14n_body = (
        f'<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="{asrt_id}" IssueInstant="{t_issue}" Version="2.0">'
        f'<saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{asrt_issuer}</saml2:Issuer>'
        f'<saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{person_identifier}</saml2:NameID>'
        f'<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml2:SubjectConfirmationData InResponseTo="{in_response_to}" NotOnOrAfter="{t_noa}" Recipient="{destination}"></saml2:SubjectConfirmationData>'
        f'</saml2:SubjectConfirmation></saml2:Subject>'
        f'{conditions_xml}'
        f'<saml2:AuthnStatement AuthnInstant="{t_issue}">'
        f'<saml2:AuthnContext><saml2:AuthnContextClassRef>{loa}</saml2:AuthnContextClassRef></saml2:AuthnContext>'
        f'</saml2:AuthnStatement>'
        f'<saml2:AttributeStatement>{attributes_xml}</saml2:AttributeStatement>'
        f'</saml2:Assertion>'
    )

    # Calculate SHA-256 Digest of canonicalized Assertion
    assertion_digest_bytes = hashlib.sha256(assertion_c14n_body.encode("utf-8")).digest()
    assertion_digest_b64 = base64.b64encode(assertion_digest_bytes).decode("utf-8")

    # 3. Build Canonical SignedInfo for Signature Calculation
    signed_info_c14n = (
        f'<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        f'<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>'
        f'<ds:SignatureMethod Algorithm="{sig_method_uri}"></ds:SignatureMethod>'
        f'<ds:Reference URI="#{asrt_id}">'
        f'<ds:Transforms>'
        f'<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>'
        f'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>'
        f'</ds:Transforms>'
        f'<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>'
        f'<ds:DigestValue>{assertion_digest_b64}</ds:DigestValue>'
        f'</ds:Reference>'
        f'</ds:SignedInfo>'
    )

    # 4. Sign SignedInfo with Private Key using OpenSSL
    with tempfile.NamedTemporaryFile("w+", delete=False) as key_f:
        key_f.write(key_pem.strip())
        key_path = key_f.name

    try:
        sign_proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", key_path],
            input=signed_info_c14n.encode("utf-8"),
            capture_output=True,
            check=True
        )
        sig_raw = sign_proc.stdout
        sig_b64 = base64.b64encode(sig_raw).decode("utf-8")
    finally:
        if os.path.exists(key_path):
            os.remove(key_path)

    # Simulate tampering if requested
    if tamper_signature_value:
        char_to_flip = "B" if sig_b64[10] != "B" else "C"
        sig_b64 = sig_b64[:10] + char_to_flip + sig_b64[11:]

    # Assemble Signature XML
    signature_xml = (
        f'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        f'{signed_info_c14n}'
        f'<ds:SignatureValue>{sig_b64}</ds:SignatureValue>'
        f'<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>'
        f'</ds:Signature>'
    )

    # Insert Signature immediately after Issuer in Assertion
    # If tampering content: alter family name to PalagX AFTER signature was computed!
    final_family_name = "PalagX" if tamper_content else family_name

    final_attr_xml_parts = []
    if not empty_attributes:
        if not omit_person_id:
            final_attr_xml_parts.append(
                f'<saml2:Attribute FriendlyName="PersonIdentifier" Name="http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{person_identifier}</saml2:AttributeValue></saml2:Attribute>'
            )
        final_attr_xml_parts.append(
            f'<saml2:Attribute FriendlyName="CurrentFamilyName" Name="http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{final_family_name}</saml2:AttributeValue></saml2:Attribute>'
        )
        final_attr_xml_parts.append(
            f'<saml2:Attribute FriendlyName="CurrentGivenName" Name="http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{given_name}</saml2:AttributeValue></saml2:Attribute>'
        )
        if not omit_dob:
            final_attr_xml_parts.append(
                f'<saml2:Attribute FriendlyName="DateOfBirth" Name="http://eidas.europa.eu/attributes/naturalperson/DateOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{date_of_birth}</saml2:AttributeValue></saml2:Attribute>'
            )
    final_attributes_xml = "".join(final_attr_xml_parts)

    assertion_with_sig = (
        f'<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="{asrt_id}" IssueInstant="{t_issue}" Version="2.0">'
        f'<saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{asrt_issuer}</saml2:Issuer>'
        f'{signature_xml}'
        f'<saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{person_identifier}</saml2:NameID>'
        f'<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml2:SubjectConfirmationData InResponseTo="{in_response_to}" NotOnOrAfter="{t_noa}" Recipient="{destination}"></saml2:SubjectConfirmationData>'
        f'</saml2:SubjectConfirmation></saml2:Subject>'
        f'{conditions_xml}'
        f'<saml2:AuthnStatement AuthnInstant="{t_issue}">'
        f'<saml2:AuthnContext><saml2:AuthnContextClassRef>{loa}</saml2:AuthnContextClassRef></saml2:AuthnContext>'
        f'</saml2:AuthnStatement>'
        f'<saml2:AttributeStatement>{final_attributes_xml}</saml2:AttributeStatement>'
        f'</saml2:Assertion>'
    )

    if extra_outer_assertion:
        # XSW attack: Add an unsigned, spoofed assertion right before the signed assertion
        spoofed_assertion = (
            f'<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_spoofed_{os.urandom(4).hex()}" IssueInstant="{t_issue}" Version="2.0">'
            f'<saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{asrt_issuer}</saml2:Issuer>'
            f'<saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">ATTACKER/ADMIN</saml2:NameID></saml2:Subject>'
            f'{conditions_xml}'
            f'<saml2:AttributeStatement>'
            f'<saml2:Attribute FriendlyName="PersonIdentifier" Name="http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"><saml2:AttributeValue>ATTACKER/ADMIN</saml2:AttributeValue></saml2:Attribute>'
            f'</saml2:AttributeStatement>'
            f'</saml2:Assertion>'
        )
        assertions_payload = spoofed_assertion + assertion_with_sig
    else:
        assertions_payload = assertion_with_sig

    in_resp_attr = f' InResponseTo="{in_response_to}"' if in_response_to is not None else ''
    response_xml = (
        f'<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'Consent="urn:oasis:names:tc:SAML:2.0:consent:obtained" Destination="{destination}" '
        f'ID="{resp_id}"{in_resp_attr} IssueInstant="{t_issue}" Version="2.0">'
        f'<saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{resp_issuer}</saml2:Issuer>'
        f'<saml2p:Status><saml2p:StatusCode Value="{status_code}"></saml2p:StatusCode><saml2p:StatusMessage>{status_code}</saml2p:StatusMessage></saml2p:Status>'
        f'{assertions_payload}'
        f'</saml2p:Response>'
    )

    return response_xml

# =============================================================================
# STATIC CONSTANTS AND CONVENIENCE FIXTURES
# =============================================================================

AUTHN_REQUEST_XML = """<saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" AssertionConsumerServiceURL="http://sp.local:9090/SP/ReturnPage" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" Destination="http://peps.local:9090/PEPS/ServiceProvider" ForceAuthn="true" ID="_d048cb317813845b32a7a2b75f3bad59" IsPassive="false" IssueInstant="2026-10-02T12:00:00Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ProviderName="Bilanx-eIDAS-SP" Version="2.0">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://S-PEPS.gov.xx</saml2:Issuer>
    <saml2p:RequestedAuthnContext Comparison="minimum">
        <saml2:AuthnContextClassRef>http://eidas.europa.eu/LoA/substantial</saml2:AuthnContextClassRef>
    </saml2p:RequestedAuthnContext>
</saml2p:AuthnRequest>"""

# Dynamic default valid response (fresh timestamps)
RESPONSE_XML = build_signed_saml_response(
    response_id="_7POlm0XG6RUlrv67ArCVMe4cjc4IjIO5S2fe74-0yYbPRqbjJYl-v2hE4l6sqA2",
    assertion_id="_asrt_valid_default_2026",
    loa="http://eidas.europa.eu/LoA/substantial",
)

def get_valid_rsa_response(**kwargs) -> str:
    return build_signed_saml_response(algorithm="rsa-sha256", **kwargs)

def get_valid_ecdsa_response(**kwargs) -> str:
    return build_signed_saml_response(
        algorithm="ecdsa-sha256",
        key_pem=IDP_EC_KEY_PEM,
        cert_pem=IDP_EC_CERT_PEM,
        **kwargs
    )

def get_tampered_response(**kwargs) -> str:
    return build_signed_saml_response(tamper_content=True, **kwargs)

def get_tampered_sig_response(**kwargs) -> str:
    return build_signed_saml_response(tamper_signature_value=True, **kwargs)

def get_expired_response(**kwargs) -> str:
    past = datetime.now(timezone.utc) - timedelta(hours=2)
    return build_signed_saml_response(
        issue_instant=past - timedelta(minutes=10),
        not_before=past - timedelta(minutes=10),
        not_on_or_after=past,
        **kwargs
    )

def get_premature_response(**kwargs) -> str:
    future = datetime.now(timezone.utc) + timedelta(hours=2)
    return build_signed_saml_response(
        issue_instant=future,
        not_before=future,
        not_on_or_after=future + timedelta(hours=1),
        **kwargs
    )

def get_audience_mismatch_response(**kwargs) -> str:
    return build_signed_saml_response(audience="http://unauthorized-sp.eu", **kwargs)

def get_missing_dob_response(**kwargs) -> str:
    return build_signed_saml_response(omit_dob=True, **kwargs)

def get_missing_person_id_response(**kwargs) -> str:
    return build_signed_saml_response(omit_person_id=True, **kwargs)

def get_xsw_attack_response(**kwargs) -> str:
    return build_signed_saml_response(extra_outer_assertion=True, **kwargs)

def get_idp_error_response(**kwargs) -> str:
    return build_signed_saml_response(
        status_code="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
        **kwargs
    )

def get_missing_conditions_response(**kwargs) -> str:
    return build_signed_saml_response(omit_conditions=True, **kwargs)

def get_empty_attributes_response(**kwargs) -> str:
    return build_signed_saml_response(empty_attributes=True, **kwargs)

def get_untrusted_cert_response(**kwargs) -> str:
    return build_signed_saml_response(key_pem=SP_RSA_KEY_PEM, cert_pem=SP_RSA_CERT_PEM, **kwargs)

def get_untrusted_response_issuer_response(**kwargs) -> str:
    return build_signed_saml_response(response_issuer="http://rogue-idp.attacker.com/metadata", **kwargs)

def get_untrusted_assertion_issuer_response(**kwargs) -> str:
    return build_signed_saml_response(assertion_issuer="http://rogue-idp.attacker.com/metadata", **kwargs)

def get_minor_response(**kwargs) -> str:
    return build_signed_saml_response(
        date_of_birth="2012-06-15",
        loa="http://eidas.europa.eu/LoA/high",
        **kwargs
    )

def get_swiss_adult_response(**kwargs) -> str:
    return build_signed_saml_response(
        given_name="Heinrich",
        family_name="Keller",
        date_of_birth="1994-05-12",
        person_identifier="CHE-ZH-884210-HK",
        loa="http://eidas.europa.eu/LoA/substantial",
        **kwargs
    )

def get_eu_adult_response(**kwargs) -> str:
    return build_signed_saml_response(
        given_name="Clara",
        family_name="Schmidt",
        date_of_birth="1988-11-20",
        person_identifier="DEU-BER-991204-CS",
        loa="http://eidas.europa.eu/LoA/high",
        **kwargs
    )

def get_minor_luca_response(**kwargs) -> str:
    return build_signed_saml_response(
        given_name="Luca",
        family_name="Rossi",
        date_of_birth="2009-08-14",
        person_identifier="CHE-TI-110482-LR",
        loa="http://eidas.europa.eu/LoA/substantial",
        **kwargs
    )

def get_italian_adult_response(**kwargs) -> str:
    return build_signed_saml_response(
        given_name="Marco",
        family_name="Rossi",
        date_of_birth="1991-03-24",
        person_identifier="ITA-RM-339102-MR",
        loa="http://eidas.europa.eu/LoA/high",
        **kwargs
    )

def get_italian_adult_substantial_response(**kwargs) -> str:
    return build_signed_saml_response(
        given_name="Giulia",
        family_name="Bianchi",
        date_of_birth="1998-07-19",
        person_identifier="ITA-MI-772910-GB",
        loa="http://eidas.europa.eu/LoA/substantial",
        **kwargs
    )

def get_italian_minor_response(**kwargs) -> str:
    return build_signed_saml_response(
        given_name="Matteo",
        family_name="Russo",
        date_of_birth="2010-09-05",
        person_identifier="ITA-NA-551029-MR",
        loa="http://eidas.europa.eu/LoA/high",
        **kwargs
    )




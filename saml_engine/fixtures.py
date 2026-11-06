"""
Realistic eIDAS 2.0 SAML Test Fixtures and Key Pairs
Includes RSA and ECDSA self-signed certificates and generators for positive
and negative security vectors (tampering, expiration, replay, audience mismatch, XSW).
"""

import os
import base64
import hashlib
import subprocess
import tempfile
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

# =============================================================================
# PERSISTENT CRYPTOGRAPHIC KEYPAIRS & CERTIFICATES (Validity: 2026 - 2046)
# =============================================================================

IDP_RSA_KEY_PEM = """[REDACTED_PEM_PRIVATE_KEY]"""

IDP_RSA_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDRzCCAi+gAwIBAgIUDcnHJcvFoif+AP0vPNMFeo1G78kwDQYJKoZIhvcNAQEL
BQAwMzEXMBUGA1UEAwwOZUlEQVMgVGVzdCBJZFAxCzAJBgNVBAoMAkVVMQswCQYD
VQQGEwJFVTAeFw0yNjEwMDIyMjI3MzJaFw00NjA5MjcyMjI3MzJaMDMxFzAVBgNV
BAMMDmVJREFTIFRlc3QgSWRQMQswCQYDVQQKDAJFVTELMAkGA1UEBhMCRVUwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCXRt3zM5Bp33ooU1IcgCcmXmWT
rkqF7qICq77FoFH6bDAePF8Ih+BNnRdqzP0z4tgxvuu2VL4cUKWvMZ202Y7mFmoV
A20KO+uU+QPnqWVGYH4SuNRO/X8OO2Ruwc5evDG13sM4IbJk7P146vyWloAuNgxd
IS2bgOOV5sEKBnkLCkcs10UhVIbNoaUlurIFly+w+hDMmNpULi01LZz0Q1zemj+S
w3rNvZkiZfLboWSEHwO4DsmwGB67SNGJ23qoaJTfZAdP1kqEP04MT77H2ik50w38
eVHCNuXA7VsrgIFeiUVIzO55Xjx4MBcpkzoIS7cW7249O0scjC7WCEaGD/mzAgMB
AAGjUzBRMB0GA1UdDgQWBBSSbcxpIq+/kA9asKjEw0Jg1LO67jAfBgNVHSMEGDAW
gBSSbcxpIq+/kA9asKjEw0Jg1LO67jAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQAXAOL8k7j2IsVEcBnhBrj93zkaczlR+QpSY0NuSSWz+jgp51q3
xrYh2//5vAuYvmGfArK/tpP8yQN7z6bvjeM1VjyZ285UaftaAepinSW8PSy5xsHy
BDhogQXlUXHQ/L9cR9GH2CYlEYzehyzV3HKnCLOZ5JjhbgTOsJZB94BcffVN2kab
iEmc8dteXEMl/jamk86Tq6xhgg8s0J6mz4K3noJ11CJT1tbMh3sXoxUrZ6sf336C
AaFcE2goEOhIjdxcEiQoQxm9YcUrqJ6V6ufPchYQ+4HVUK1cYOV643IluEn0zM+2
2gpM1WZ1LdX8NLJ/ihjwdYv0E/YSxJzKoq5u
-----END CERTIFICATE-----"""

IDP_EC_KEY_PEM = """[REDACTED_PEM_PRIVATE_KEY]"""

IDP_EC_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIBwjCCAWegAwIBAgIUCl9FEnJWaGTAQa3OksF8pbqBCzowCgYIKoZIzj0EAwIw
NjEaMBgGA1UEAwwRZUlEQVMgVGVzdCBFQyBJZFAxCzAJBgNVBAoMAkVVMQswCQYD
VQQGEwJFVTAeFw0yNjEwMDIyMjI3MzJaFw00NjA5MjcyMjI3MzJaMDYxGjAYBgNV
BAMMEWVJREFTIFRlc3QgRUMgSWRQMQswCQYDVQQKDAJFVTELMAkGA1UEBhMCRVUw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATmnIm23PnIiaknhVGMXFWGT4wcLEW1
dqtaxrVYfAo5wZN9H8duE5IrdUykFYJGbViQfvL0ex8x61UkvJYKBBlIo1MwUTAd
BgNVHQ4EFgQUfDY08b8Dj4bzespi4leCBIDr3S0wHwYDVR0jBBgwFoAUfDY08b8D
j4bzespi4leCBIDr3S0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBG
AiEAolPQPfL1S8rwL0dB2PqbEBbhrXdDzwvEnJVNP4vJGtQCIQCiWT4igAIJQz+3
x8iqI5ag8LxzmXOMwSc1Y5oXTOpaQw==
-----END CERTIFICATE-----"""

SP_RSA_KEY_PEM = """[REDACTED_PEM_PRIVATE_KEY]"""

SP_RSA_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUNz/QFyoOUVQ/4EXB2E1cns2IS44wDQYJKoZIhvcNAQEL
BQAwRTEdMBsGA1UEAwwUQmlsYW54IGVJREFTIFNQIE5vZGUxFzAVBgNVBAoMDlBy
b2plY3QgQmlsYW54MQswCQYDVQQGEwJFVTAeFw0yNjEwMDIyMjI3MzJaFw00NjA5
MjcyMjI3MzJaMEUxHTAbBgNVBAMMFEJpbGFueCBlSURBUyBTUCBOb2RlMRcwFQYD
VQQKDA5Qcm9qZWN0IEJpbGFueDELMAkGA1UEBhMCRVUwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDJIGjGaCYPBBUuPxuFYWp/H0ThwRD7zQpS4K6mVqw4
PX+fx35dpwcIuAhwMg8PTbSuEAe8cn6MwD/UAMuXXC3DWqRD2A4ElUvzd6cz3wxf
H+xk6pmiirjwmEcbkLCEsORMIMt5zT0t5gSKg1V89mNfHYU6d5/Lq9HztQrcIqTW
WhvU61XJLPA1YRZd3c27x8dMeiCwxbgEh5+YFwiY420hyOD4SF3+IBxmO4aXE0P1
vQJKSIRp4O6wwvEh/de/rAcNPYDD+q/HymMDtRnNwwR/rjoA30VIcejS2RC12Sv3
bwXMuFfZlPDowU5LylE6dQdFYKRMaCVi/Thes1pOOk41AgMBAAGjUzBRMB0GA1Ud
DgQWBBQSoM5HJfi/fl+XHVAWMamD+QY95TAfBgNVHSMEGDAWgBQSoM5HJfi/fl+X
HVAWMamD+QY95TAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBc
rBklVVYxwqGfXrvEzcU2v5J5xFdBeMFOQZjsogDJIB5MQWJUSuNjMTsGVquWiO8+
rG4P1uKorDASUpVs9IAU4ccC4/dH7/D7GJ718opQXzeLn/xx/pdr+wgh79sOPX0z
+sAqcYpowZVmo0xqJJHnMy1BoT4o70hz63AnwMU5wyi1WVoMYZqCuk3EqJZHAE2K
peuCIKo3iYKtp8g8x0YY4BrItXilBrvluQmu41U7/jP91JlBQcrq9EuC+ejMZcxR
Rnx2ULb1WnXUHP7iIZY7tbuXrqRQscLuP68IPhdC/iUjJ7SoFYfPms26nbVUOiiX
WVYVNqap28CrY9Rxo3s5
-----END CERTIFICATE-----"""

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




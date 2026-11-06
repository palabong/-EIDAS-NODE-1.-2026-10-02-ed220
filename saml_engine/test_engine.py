import os
import sys
import unittest
from datetime import datetime, timezone, timedelta

# Ensure parent directory and saml_engine directory are in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from saml_engine.engine import (
    SAMLValidationEngine,
    SAMLAuthnRequestGenerator,
    SAMLMetadataGenerator,
    SecureXMLParser,
    XMLSignatureVerifier,
)
from saml_engine.mapping import SAMLToPOSMapper
from saml_engine.fixtures import (
    AUTHN_REQUEST_XML,
    RESPONSE_XML,
    SP_RSA_CERT_PEM,
    IDP_RSA_CERT_PEM,
    IDP_EC_CERT_PEM,
    get_valid_rsa_response,
    get_valid_ecdsa_response,
    get_tampered_response,
    get_tampered_sig_response,
    get_expired_response,
    get_premature_response,
    get_audience_mismatch_response,
    get_missing_dob_response,
    get_missing_person_id_response,
    get_xsw_attack_response,
    get_idp_error_response,
    get_missing_conditions_response,
    get_empty_attributes_response,
    get_untrusted_cert_response,
    get_untrusted_response_issuer_response,
    get_untrusted_assertion_issuer_response,
    get_minor_response,
)

class TestSAMLEngineHardened(unittest.TestCase):
    def setUp(self):
        default_cache = SAMLValidationEngine.DEFAULT_CACHE_FILE
        if os.path.exists(default_cache):
            try:
                os.remove(default_cache)
            except Exception:
                pass

        self.allowed_issuers = [
            "http://S-PEPS.gov.xx",
            "http://cef-eid-build-1:8080/EidasNode/ServiceMetadata",
            "http://sp.local:9090/SP/Metadata",
            "urn:bilanx:eidas:sp",
        ]
        self.allowed_destinations = [
            "http://peps.local:9090/PEPS/ServiceProvider",
            "http://cef-eid-build-1:8080/EidasNode/ColleagueResponse",
            "http://sp.local:9090/SP/ReturnPage",
            "http://localhost:3000/saml/acs",
        ]
        # Strictly in-memory cache for unit tests: 100% idempotent and isolated
        self.engine = SAMLValidationEngine(
            allowed_issuers=self.allowed_issuers,
            allowed_destinations=self.allowed_destinations,
            trusted_certificates=[IDP_RSA_CERT_PEM, IDP_EC_CERT_PEM],
            clock_skew_seconds=300,
            replay_ttl_seconds=600,
            persist_cache=False,
            cache_file=None,
        )

    def tearDown(self):
        default_cache = SAMLValidationEngine.DEFAULT_CACHE_FILE
        if os.path.exists(default_cache):
            try:
                os.remove(default_cache)
            except Exception:
                pass

    def test_01_authn_request_happy_path_static(self):
        """Validates that a standard AuthnRequest parses successfully."""
        res = self.engine.validate_authn_request(AUTHN_REQUEST_XML)
        self.assertTrue(res.is_valid, f"Failed parsing static AuthnRequest: {res.error_message}")
        self.assertEqual(res.claims["issuer"], "http://S-PEPS.gov.xx")
        self.assertEqual(res.claims["level_of_assurance"], "http://eidas.europa.eu/LoA/substantial")

        pos_context = SAMLToPOSMapper.map_claims_to_pos(res.claims)
        self.assertEqual(pos_context.role, "STORE_MANAGER")
        self.assertEqual(pos_context.level_of_assurance, "SUBSTANTIAL")
        self.assertIn("SHIFT_START", pos_context.permissions)

    def test_02_authn_request_generator(self):
        """Verifies that SAMLAuthnRequestGenerator builds valid eIDAS AuthnRequest XML."""
        generator = SAMLAuthnRequestGenerator(
            sp_entity_id="http://sp.local:9090/SP/Metadata",
            acs_url="http://sp.local:9090/SP/ReturnPage",
            destination_url="http://peps.local:9090/PEPS/ServiceProvider",
            sp_type="public",
        )
        req_id, xml, b64 = generator.generate(loa="high")
        self.assertTrue(req_id.startswith("_authn_"))
        self.assertIn('xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"', xml)
        self.assertIn('xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"', xml)
        self.assertIn("<eidas:SPType>public</eidas:SPType>", xml)
        self.assertIn("http://eidas.europa.eu/LoA/high", xml)
        self.assertIn("http://sp.local:9090/SP/Metadata", xml)
        self.assertTrue(len(b64) > 100)

        # Re-validate generated AuthnRequest with engine
        res = self.engine.validate_authn_request(xml)
        self.assertTrue(res.is_valid, f"Generated AuthnRequest failed validation: {res.error_message}")
        self.assertEqual(res.claims["level_of_assurance"], "http://eidas.europa.eu/LoA/high")

    def test_03_metadata_generator(self):
        """Verifies that SAMLMetadataGenerator generates valid SAML 2.0 EntityDescriptor XML."""
        generator = SAMLMetadataGenerator(
            sp_entity_id="http://sp.local:9090/SP/Metadata",
            acs_url="http://sp.local:9090/SP/ReturnPage",
            signing_cert_pem=SP_RSA_CERT_PEM,
        )
        xml = generator.generate()
        self.assertIn("<md:EntityDescriptor", xml)
        self.assertIn('entityID="http://sp.local:9090/SP/Metadata"', xml)
        self.assertIn("<md:SPSSODescriptor", xml)
        self.assertIn('<md:KeyDescriptor use="signing">', xml)
        self.assertIn('<md:KeyDescriptor use="encryption">', xml)
        self.assertIn('Location="http://sp.local:9090/SP/ReturnPage"', xml)

    def test_04_valid_signed_response_rsa(self):
        """End-to-end happy path validation of RSA-SHA256 signed eIDAS response."""
        xml = get_valid_rsa_response()
        res = self.engine.validate_response(xml)
        self.assertTrue(res.is_valid, f"Valid RSA Response failed: {res.error_message}")
        self.assertEqual(res.claims["status_code"], "urn:oasis:names:tc:SAML:2.0:status:Success")
        self.assertEqual(res.pos_context.user_id, "IT/IT/TINIT-PLGDNL85M01H501Z")
        self.assertEqual(res.pos_context.family_name, "Palagi")
        self.assertEqual(res.pos_context.given_name, "Daniele")
        self.assertEqual(res.pos_context.date_of_birth, "1985-08-01")
        self.assertTrue(res.pos_context.is_over_18)
        self.assertEqual(res.pos_context.role, "STORE_MANAGER")
        self.assertIn("MANAGER_OVERRIDE", res.pos_context.permissions)

    def test_05_valid_signed_response_ecdsa(self):
        """End-to-end happy path validation of ECDSA-SHA256 signed eIDAS response."""
        xml = get_valid_ecdsa_response()
        res = self.engine.validate_response(xml)
        self.assertTrue(res.is_valid, f"Valid ECDSA Response failed: {res.error_message}")
        self.assertEqual(res.claims["status_code"], "urn:oasis:names:tc:SAML:2.0:status:Success")
        self.assertEqual(res.pos_context.user_id, "IT/IT/TINIT-PLGDNL85M01H501Z")
        self.assertTrue(res.pos_context.is_over_18)

    def test_06_signature_tampering_content(self):
        """Verifies that modifying assertion content (e.g. surname) invalidates digest."""
        xml = get_tampered_response()
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid)
        self.assertIn("Digest Mismatch", res.error_message)

    def test_07_signature_tampering_sig_bytes(self):
        """Verifies that altering ds:SignatureValue bytes fails verification."""
        xml = get_tampered_sig_response()
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid)
        self.assertIn("Cryptographic Verification Failed", res.error_message)

    def test_08_expired_assertion(self):
        """Verifies that an assertion whose NotOnOrAfter is in the past is rejected."""
        xml = get_expired_response()
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid)
        self.assertIn("has expired", res.error_message)

    def test_09_premature_assertion(self):
        """Verifies that an assertion whose NotBefore is in the future is rejected."""
        xml = get_premature_response()
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid)
        self.assertIn("is premature", res.error_message)

    def test_10_replay_attack_prevention(self):
        """Ensures that the same assertion ID cannot be processed more than once."""
        xml = get_valid_rsa_response()
        res1 = self.engine.validate_response(xml)
        self.assertTrue(res1.is_valid)

        res2 = self.engine.validate_response(xml)
        self.assertFalse(res2.is_valid)
        self.assertIn("Replay Attack Detected", res2.error_message)

    def test_11_audience_mismatch_rejection(self):
        """Verifies that an assertion with unauthorized Audience is rejected."""
        xml = get_audience_mismatch_response()
        res = self.engine.validate_response(xml, expected_audience="http://sp.local:9090/SP/Metadata")
        self.assertFalse(res.is_valid)
        self.assertIn("Audience Mismatch", res.error_message)

    def test_12_unauthorized_destination_rejection(self):
        """Verifies that an unauthorized destination URL is rejected."""
        xml = get_valid_rsa_response(destination="http://malicious-gateway.org/hack")
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid)
        self.assertIn("Unauthorized Destination", res.error_message)

    def test_13_missing_mandatory_eidas_dob(self):
        """Verifies that omitting DateOfBirth triggers validation rejection."""
        xml = get_missing_dob_response()
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid)
        self.assertIn("Missing mandatory eIDAS attribute: DateOfBirth", res.error_message)

    def test_14_missing_mandatory_eidas_person_id(self):
        """Verifies that omitting PersonIdentifier triggers validation rejection."""
        xml = get_missing_person_id_response()
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid)
        self.assertIn("Missing mandatory eIDAS attribute: PersonIdentifier", res.error_message)

    def test_15_xml_bomb_and_dtd_defense(self):
        """Verifies that inline entity declarations and DTDs trigger immediate safety rejection."""
        malicious_xml = """<?xml version="1.0"?>
        <!DOCTYPE lolz [
         <!ENTITY lol "lol">
         <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
        ]>
        <saml2p:AuthnRequest ID="_fakeID" Destination="http://peps.local:9090/PEPS/ServiceProvider" IssueInstant="2026-10-02T12:00:00Z">
            <saml2:Issuer>http://S-PEPS.gov.xx</saml2:Issuer>
        </saml2p:AuthnRequest>"""
        res = self.engine.validate_authn_request(malicious_xml)
        self.assertFalse(res.is_valid)
        self.assertIn("Security Violation", res.error_message)

    def test_16_xsw_attack_mitigation(self):
        """Verifies that XML Signature Wrapping (multiple assertions / wrapper attack) is detected and blocked."""
        xml = get_xsw_attack_response()
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid)
        self.assertIn("XSW Defense Violation", res.error_message)

    def test_17_idp_error_status(self):
        """Verifies that non-Success status codes (e.g. AuthnFailed) return validation failure."""
        xml = get_idp_error_response()
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid)
        self.assertIn("SAML IdP Error", res.error_message)

    def test_18_eidas_age_gate_calculation(self):
        """Verifies age calculation and demographic predicates (is_over_18, is_over_21)."""
        # Person born in 2012 (under 18 in 2026)
        claims_minor = {
            "attributes": {
                "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier": "IT/IT/MINOR-01",
                "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName": "Rossi",
                "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName": "Luca",
                "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth": "2012-06-15",
            },
            "level_of_assurance": "http://eidas.europa.eu/LoA/low"
        }
        pos_minor = SAMLToPOSMapper.map_claims_to_pos(claims_minor)
        self.assertEqual(pos_minor.user_id, "IT/IT/MINOR-01")
        self.assertFalse(pos_minor.is_over_18)
        self.assertFalse(pos_minor.is_over_21)
        self.assertEqual(pos_minor.role, "CASHIER")

        # Person born in 1990 (adult)
        claims_adult = {
            "attributes": {
                "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier": "IT/IT/ADULT-01",
                "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName": "Palagi",
                "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName": "Daniele",
                "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth": "1990-05-14",
            },
            "level_of_assurance": "http://eidas.europa.eu/LoA/high"
        }
        pos_adult = SAMLToPOSMapper.map_claims_to_pos(claims_adult)
        self.assertTrue(pos_adult.is_over_18)
        self.assertTrue(pos_adult.is_over_21)
        self.assertEqual(pos_adult.role, "STORE_MANAGER")
        self.assertIn("DRAWER_ACCESS", pos_adult.permissions)

    def test_19_missing_conditions_rejection(self):
        """Verifies that an assertion omitting saml2:Conditions is rejected unconditionally."""
        xml = get_missing_conditions_response()
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid)
        self.assertIn("Missing mandatory <saml2:Conditions> element", res.error_message)

    def test_20_untrusted_idp_certificate_rejection(self):
        """Verifies that an assertion signed by an untrusted certificate is rejected."""
        xml = get_untrusted_cert_response()
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid)
        self.assertIn("Untrusted IdP Certificate", res.error_message)

    def test_21_untrusted_response_issuer_rejection(self):
        """Verifies that a SAML Response with untrusted Response-level Issuer is rejected."""
        xml = get_untrusted_response_issuer_response()
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid)
        self.assertIn("Unauthorized Response Issuer", res.error_message)

    def test_22_untrusted_assertion_issuer_rejection(self):
        """Verifies that a SAML Assertion with untrusted Assertion-level Issuer is rejected."""
        xml = get_untrusted_assertion_issuer_response()
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid)
        self.assertIn("Unauthorized Assertion Issuer", res.error_message)

    def test_23_empty_attributes_statement_rejection(self):
        """Verifies that an assertion with empty AttributeStatement is rejected."""
        xml = get_empty_attributes_response()
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid)
        self.assertIn("Missing mandatory eIDAS attribute", res.error_message)

    def test_24_in_response_to_correlation(self):
        """Verifies InResponseTo correlation checks against expected_request_id."""
        req_id = "_expected_req_corr_98765"
        xml = get_valid_rsa_response(in_response_to=req_id)
        # Matching expected_request_id passes
        res_ok = self.engine.validate_response(xml, expected_request_id=req_id)
        self.assertTrue(res_ok.is_valid, f"Expected matching InResponseTo to pass: {res_ok.error_message}")

        # Mismatched expected_request_id fails
        engine2 = SAMLValidationEngine(
            allowed_issuers=self.allowed_issuers,
            allowed_destinations=self.allowed_destinations,
            trusted_certificates=[IDP_RSA_CERT_PEM, IDP_EC_CERT_PEM],
            persist_cache=False,
        )
        res_mismatch = engine2.validate_response(xml, expected_request_id="_different_req_00000")
        self.assertFalse(res_mismatch.is_valid)
        self.assertIn("InResponseTo Mismatch", res_mismatch.error_message)

    def test_25_minor_retail_role_protection_high_loa(self):
        """Verifies that minors (<18) are never granted STORE_MANAGER even with HIGH LoA."""
        xml = get_minor_response()
        res = self.engine.validate_response(xml)
        self.assertTrue(res.is_valid, f"Valid minor response failed: {res.error_message}")
        self.assertFalse(res.pos_context.is_over_18)
        self.assertEqual(res.pos_context.level_of_assurance, "HIGH")
        # Role must be restricted to CASHIER
        self.assertEqual(res.pos_context.role, "CASHIER")
        self.assertNotIn("MANAGER_OVERRIDE", res.pos_context.permissions)
        self.assertNotIn("DRAWER_ACCESS", res.pos_context.permissions)

    def test_26_disk_cache_persistence_and_flock(self):
        """Verifies disk cache persistence, flock file locking, and cross-instance anti-replay."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            cache_path = os.path.join(td, "shared_replay_cache.json")
            eng1 = SAMLValidationEngine(
                allowed_issuers=self.allowed_issuers,
                allowed_destinations=self.allowed_destinations,
                trusted_certificates=[IDP_RSA_CERT_PEM, IDP_EC_CERT_PEM],
                cache_file=cache_path,
                persist_cache=True,
            )
            eng2 = SAMLValidationEngine(
                allowed_issuers=self.allowed_issuers,
                allowed_destinations=self.allowed_destinations,
                trusted_certificates=[IDP_RSA_CERT_PEM, IDP_EC_CERT_PEM],
                cache_file=cache_path,
                persist_cache=True,
            )

            xml = get_valid_rsa_response()
            res1 = eng1.validate_response(xml)
            self.assertTrue(res1.is_valid, f"First response should be valid: {res1.error_message}")

            # eng2 must detect replay via locked disk cache file
            res2 = eng2.validate_response(xml)
            self.assertFalse(res2.is_valid)
            self.assertIn("Replay Attack Detected", res2.error_message)

    def test_27_malformed_base64_signature_value(self):
        """Verifies that non-base64 garbage or corrupted padding in ds:SignatureValue fails verification."""
        xml = get_valid_rsa_response()
        corrupted_xml = xml.replace("</ds:SignatureValue>", "???!!!</ds:SignatureValue>")
        res = self.engine.validate_response(corrupted_xml)
        self.assertFalse(res.is_valid)
        self.assertIn("Cryptographic Verification Failed", res.error_message)

    def test_28_multiple_signature_elements_rejection(self):
        """Verifies that injecting a duplicate ds:Signature element into an Assertion is blocked as XSW attack."""
        xml = get_valid_rsa_response()
        # Duplicate the ds:Signature element inside Assertion
        sig_start = xml.find("<ds:Signature")
        sig_end = xml.find("</ds:Signature>") + len("</ds:Signature>")
        sig_block = xml[sig_start:sig_end]
        tampered_xml = xml[:sig_end] + sig_block + xml[sig_end:]
        res = self.engine.validate_response(tampered_xml)
        self.assertFalse(res.is_valid)
        self.assertIn("XSW Defense Violation", res.error_message)
        self.assertIn("Multiple ds:Signature elements", res.error_message)

    def test_29_multiple_reference_elements_rejection(self):
        """Verifies that injecting a second ds:Reference in ds:SignedInfo is blocked as XSW attack."""
        xml = get_valid_rsa_response()
        ref_start = xml.find("<ds:Reference")
        ref_end = xml.find("</ds:Reference>") + len("</ds:Reference>")
        ref_block = xml[ref_start:ref_end]
        tampered_xml = xml[:ref_end] + ref_block + xml[ref_end:]
        res = self.engine.validate_response(tampered_xml)
        self.assertFalse(res.is_valid)
        self.assertIn("XSW Defense Violation", res.error_message)
        self.assertIn("Expected exactly 1 ds:Reference", res.error_message)

    def test_30_multiple_digest_values_rejection(self):
        """Verifies that injecting a duplicate ds:DigestValue in ds:Reference is blocked as XSW attack."""
        xml = get_valid_rsa_response()
        dv_start = xml.find("<ds:DigestValue>")
        dv_end = xml.find("</ds:DigestValue>") + len("</ds:DigestValue>")
        dv_block = xml[dv_start:dv_end]
        tampered_xml = xml[:dv_end] + dv_block + xml[dv_end:]
        res = self.engine.validate_response(tampered_xml)
        self.assertFalse(res.is_valid)
        self.assertIn("XSW Defense Violation", res.error_message)
        self.assertIn("Expected exactly 1 ds:DigestValue", res.error_message)

    def test_31_doctype_split_newline_mixed_case(self):
        """Verifies that a well-formed DOCTYPE declaration is rejected with Security Violation."""
        payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        res = self.engine.validate_authn_request(payload)
        self.assertFalse(res.is_valid)
        self.assertIn("Security Violation", res.error_message)

    def test_32_doctype_utf16le_with_bom(self):
        """Verifies that the same payload encoded in UTF-16LE with BOM is rejected with Security Violation."""
        import codecs
        payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        utf16le_payload = codecs.BOM_UTF16_LE + payload.encode("utf-16le")
        res = self.engine.validate_authn_request(utf16le_payload)
        self.assertFalse(res.is_valid)
        self.assertIn("Security Violation", res.error_message)

if __name__ == "__main__":
    unittest.main()

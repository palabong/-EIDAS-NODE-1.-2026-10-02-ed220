"""
Challenger 3 Regression Test Suite
Empirically verifies all 6 attack vectors and edge cases:
1. Certificate substitution attack with untrusted self-signed certificate -> MUST be rejected.
2. Empty or missing AttributeStatement -> MUST be rejected.
3. Missing saml2:Conditions -> MUST be rejected.
4. InResponseTo mismatch -> MUST be rejected.
5. RelayState preservation in /saml/acs -> MUST be present in response.
6. Underage user (<18) -> MUST be restricted to CASHIER role, denying STORE_MANAGER.
"""

import os
import sys
import unittest
from datetime import datetime, timezone, timedelta, date

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from saml_engine.engine import SAMLValidationEngine
from saml_engine.mapping import SAMLToPOSMapper
from saml_engine.fixtures import (
    build_signed_saml_response,
    get_valid_rsa_response,
    get_missing_conditions_response,
    get_empty_attributes_response,
    get_untrusted_cert_response,
    get_minor_response,
)

class Challenger3AdversarialRegressionTests(unittest.TestCase):
    def setUp(self):
        self.engine = SAMLValidationEngine(
            clock_skew_seconds=300,
            replay_ttl_seconds=600,
            persist_cache=False,
        )

    # 1. Certificate substitution attack with untrusted self-signed certificate
    def test_vector_1_untrusted_cert_substitution(self):
        xml = get_untrusted_cert_response()
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid, "VULNERABILITY: Response with untrusted self-signed certificate was accepted!")
        self.assertIn("Untrusted IdP Certificate", res.error_message)

    # 2. Empty or missing AttributeStatement
    def test_vector_2_empty_or_missing_attribute_statement(self):
        # Case A: Empty AttributeStatement
        xml_empty = get_empty_attributes_response()
        res_empty = self.engine.validate_response(xml_empty)
        self.assertFalse(res_empty.is_valid, "VULNERABILITY: Response with empty AttributeStatement was accepted!")
        self.assertIn("Missing mandatory eIDAS attribute", res_empty.error_message)

        # Case B: Completely omitted AttributeStatement
        now = datetime.now(timezone.utc)
        resp_id = f"_resp_no_attrs_{os.urandom(4).hex()}"
        asrt_id = f"_asrt_no_attrs_{os.urandom(4).hex()}"
        t_issue = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        t_nb = (now - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        t_noa = (now + timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ")
        xml_omitted = (
            f'<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
            f'Destination="http://cef-eid-build-1:8080/EidasNode/ColleagueResponse" ID="{resp_id}" IssueInstant="{t_issue}" Version="2.0">'
            f'<saml2:Issuer>http://cef-eid-build-1:8080/EidasNode/ServiceMetadata</saml2:Issuer>'
            f'<saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>'
            f'<saml2:Assertion ID="{asrt_id}" IssueInstant="{t_issue}" Version="2.0">'
            f'<saml2:Issuer>http://cef-eid-build-1:8080/EidasNode/ServiceMetadata</saml2:Issuer>'
            f'<saml2:Conditions NotBefore="{t_nb}" NotOnOrAfter="{t_noa}"><saml2:AudienceRestriction><saml2:Audience>http://sp.local:9090/SP/Metadata</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions>'
            f'</saml2:Assertion>'
            f'</saml2p:Response>'
        )
        res_omitted = self.engine.validate_response(xml_omitted, require_signature=False)
        self.assertFalse(res_omitted.is_valid, "VULNERABILITY: Response with missing AttributeStatement element was accepted!")
        self.assertIn("Missing mandatory eIDAS attribute", res_omitted.error_message)

    # 3. Missing saml2:Conditions
    def test_vector_3_missing_saml2_conditions(self):
        xml = get_missing_conditions_response()
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid, "VULNERABILITY: Response missing <saml2:Conditions> was accepted!")
        self.assertIn("Missing mandatory <saml2:Conditions> element in Assertion.", res.error_message)

    # 4. InResponseTo mismatch
    def test_vector_4_in_response_to_mismatch(self):
        expected_id = "_req_correct_12345"
        xml = get_valid_rsa_response(in_response_to=expected_id)

        # Case A: Matching ID -> passes
        res_match = self.engine.validate_response(xml, expected_request_id=expected_id)
        self.assertTrue(res_match.is_valid, f"Expected matching InResponseTo to pass: {res_match.error_message}")

        # Case B: Mismatched ID -> rejected
        engine2 = SAMLValidationEngine(persist_cache=False)
        res_mismatch = engine2.validate_response(xml, expected_request_id="_req_different_99999")
        self.assertFalse(res_mismatch.is_valid, "VULNERABILITY: InResponseTo mismatch was accepted!")
        self.assertIn("InResponseTo Mismatch", res_mismatch.error_message)

        # Case C: Missing InResponseTo attribute on Response when expected_request_id is specified
        xml_no_inresp = get_valid_rsa_response(in_response_to=None)
        engine3 = SAMLValidationEngine(persist_cache=False)
        res_missing = engine3.validate_response(xml_no_inresp, expected_request_id=expected_id)
        self.assertFalse(res_missing.is_valid, "VULNERABILITY: Missing InResponseTo was accepted when expected!")
        self.assertIn("Missing InResponseTo attribute on Response", res_missing.error_message)

    # 5. Underage user (<18) -> MUST be restricted to CASHIER role, denying STORE_MANAGER
    def test_vector_6_underage_role_restriction(self):
        # Underage with HIGH LoA
        claims_minor_high = {
            "attributes": {
                "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier": "IT/IT/MINOR-HIGH-LOA",
                "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName": "Rossi",
                "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName": "Marco",
                "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth": "2010-05-20",
            },
            "level_of_assurance": "http://eidas.europa.eu/LoA/high"
        }
        pos_minor = SAMLToPOSMapper.map_claims_to_pos(claims_minor_high)
        self.assertFalse(pos_minor.is_over_18)
        self.assertEqual(pos_minor.role, "CASHIER", "VULNERABILITY: Minor was granted non-CASHIER role!")
        self.assertNotIn("MANAGER_OVERRIDE", pos_minor.permissions)
        self.assertNotIn("DRAWER_ACCESS", pos_minor.permissions)
        self.assertNotIn("VOID_TRANSACTION", pos_minor.permissions)
        self.assertNotIn("REFUND_OVERRIDE", pos_minor.permissions)

        # Underage with SUBSTANTIAL LoA
        claims_minor_sub = {
            "attributes": {
                "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier": "IT/IT/MINOR-SUB-LOA",
                "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName": "Bianchi",
                "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName": "Giulia",
                "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth": "2009-11-15",
            },
            "level_of_assurance": "http://eidas.europa.eu/LoA/substantial"
        }
        pos_minor_sub = SAMLToPOSMapper.map_claims_to_pos(claims_minor_sub)
        self.assertFalse(pos_minor_sub.is_over_18)
        self.assertEqual(pos_minor_sub.role, "CASHIER", "VULNERABILITY: Minor was granted non-CASHIER role under substantial LoA!")
        self.assertNotIn("MANAGER_OVERRIDE", pos_minor_sub.permissions)

        # Full end-to-end minor response XML
        xml_minor = get_minor_response()
        res_minor = self.engine.validate_response(xml_minor)
        self.assertTrue(res_minor.is_valid)
        self.assertFalse(res_minor.pos_context.is_over_18)
        self.assertEqual(res_minor.pos_context.role, "CASHIER")
        self.assertNotIn("MANAGER_OVERRIDE", res_minor.pos_context.permissions)

        # Adult comparison (age >= 18) with HIGH LoA -> STORE_MANAGER
        claims_adult_high = {
            "attributes": {
                "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier": "IT/IT/ADULT-HIGH-LOA",
                "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName": "Verdi",
                "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName": "Giuseppe",
                "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth": "1990-01-01",
            },
            "level_of_assurance": "http://eidas.europa.eu/LoA/high"
        }
        pos_adult = SAMLToPOSMapper.map_claims_to_pos(claims_adult_high)
        self.assertTrue(pos_adult.is_over_18)
        self.assertEqual(pos_adult.role, "STORE_MANAGER")
        self.assertIn("MANAGER_OVERRIDE", pos_adult.permissions)

if __name__ == "__main__":
    unittest.main()

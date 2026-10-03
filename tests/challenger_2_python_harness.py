"""
Challenger 2 Empirical Verification Test Suite - Python SAML Engine & Demographic Gating
Tests:
1. Missing mandatory eIDAS attributes (PersonIdentifier, DateOfBirth, CurrentFamilyName, CurrentGivenName, and empty AttributeStatement)
2. Non-ASCII / UTF-8 multi-byte name handling (René, Müller, García, Østergård, Cyrillic, Chinese)
3. Age calculation corner cases (turned 18 today, turns 18 tomorrow, leap-year Feb 29)
4. Underage rejection (age 16 -> is_over_18=False)
5. AuthnRequest parameters and LoA mappings (low, substantial, high, unrecognized)
6. Replay cache disk pollution / isolation
"""

import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone, date, timedelta

# Ensure saml_engine in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from saml_engine.engine import (
    SAMLValidationEngine,
    SAMLAuthnRequestGenerator,
    SecureXMLParser,
    XMLSignatureVerifier,
)
from saml_engine.mapping import SAMLToPOSMapper
from saml_engine.fixtures import (
    build_signed_saml_response,
    IDP_RSA_KEY_PEM,
    IDP_RSA_CERT_PEM,
)

class Challenger2PythonTests(unittest.TestCase):
    def setUp(self):
        # Use an isolated temp cache file for replay to prevent cross-test contamination
        self.temp_dir = tempfile.mkdtemp()
        self.engine = SAMLValidationEngine(
            clock_skew_seconds=300,
            replay_ttl_seconds=600,
        )
        self.engine._cache_file = os.path.join(self.temp_dir, "isolated_replay_cache.json")
        self.engine.processed_ids = {}

    def tearDown(self):
        if os.path.exists(self.engine._cache_file):
            try:
                os.remove(self.engine._cache_file)
            except OSError:
                pass

    # =========================================================================
    # 1. Age Calculation Corner Cases & Demographic Gating
    # =========================================================================

    def test_age_turned_18_today(self):
        """Subject turned 18 exactly today: age=18, is_over_18=True, is_over_21=False"""
        ref_date = date(2026, 10, 2)
        dob = "2008-10-02"
        age, is_over_18, is_over_21 = SAMLToPOSMapper.calculate_age(dob, reference_date=ref_date)
        self.assertEqual(age, 18, f"Expected age 18 on 18th birthday, got {age}")
        self.assertTrue(is_over_18, "Expected is_over_18 to be True on 18th birthday")
        self.assertFalse(is_over_21, "Expected is_over_21 to be False on 18th birthday")

    def test_age_turns_18_tomorrow(self):
        """Subject turns 18 tomorrow: age=17, is_over_18=False, is_over_21=False"""
        ref_date = date(2026, 10, 2)
        dob = "2008-10-03"
        age, is_over_18, is_over_21 = SAMLToPOSMapper.calculate_age(dob, reference_date=ref_date)
        self.assertEqual(age, 17, f"Expected age 17 the day before 18th birthday, got {age}")
        self.assertFalse(is_over_18, "Expected is_over_18 to be False the day before 18th birthday")
        self.assertFalse(is_over_21, "Expected is_over_21 to be False")

    def test_age_leap_year_birthday_feb29(self):
        """Leap-year birthday (Feb 29, 2008): tested on Feb 28 vs Mar 1 in non-leap year 2026"""
        dob = "2008-02-29"
        
        # Day before anniversary in non-leap year: 2026-02-28
        ref_feb28 = date(2026, 2, 28)
        age_28, over18_28, _ = SAMLToPOSMapper.calculate_age(dob, reference_date=ref_feb28)
        self.assertEqual(age_28, 17, f"Expected age 17 on 2026-02-28, got {age_28}")
        self.assertFalse(over18_28, "Expected is_over_18 to be False on 2026-02-28")

        # Anniversary in non-leap year (March 1st): 2026-03-01
        ref_mar01 = date(2026, 3, 1)
        age_01, over18_01, _ = SAMLToPOSMapper.calculate_age(dob, reference_date=ref_mar01)
        self.assertEqual(age_01, 18, f"Expected age 18 on 2026-03-01, got {age_01}")
        self.assertTrue(over18_01, "Expected is_over_18 to be True on 2026-03-01")

        # In a leap year on Feb 29 (e.g. 2028-02-29) -> 20th birthday
        ref_leap28 = date(2028, 2, 29)
        age_leap, over18_leap, over21_leap = SAMLToPOSMapper.calculate_age(dob, reference_date=ref_leap28)
        self.assertEqual(age_leap, 20, f"Expected age 20 on 2028-02-29, got {age_leap}")
        self.assertTrue(over18_leap)
        self.assertFalse(over21_leap)

    def test_underage_rejection_age_16(self):
        """Minor subject (age 16): is_over_18 must evaluate to False"""
        ref_date = date(2026, 10, 2)
        dob = "2010-06-15"
        age, is_over_18, is_over_21 = SAMLToPOSMapper.calculate_age(dob, reference_date=ref_date)
        self.assertEqual(age, 16)
        self.assertFalse(is_over_18)
        self.assertFalse(is_over_21)

        # Full mapper check
        claims = {
            "attributes": {
                "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier": "IT/IT/MINOR-TEST",
                "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName": "Verdi",
                "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName": "Giuseppe",
                "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth": dob,
            },
            "level_of_assurance": "http://eidas.europa.eu/LoA/substantial"
        }
        pos = SAMLToPOSMapper.map_claims_to_pos(claims)
        self.assertEqual(pos.age, 16)
        self.assertFalse(pos.is_over_18)
        self.assertFalse(pos.is_over_21)

    def test_age_malformed_inputs(self):
        """Malformed DOB strings should gracefully return (None, None, None)"""
        malformed = ["", "invalid-date", "2008-02-30", "15/06/2008", "2008/10/02", None]
        for m in malformed:
            age, is_18, is_21 = SAMLToPOSMapper.calculate_age(m)
            self.assertIsNone(age, f"Expected None age for {m}, got {age}")
            self.assertIsNone(is_18, f"Expected None is_18 for {m}")
            self.assertIsNone(is_21, f"Expected None is_21 for {m}")

    # =========================================================================
    # 2. Non-ASCII / UTF-8 Multi-byte Characters in Names
    # =========================================================================

    def test_utf8_names_rene_muller_garcia_ostergard(self):
        """End-to-end XML signing and verification of multi-byte UTF-8 names"""
        test_cases = [
            ("René", "Müller", "FR/FR/RENE-MULLER-01"),
            ("García", "Østergård", "ES/DK/GARCIA-OSTERGARD-02"),
            ("Παπαδόπουλος", "Γεώργιος", "GR/GR/PAPADOPOULOS-03"),
            ("Иванов", "Алексей", "BG/BG/IVANOV-04"),
            ("李", "华", "EU/EXP/LI-HUA-05"),
        ]

        for given, family, pid in test_cases:
            xml = build_signed_saml_response(
                person_identifier=pid,
                given_name=given,
                family_name=family,
                date_of_birth="1992-04-10",
                loa="http://eidas.europa.eu/LoA/substantial",
            )
            res = self.engine.validate_response(xml)
            self.assertTrue(res.is_valid, f"Failed validating UTF-8 name '{given} {family}': {res.error_message}")
            self.assertEqual(res.pos_context.given_name, given)
            self.assertEqual(res.pos_context.family_name, family)
            self.assertEqual(res.pos_context.user_id, pid)

    # =========================================================================
    # 3. Missing Mandatory Attributes & Edge Cases
    # =========================================================================

    def test_missing_person_identifier(self):
        """Missing PersonIdentifier attribute is rejected when other attributes exist"""
        xml = build_signed_saml_response(omit_person_id=True)
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid)
        self.assertIn("Missing mandatory eIDAS attribute: PersonIdentifier", res.error_message)

    def test_missing_date_of_birth(self):
        """Missing DateOfBirth attribute is rejected when other attributes exist"""
        xml = build_signed_saml_response(omit_dob=True)
        res = self.engine.validate_response(xml)
        self.assertFalse(res.is_valid)
        self.assertIn("Missing mandatory eIDAS attribute: DateOfBirth", res.error_message)

    def test_missing_current_family_name(self):
        """Missing CurrentFamilyName attribute is rejected"""
        # Build custom response omitting family name
        now = datetime.now(timezone.utc)
        resp_id = f"_resp_{int(now.timestamp())}_{os.urandom(4).hex()}"
        asrt_id = f"_asrt_{int(now.timestamp())}_{os.urandom(4).hex()}"
        t_issue = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        t_nb = (now - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        t_noa = (now + timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Attribute list without CurrentFamilyName
        attr_xml = (
            f'<saml2:Attribute FriendlyName="PersonIdentifier" Name="http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"><saml2:AttributeValue>IT/IT/TEST-01</saml2:AttributeValue></saml2:Attribute>'
            f'<saml2:Attribute FriendlyName="CurrentGivenName" Name="http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName"><saml2:AttributeValue>Mario</saml2:AttributeValue></saml2:Attribute>'
            f'<saml2:Attribute FriendlyName="DateOfBirth" Name="http://eidas.europa.eu/attributes/naturalperson/DateOfBirth"><saml2:AttributeValue>1980-01-01</saml2:AttributeValue></saml2:Attribute>'
        )

        xml = (
            f'<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
            f'Destination="http://cef-eid-build-1:8080/EidasNode/ColleagueResponse" ID="{resp_id}" IssueInstant="{t_issue}" Version="2.0">'
            f'<saml2:Issuer>http://cef-eid-build-1:8080/EidasNode/ServiceMetadata</saml2:Issuer>'
            f'<saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>'
            f'<saml2:Assertion ID="{asrt_id}" IssueInstant="{t_issue}" Version="2.0">'
            f'<saml2:Issuer>http://cef-eid-build-1:8080/EidasNode/ServiceMetadata</saml2:Issuer>'
            f'<saml2:Conditions NotBefore="{t_nb}" NotOnOrAfter="{t_noa}"><saml2:AudienceRestriction><saml2:Audience>http://sp.local:9090/SP/Metadata</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions>'
            f'<saml2:AttributeStatement>{attr_xml}</saml2:AttributeStatement>'
            f'</saml2:Assertion>'
            f'</saml2p:Response>'
        )

        res = self.engine.validate_response(xml, require_signature=False)
        self.assertFalse(res.is_valid)
        self.assertIn("Missing mandatory eIDAS attribute: CurrentFamilyName", res.error_message)

    def test_missing_current_given_name(self):
        """Missing CurrentGivenName attribute is rejected"""
        now = datetime.now(timezone.utc)
        resp_id = f"_resp_{int(now.timestamp())}_{os.urandom(4).hex()}"
        asrt_id = f"_asrt_{int(now.timestamp())}_{os.urandom(4).hex()}"
        t_issue = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        t_nb = (now - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        t_noa = (now + timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ")

        attr_xml = (
            f'<saml2:Attribute FriendlyName="PersonIdentifier" Name="http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"><saml2:AttributeValue>IT/IT/TEST-01</saml2:AttributeValue></saml2:Attribute>'
            f'<saml2:Attribute FriendlyName="CurrentFamilyName" Name="http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName"><saml2:AttributeValue>Rossi</saml2:AttributeValue></saml2:Attribute>'
            f'<saml2:Attribute FriendlyName="DateOfBirth" Name="http://eidas.europa.eu/attributes/naturalperson/DateOfBirth"><saml2:AttributeValue>1980-01-01</saml2:AttributeValue></saml2:Attribute>'
        )

        xml = (
            f'<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
            f'Destination="http://cef-eid-build-1:8080/EidasNode/ColleagueResponse" ID="{resp_id}" IssueInstant="{t_issue}" Version="2.0">'
            f'<saml2:Issuer>http://cef-eid-build-1:8080/EidasNode/ServiceMetadata</saml2:Issuer>'
            f'<saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>'
            f'<saml2:Assertion ID="{asrt_id}" IssueInstant="{t_issue}" Version="2.0">'
            f'<saml2:Issuer>http://cef-eid-build-1:8080/EidasNode/ServiceMetadata</saml2:Issuer>'
            f'<saml2:Conditions NotBefore="{t_nb}" NotOnOrAfter="{t_noa}"><saml2:AudienceRestriction><saml2:Audience>http://sp.local:9090/SP/Metadata</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions>'
            f'<saml2:AttributeStatement>{attr_xml}</saml2:AttributeStatement>'
            f'</saml2:Assertion>'
            f'</saml2p:Response>'
        )

        res = self.engine.validate_response(xml, require_signature=False)
        self.assertFalse(res.is_valid)
        self.assertIn("Missing mandatory eIDAS attribute: CurrentGivenName", res.error_message)

    def test_vulnerability_completely_empty_attribute_statement_bypasses_check(self):
        """
        ADVERSARIAL VULNERABILITY TEST:
        If an assertion has NO AttributeStatement or an empty AttributeStatement,
        'if attributes:' in engine.py evaluates to False, allowing the assertion
        to bypass all mandatory attribute checks!
        """
        now = datetime.now(timezone.utc)
        resp_id = f"_resp_{int(now.timestamp())}_{os.urandom(4).hex()}"
        asrt_id = f"_asrt_{int(now.timestamp())}_{os.urandom(4).hex()}"
        t_issue = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        t_nb = (now - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        t_noa = (now + timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ")

        xml = (
            f'<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
            f'Destination="http://cef-eid-build-1:8080/EidasNode/ColleagueResponse" ID="{resp_id}" IssueInstant="{t_issue}" Version="2.0">'
            f'<saml2:Issuer>http://cef-eid-build-1:8080/EidasNode/ServiceMetadata</saml2:Issuer>'
            f'<saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>'
            f'<saml2:Assertion ID="{asrt_id}" IssueInstant="{t_issue}" Version="2.0">'
            f'<saml2:Issuer>http://cef-eid-build-1:8080/EidasNode/ServiceMetadata</saml2:Issuer>'
            f'<saml2:Subject><saml2:NameID>GHOST_USER</saml2:NameID></saml2:Subject>'
            f'<saml2:Conditions NotBefore="{t_nb}" NotOnOrAfter="{t_noa}"><saml2:AudienceRestriction><saml2:Audience>http://sp.local:9090/SP/Metadata</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions>'
            f'<!-- OMITTED AttributeStatement COMPLETELY -->'
            f'</saml2:Assertion>'
            f'</saml2p:Response>'
        )

        res = self.engine.validate_response(xml, require_signature=False)
        # Empirical test: Does the engine erroneously mark this as valid?
        # Under eIDAS MDS, this MUST be invalid!
        # If res.is_valid is True, it confirms the vulnerability!
        print(f"\n[EMPIRICAL FINDING] Empty AttributeStatement validation result: is_valid={res.is_valid}, error={res.error_message}")
        # We record the empirical behavior:
        if res.is_valid:
            print("[BUG CONFIRMED] Engine accepts SAML Assertion without ANY natural person attributes!")
        self.assertFalse(res.is_valid, "SECURITY BUG: Empty attributes bypassed mandatory eIDAS attribute checks!")

    # =========================================================================
    # 4. AuthnRequest LoA Handling (low, substantial, high, unrecognized)
    # =========================================================================

    def test_authnrequest_loa_handling(self):
        """Tests AuthnRequest generator and validator with various LoA levels"""
        generator = SAMLAuthnRequestGenerator(
            sp_entity_id="http://sp.local:9090/SP/Metadata",
            acs_url="http://sp.local:9090/SP/ReturnPage",
            destination_url="http://peps.local:9090/PEPS/ServiceProvider",
        )

        loa_tests = [
            ("low", "http://eidas.europa.eu/LoA/low", "CASHIER", "LOW"),
            ("substantial", "http://eidas.europa.eu/LoA/substantial", "STORE_MANAGER", "SUBSTANTIAL"),
            ("high", "http://eidas.europa.eu/LoA/high", "STORE_MANAGER", "HIGH"),
            ("unrecognized_xyz", "http://eidas.europa.eu/LoA/unrecognized_xyz", "CASHIER", "LOW"),
        ]

        for input_loa, expected_uri, expected_role, expected_loa_level in loa_tests:
            req_id, xml, _ = generator.generate(loa=input_loa)
            res = self.engine.validate_authn_request(xml)
            self.assertTrue(res.is_valid, f"Failed validating AuthnRequest for LoA {input_loa}")
            self.assertEqual(res.claims["level_of_assurance"], expected_uri)

            # POS mapping
            pos = SAMLToPOSMapper.map_claims_to_pos(res.claims)
            self.assertEqual(pos.role, expected_role, f"LoA {input_loa} gave role {pos.role}, expected {expected_role}")
            self.assertEqual(pos.level_of_assurance, expected_loa_level)

if __name__ == "__main__":
    unittest.main()

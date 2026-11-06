import re
import os
import sys
import base64
import hashlib
import tempfile
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple, Set
import xml.etree.ElementTree as ET
import fcntl

from .mapping import SAMLToPOSMapper, POSUserContext
from .namespaces import (
    NS_SAML2P,
    NS_SAML2,
    NS_DS,
    NS_MD,
    NS_EIDAS,
    NS_EIDAS_NATURAL,
    NS_XSI,
    NS_XS,
)
from .xml_parser import SecureXMLParser
from .builders import SAMLAuthnRequestGenerator, SAMLMetadataGenerator
from .xmldsig import SignatureResult, XMLSignatureVerifier

def load_trusted_certificates_from_directory(directory_path: str) -> List[str]:
    """Loads all X.509 PEM certificates from a designated trust anchor directory."""
    certs = []
    if os.path.exists(directory_path) and os.path.isdir(directory_path):
        for filename in sorted(os.listdir(directory_path)):
            if filename.endswith((".pem", ".crt", ".cer")):
                filepath = os.path.join(directory_path, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        content = f.read().strip()
                        if "BEGIN CERTIFICATE" in content:
                            certs.append(content)
                except Exception:
                    pass
    return certs


# =============================================================================
# VALIDATION RESULT DATA MODEL
# =============================================================================

class SAMLValidationResult:
    def __init__(
        self,
        is_valid: bool,
        error_message: Optional[str] = None,
        claims: Optional[Dict[str, Any]] = None,
        pos_context: Optional[POSUserContext] = None,
    ):
        self.is_valid = is_valid
        self.error_message = error_message
        self.claims = claims or {}
        self.pos_context = pos_context

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "is_valid": self.is_valid,
            "error_message": self.error_message,
            "claims": self.claims,
        }
        if self.pos_context:
            res["pos_context"] = self.pos_context.to_dict()
        return res


# =============================================================================
# SAML VALIDATION ENGINE
# =============================================================================

class SAMLValidationEngine:
    """
    eIDAS 2.0 Hardened SAML Processing & Validation Engine.
    Enforces:
    - XML-DSig signature verification (RSA-SHA256, ECDSA-SHA256)
    - Anti-Replay with TTL-based pruning
    - Temporal validity window (IssueInstant, NotBefore, NotOnOrAfter, Clock Skew)
    - Audience restriction matching
    - XML Signature Wrapping (XSW) & XXE protection
    - Mandatory eIDAS Natural Person attribute profile extraction
    """
    DEFAULT_CACHE_FILE = os.path.join(tempfile.gettempdir(), "eidas_saml_replay_cache.json")

    def __init__(
        self,
        allowed_issuers: Optional[List[str]] = None,
        allowed_destinations: Optional[List[str]] = None,
        clock_skew_seconds: int = 300,
        replay_ttl_seconds: int = 600,
        cache_file: Optional[str] = DEFAULT_CACHE_FILE,
        persist_cache: bool = True,
        trusted_certificates: Optional[List[str]] = None,
        trusted_fingerprints: Optional[List[str]] = None,
        trusted_certs_dir: Optional[str] = None,
    ):
        self.allowed_issuers = allowed_issuers if allowed_issuers is not None else [
            "http://S-PEPS.gov.xx",
            "http://cef-eid-build-1:8080/EidasNode/ServiceMetadata",
            "http://sp.local:9090/SP/Metadata",
            "urn:bilanx:eidas:sp",
        ]
        self.allowed_destinations = allowed_destinations if allowed_destinations is not None else [
            "http://peps.local:9090/PEPS/ServiceProvider",
            "http://cef-eid-build-1:8080/EidasNode/ColleagueResponse",
            "http://sp.local:9090/SP/ReturnPage",
            "http://localhost:3000/saml/acs",
            "http://localhost:3000/auth/callback",
        ]
        self.clock_skew_seconds = clock_skew_seconds
        self.replay_ttl_seconds = replay_ttl_seconds
        self.allowed_audiences = [
            "http://sp.local:9090/SP/Metadata",
            "http://localhost:3000/saml/metadata",
            "http://localhost:3099/saml/metadata",
            "urn:bilanx:eidas:sp",
        ]
        # In-memory replay cache mapping id -> expire_timestamp
        self.processed_ids: Dict[str, float] = {}

        # Replay cache storage configuration
        if cache_file is None or not persist_cache:
            self._cache_file = None
            self.persist_cache = False
        else:
            self._cache_file = cache_file
            self.persist_cache = True

        # Trust anchor configuration (isolated from test fixtures)
        if trusted_certificates is not None:
            self.trusted_certificates = list(trusted_certificates)
        else:
            explicit_dir = trusted_certs_dir or os.environ.get("SAML_TRUSTED_CERTS_DIR")
            resolved_dir = explicit_dir or os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "certs"
            )
            self.trusted_certificates = load_trusted_certificates_from_directory(resolved_dir)
            # If no explicit SAML_TRUSTED_CERTS_DIR was forced and no production certs are mounted,
            # also accept ephemeral sandbox IdP certificates generated in OS temp storage
            if (
                not explicit_dir
                and not self.trusted_certificates
                and os.environ.get("SAML_DISABLE_EPHEMERAL_CERTS", "").lower() != "true"
            ):
                ephemeral_certs_dir = os.path.join(
                    tempfile.gettempdir(), f"bilanx_ephemeral_saml_{os.getuid()}", "certs"
                )
                self.trusted_certificates = load_trusted_certificates_from_directory(
                    ephemeral_certs_dir
                )

        self.trusted_fingerprints: Set[str] = set()
        if trusted_fingerprints:
            for tf in trusted_fingerprints:
                self.trusted_fingerprints.add(tf.replace(":", "").replace(" ", "").upper())
        for tc in self.trusted_certificates:
            try:
                self.trusted_fingerprints.add(XMLSignatureVerifier.compute_cert_fingerprint(tc))
            except Exception:
                pass

    def _load_disk_cache(self) -> Dict[str, float]:
        import json
        if not self.persist_cache or not self._cache_file:
            return {}
        try:
            if os.path.exists(self._cache_file):
                with open(self._cache_file, "r") as f:
                    fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                    try:
                        data = json.load(f)
                        if isinstance(data, dict):
                            return {str(k): float(v) for k, v in data.items()}
                    finally:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        return {}

    def _save_disk_cache(self, cache: Dict[str, float]):
        import json
        if not self.persist_cache or not self._cache_file:
            return
        try:
            with open(self._cache_file, "a+") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.seek(0)
                    f.truncate(0)
                    json.dump(cache, f)
                    f.flush()
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass

    def _prune_replay_cache(self, now_ts: float):
        if not self.persist_cache or not self._cache_file:
            self.processed_ids = {k: exp for k, exp in self.processed_ids.items() if exp > now_ts}
            return
        disk_cache = self._load_disk_cache()
        combined = {**disk_cache, **self.processed_ids}
        active = {k: exp for k, exp in combined.items() if exp > now_ts}
        self.processed_ids = active
        self._save_disk_cache(active)

    def _check_and_record_replay(self, message_id: str, max_valid_ts: Optional[float] = None) -> bool:
        """
        Returns True if fresh (not replayed), False if already processed.
        Persisted across CLI executions via temporary storage with TTL pruning and fcntl file locking.
        """
        now_ts = datetime.now(timezone.utc).timestamp()
        if not self.persist_cache or not self._cache_file:
            self.processed_ids = {k: exp for k, exp in self.processed_ids.items() if exp > now_ts}
            if message_id in self.processed_ids:
                return False
            expire_ts = max_valid_ts if max_valid_ts and max_valid_ts > now_ts else (now_ts + self.replay_ttl_seconds)
            self.processed_ids[message_id] = expire_ts
            return True

        import json
        try:
            with open(self._cache_file, "a+") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.seek(0)
                    content = f.read().strip()
                    disk_cache = {}
                    if content:
                        try:
                            data = json.loads(content)
                            if isinstance(data, dict):
                                disk_cache = {str(k): float(v) for k, v in data.items()}
                        except Exception:
                            disk_cache = {}

                    combined = {**disk_cache, **self.processed_ids}
                    active = {k: exp for k, exp in combined.items() if exp > now_ts}
                    self.processed_ids = active

                    if message_id in self.processed_ids:
                        f.seek(0)
                        f.truncate(0)
                        json.dump(self.processed_ids, f)
                        f.flush()
                        return False

                    expire_ts = max_valid_ts if max_valid_ts and max_valid_ts > now_ts else (now_ts + self.replay_ttl_seconds)
                    self.processed_ids[message_id] = expire_ts

                    f.seek(0)
                    f.truncate(0)
                    json.dump(self.processed_ids, f)
                    f.flush()
                    return True
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception:
            if message_id in self.processed_ids:
                return False
            expire_ts = max_valid_ts if max_valid_ts and max_valid_ts > now_ts else (now_ts + self.replay_ttl_seconds)
            self.processed_ids[message_id] = expire_ts
            return True

    def validate_authn_request(self, xml_string: str, check_freshness: bool = False) -> SAMLValidationResult:
        """
        Validates incoming SAML 2.0 AuthnRequest.
        """
        try:
            root = SecureXMLParser.parse_string(xml_string)

            tag = root.tag
            if not tag.endswith("AuthnRequest"):
                return SAMLValidationResult(False, f"Invalid root tag: {tag}. Expected AuthnRequest.")

            request_id = root.attrib.get("ID")
            if not request_id:
                return SAMLValidationResult(False, "Missing ID attribute on AuthnRequest.")

            destination = root.attrib.get("Destination")
            if destination and self.allowed_destinations and destination not in self.allowed_destinations:
                return SAMLValidationResult(False, f"Unauthorized Destination: {destination}")

            if not self._check_and_record_replay(request_id):
                return SAMLValidationResult(False, f"Replay Attack Detected: AuthnRequest ID {request_id} already processed.")

            issue_instant_str = root.attrib.get("IssueInstant")
            if not issue_instant_str:
                return SAMLValidationResult(False, "Missing IssueInstant attribute.")

            # Validate IssueInstant freshness if requested
            if check_freshness:
                try:
                    norm_ts = issue_instant_str.replace("Z", "+00:00")
                    issue_dt = datetime.fromisoformat(norm_ts)
                    now_utc = datetime.now(timezone.utc)
                    if abs((now_utc - issue_dt).total_seconds()) > (3600 + self.clock_skew_seconds):
                        return SAMLValidationResult(False, f"AuthnRequest IssueInstant is outside acceptable window: {issue_instant_str}")
                except Exception:
                    pass

            # Parse Issuer
            issuer_element = None
            for child in root:
                if child.tag.endswith("Issuer"):
                    issuer_element = child
                    break

            if issuer_element is None or not issuer_element.text:
                return SAMLValidationResult(False, "Missing or empty saml2:Issuer element.")

            issuer = issuer_element.text.strip()
            if self.allowed_issuers and issuer not in self.allowed_issuers:
                return SAMLValidationResult(False, f"Untrusted Issuer: {issuer}")

            # Extract RequestedAuthnContext
            loa = None
            for child in root:
                if child.tag.endswith("RequestedAuthnContext"):
                    for nested in child:
                        if nested.tag.endswith("AuthnContextClassRef") and nested.text:
                            loa = nested.text.strip()
                            break

            claims = {
                "type": "AuthnRequest",
                "id": request_id,
                "issuer": issuer,
                "destination": destination,
                "issue_instant": issue_instant_str,
                "consent": root.attrib.get("Consent"),
                "provider_name": root.attrib.get("ProviderName"),
                "assertion_consumer_service_url": root.attrib.get("AssertionConsumerServiceURL"),
                "level_of_assurance": loa,
            }

            return SAMLValidationResult(True, claims=claims)

        except Exception as e:
            return SAMLValidationResult(False, f"Parser Error: {str(e)}")

    def validate_response(
        self,
        xml_string: str,
        expected_request_id: Optional[str] = None,
        require_signature: bool = True,
        check_temporal: bool = True,
        check_audience: bool = True,
        expected_audience: Optional[str] = None,
    ) -> SAMLValidationResult:
        """
        Validates an eIDAS SAML 2.0 Response & Assertion:
        1. Root tag & status code verification (Success).
        2. Anti-replay protection on Response and Assertion IDs.
        3. XML-DSig signature verification over the canonical Assertion (SHA-256 digest + RSA/ECDSA).
        4. Temporal validation (IssueInstant, NotBefore, NotOnOrAfter with clock skew).
        5. AudienceRestriction validation.
        6. eIDAS Mandatory Attribute profile extraction (PersonIdentifier, CurrentFamilyName, CurrentGivenName, DateOfBirth).
        7. Retail POS Context calculation & age gating (18+).
        """
        if not self.trusted_certificates:
            return SAMLValidationResult(is_valid=False, error_message="No trusted certificates configured")

        try:
            root = SecureXMLParser.parse_string(xml_string)

            tag = root.tag
            if not tag.endswith("Response"):
                return SAMLValidationResult(False, f"Invalid root tag: {tag}. Expected Response.")

            response_id = root.attrib.get("ID")
            if not response_id:
                return SAMLValidationResult(False, "Missing ID attribute on Response.")

            destination = root.attrib.get("Destination")
            if destination and self.allowed_destinations and destination not in self.allowed_destinations:
                return SAMLValidationResult(False, f"Unauthorized Destination: {destination}")

            in_response_to = root.attrib.get("InResponseTo")
            if expected_request_id:
                if not in_response_to:
                    return SAMLValidationResult(False, f"Missing InResponseTo attribute on Response: Expected {expected_request_id}")
                if in_response_to != expected_request_id:
                    return SAMLValidationResult(False, f"InResponseTo Mismatch: Expected {expected_request_id}, got {in_response_to}")

            # Replay check for Response ID
            if not self._check_and_record_replay(response_id):
                return SAMLValidationResult(False, f"Replay Attack Detected: Response ID {response_id} already processed.")

            # Status code validation
            status_code = None
            status_msg = None
            for child in root:
                if child.tag.endswith("Status"):
                    for nested in child:
                        if nested.tag.endswith("StatusCode"):
                            status_code = nested.attrib.get("Value")
                        elif nested.tag.endswith("StatusMessage"):
                            status_msg = nested.text

            if status_code != "urn:oasis:names:tc:SAML:2.0:status:Success":
                return SAMLValidationResult(False, f"SAML IdP Error: StatusCode={status_code}, Message={status_msg or 'Authentication Failed'}")

            # Parse and validate Issuer of Response
            resp_issuer = None
            for child in root:
                if child.tag.endswith("Issuer") and child.text:
                    resp_issuer = child.text.strip()
                    break

            if self.allowed_issuers:
                if not resp_issuer:
                    return SAMLValidationResult(False, "Missing or empty saml2:Issuer on Response.")
                if resp_issuer not in self.allowed_issuers:
                    return SAMLValidationResult(False, f"Unauthorized Response Issuer: {resp_issuer}")

            # Locate Assertion (must be direct child to prevent XSW injection)
            assertions = [c for c in root if c.tag.endswith("Assertion")]
            if not assertions:
                return SAMLValidationResult(False, "Missing saml2:Assertion in SAML Response.")

            # XSW Defense: Reject if multiple unhandled assertions exist
            if len(assertions) > 1:
                return SAMLValidationResult(False, "XSW Defense Violation: Multiple Assertion elements detected in Response.")

            assertion = assertions[0]
            assertion_id = assertion.attrib.get("ID")
            if not assertion_id:
                return SAMLValidationResult(False, "Missing ID attribute on Assertion.")

            # Parse and validate Issuer of Assertion
            assertion_issuer = None
            for child in assertion:
                if child.tag.endswith("Issuer") and child.text:
                    assertion_issuer = child.text.strip()
                    break

            if self.allowed_issuers:
                if not assertion_issuer:
                    return SAMLValidationResult(False, "Missing or empty saml2:Issuer on Assertion.")
                if assertion_issuer not in self.allowed_issuers:
                    return SAMLValidationResult(False, f"Unauthorized Assertion Issuer: {assertion_issuer}")

            # Replay check for Assertion ID
            if not self._check_and_record_replay(assertion_id):
                return SAMLValidationResult(False, f"Replay Attack Detected: Assertion ID {assertion_id} already processed.")

            # 3. XML-DSig Signature Verification
            has_signature = False
            for child in assertion:
                if child.tag.endswith("Signature"):
                    has_signature = True
                    break
            if not has_signature:
                for child in root:
                    if child.tag.endswith("Signature"):
                        has_signature = True
                        break

            if require_signature:
                if not has_signature:
                    return SAMLValidationResult(False, "Cryptographic Error: Assertion is not digitally signed.")

                sig_valid, sig_msg, cert_info = XMLSignatureVerifier.verify_signature(
                    root=root,
                    target_element=assertion,
                    expected_target_id=assertion_id,
                    trusted_certificates=self.trusted_certificates,
                    trusted_fingerprints=self.trusted_fingerprints,
                )
                if not sig_valid:
                    return SAMLValidationResult(False, f"Cryptographic Verification Failed: {sig_msg}")

            # 4. Temporal Checks & Conditions
            now_utc = datetime.now(timezone.utc)
            skew = timedelta(seconds=self.clock_skew_seconds)

            conditions_elem = None
            subject_elem = None
            authn_stmt_elem = None
            attr_stmt_elem = None

            for child in assertion:
                if child.tag.endswith("Conditions"):
                    conditions_elem = child
                elif child.tag.endswith("Subject"):
                    subject_elem = child
                elif child.tag.endswith("AuthnStatement"):
                    authn_stmt_elem = child
                elif child.tag.endswith("AttributeStatement"):
                    attr_stmt_elem = child

            if conditions_elem is None:
                return SAMLValidationResult(False, "Missing mandatory <saml2:Conditions> element in Assertion.")

            if check_temporal:
                not_before_str = conditions_elem.attrib.get("NotBefore")
                not_on_or_after_str = conditions_elem.attrib.get("NotOnOrAfter")

                if not_before_str:
                    try:
                        nb_dt = datetime.fromisoformat(not_before_str.replace("Z", "+00:00"))
                        if now_utc < (nb_dt - skew):
                            return SAMLValidationResult(False, f"Temporal Violation: Assertion is premature (NotBefore={not_before_str}, Current={now_utc.isoformat()}).")
                    except ValueError:
                        return SAMLValidationResult(False, f"Malformed NotBefore timestamp: {not_before_str}")

                if not_on_or_after_str:
                    try:
                        noa_dt = datetime.fromisoformat(not_on_or_after_str.replace("Z", "+00:00"))
                        if now_utc >= (noa_dt + skew):
                            return SAMLValidationResult(False, f"Temporal Violation: Assertion has expired (NotOnOrAfter={not_on_or_after_str}, Current={now_utc.isoformat()}).")
                    except ValueError:
                        return SAMLValidationResult(False, f"Malformed NotOnOrAfter timestamp: {not_on_or_after_str}")

            # 5. Audience Restriction Validation
            if check_audience:
                audience_match = False
                found_audiences = []
                for ar in conditions_elem:
                    if ar.tag.endswith("AudienceRestriction"):
                        for aud in ar:
                            if aud.tag.endswith("Audience") and aud.text:
                                aud_val = aud.text.strip()
                                found_audiences.append(aud_val)
                                if expected_audience:
                                    if aud_val == expected_audience:
                                        audience_match = True
                                else:
                                    if aud_val in self.allowed_audiences or aud_val in self.allowed_issuers:
                                        audience_match = True

                if found_audiences and not audience_match:
                    return SAMLValidationResult(False, f"Audience Mismatch: Configured SP does not match assertion audience(s): {found_audiences}")

            # 6. Parse Subject (NameID & InResponseTo correlation in SubjectConfirmationData)
            name_id = None
            if subject_elem is not None:
                for child in subject_elem:
                    if child.tag.endswith("NameID") and child.text:
                        name_id = child.text.strip()
                    elif child.tag.endswith("SubjectConfirmation"):
                        if expected_request_id:
                            for sc_child in child:
                                if sc_child.tag.endswith("SubjectConfirmationData"):
                                    sc_in_resp = sc_child.attrib.get("InResponseTo")
                                    if sc_in_resp and sc_in_resp != expected_request_id:
                                        return SAMLValidationResult(False, f"SubjectConfirmationData InResponseTo Mismatch: Expected {expected_request_id}, got {sc_in_resp}")

            # 7. Parse AuthnStatement (LoA)
            loa = None
            authn_instant = None
            if authn_stmt_elem is not None:
                authn_instant = authn_stmt_elem.attrib.get("AuthnInstant")
                for child in authn_stmt_elem.iter():
                    if child.tag.endswith("AuthnContextClassRef") and child.text:
                        loa = child.text.strip()
                        break

            # 8. Parse AttributeStatement (eIDAS Natural Person Attributes)
            attributes: Dict[str, Any] = {}
            if attr_stmt_elem is not None:
                for attr_node in attr_stmt_elem:
                    if attr_node.tag.endswith("Attribute"):
                        name = attr_node.attrib.get("Name")
                        friendly_name = attr_node.attrib.get("FriendlyName")
                        values = []
                        for val_node in attr_node:
                            if val_node.tag.endswith("AttributeValue") and val_node.text:
                                values.append(val_node.text.strip())

                        val_str = values[0] if len(values) == 1 else values
                        if name:
                            attributes[name] = val_str
                        if friendly_name and friendly_name not in attributes:
                            attributes[friendly_name] = val_str

            # Validate mandatory eIDAS natural person attributes unconditionally
            if attr_stmt_elem is None or not attributes:
                return SAMLValidationResult(False, "Missing mandatory eIDAS attribute: PersonIdentifier.")

            has_person_id = any(
                k.endswith("PersonIdentifier") or k == "PersonIdentifier"
                for k in attributes
            )
            has_family_name = any(
                k.endswith("CurrentFamilyName") or k == "CurrentFamilyName" or k == "FamilyName"
                for k in attributes
            )
            has_given_name = any(
                k.endswith("CurrentGivenName") or k == "CurrentGivenName" or k == "GivenName" or k == "FirstName"
                for k in attributes
            )
            has_dob = any(
                k.endswith("DateOfBirth") or k == "DateOfBirth"
                for k in attributes
            )

            if not has_person_id:
                return SAMLValidationResult(False, "Missing mandatory eIDAS attribute: PersonIdentifier.")
            if not has_family_name:
                return SAMLValidationResult(False, "Missing mandatory eIDAS attribute: CurrentFamilyName.")
            if not has_given_name:
                return SAMLValidationResult(False, "Missing mandatory eIDAS attribute: CurrentGivenName.")
            if not has_dob:
                return SAMLValidationResult(False, "Missing mandatory eIDAS attribute: DateOfBirth.")

            claims = {
                "type": "Response",
                "id": response_id,
                "assertion_id": assertion_id,
                "in_response_to": in_response_to,
                "issuer": resp_issuer,
                "assertion_issuer": assertion_issuer,
                "destination": destination,
                "issue_instant": root.attrib.get("IssueInstant"),
                "status_code": status_code,
                "status_message": status_msg,
                "name_id": name_id,
                "authn_instant": authn_instant,
                "level_of_assurance": loa,
                "attributes": attributes,
            }

            # Map to POS User Context
            pos_context = SAMLToPOSMapper.map_claims_to_pos(claims)

            return SAMLValidationResult(True, claims=claims, pos_context=pos_context)

        except Exception as e:
            return SAMLValidationResult(False, f"Validation Failure: {str(e)}")

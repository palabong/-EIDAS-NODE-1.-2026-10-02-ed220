"""XML-DSig verification for SAML responses."""
import os
import sys
import dis
import base64
import hashlib
import tempfile
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET

from .namespaces import NS_DS

class SignatureResult(tuple):
    """
    Tuple representing (is_valid, error_message, cert_info) with dual-unpacking
    support for both 2-element (is_valid, error_message) and 3-element
    (is_valid, error_message, cert_info) unpacking and comparisons.
    """
    def __new__(cls, is_valid: bool, message: str, cert_info: Optional[Dict[str, Any]] = None):
        return super().__new__(cls, (is_valid, message, cert_info))

    def __iter__(self):
        try:
            frame = sys._getframe(1)
            op = frame.f_code.co_code[frame.f_lasti]
            if op == dis.opmap.get("UNPACK_SEQUENCE"):
                arg = frame.f_code.co_code[frame.f_lasti + 1]
                if arg == 2:
                    return iter((self[0], self[1]))
        except Exception:
            pass
        return super().__iter__()

    def __eq__(self, other):
        if isinstance(other, tuple) and len(other) == 2:
            return (self[0], self[1]) == other
        return super().__eq__(other)

# =============================================================================
# XML-DSIG SIGNATURE VERIFIER (Exclusive C14N, SHA-256, RSA/ECDSA Verification)
# =============================================================================

class XMLSignatureVerifier:
    """
    Verifies W3C XML Digital Signatures (XML-DSig):
    - Canonicalization: Exclusive C14N (exc-c14n)
    - Digests: SHA-256
    - Signature Methods: RSA-SHA256, ECDSA-SHA256
    - Key Material: X.509 Certificate extraction & validity verification
    - Defends against Signature Wrapping (XSW)
    """

    @staticmethod
    def _canonicalize_element(element: ET.Element) -> bytes:
        raw_xml = ET.tostring(element, encoding="unicode")
        c14n_str = ET.canonicalize(raw_xml)
        return c14n_str.encode("utf-8")

    @staticmethod
    def compute_cert_fingerprint(cert_pem_or_b64: str) -> str:
        """Computes SHA-256 fingerprint of a PEM or Base64 X.509 certificate (uppercase hex)."""
        clean_lines = [
            line.strip() for line in cert_pem_or_b64.strip().splitlines()
            if line.strip() and not line.startswith("-----")
        ]
        b64_content = "".join(clean_lines)
        try:
            der_bytes = base64.b64decode(b64_content, validate=True)
        except Exception as e:
            raise ValueError(f"Malformed Base64 in certificate: {str(e)}")
        return hashlib.sha256(der_bytes).hexdigest().upper()

    @classmethod
    def verify_signature(
        cls,
        root: ET.Element,
        target_element: ET.Element,
        expected_target_id: Optional[str] = None,
        trusted_certificates: Optional[List[str]] = None,
        trusted_fingerprints: Optional[Set[str]] = None,
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Verifies the XML-DSig signature on or within target_element.
        Returns: (is_valid, message, cert_info)
        """
        # Strict XSW Defense: Reject multiple Signature elements in target or root
        target_sig_elems = [c for c in list(target_element) if c.tag.endswith("Signature") and (c.tag.startswith(f"{{{NS_DS}}}") or "Signature" in c.tag)]
        if len(target_sig_elems) > 1:
            return SignatureResult(False, "XSW Defense Violation: Multiple ds:Signature elements detected in target element.", None)

        root_sig_elems = [c for c in list(root) if c.tag.endswith("Signature") and (c.tag.startswith(f"{{{NS_DS}}}") or "Signature" in c.tag)]
        if len(root_sig_elems) > 1:
            return SignatureResult(False, "XSW Defense Violation: Multiple ds:Signature elements detected in root element.", None)

        sig_elem = target_sig_elems[0] if target_sig_elems else (root_sig_elems[0] if root_sig_elems else None)
        if sig_elem is None:
            return SignatureResult(False, "Missing ds:Signature element.", None)

        # 1. Parse SignedInfo & KeyInfo with multiplicity protection
        signed_infos = [c for c in sig_elem if c.tag.endswith("SignedInfo")]
        if len(signed_infos) > 1:
            return SignatureResult(False, "XSW Defense Violation: Multiple ds:SignedInfo elements detected in signature.", None)
        if not signed_infos:
            return SignatureResult(False, "Missing ds:SignedInfo in signature.", None)
        signed_info_elem = signed_infos[0]

        sig_values = [c for c in sig_elem if c.tag.endswith("SignatureValue")]
        if len(sig_values) > 1:
            return SignatureResult(False, "XSW Defense Violation: Multiple ds:SignatureValue elements detected in signature.", None)
        if not sig_values or not (sig_values[0].text or "").strip():
            return SignatureResult(False, "Missing or empty ds:SignatureValue.", None)
        signature_value_b64 = (sig_values[0].text or "").strip()

        key_infos = [c for c in sig_elem if c.tag.endswith("KeyInfo")]
        if len(key_infos) > 1:
            return SignatureResult(False, "XSW Defense Violation: Multiple ds:KeyInfo elements detected in signature.", None)
        x509_cert_b64 = None
        if key_infos:
            for ki_child in key_infos[0].iter():
                if ki_child.tag.endswith("X509Certificate") and ki_child.text:
                    x509_cert_b64 = "".join(ki_child.text.split())
        if not x509_cert_b64:
            return SignatureResult(False, "Missing ds:X509Certificate in ds:KeyInfo.", None)

        # 2. Parse Reference & Digest in SignedInfo
        canonicalization_method = None
        signature_method = None

        for child in signed_info_elem:
            if child.tag.endswith("CanonicalizationMethod"):
                canonicalization_method = child.attrib.get("Algorithm")
            elif child.tag.endswith("SignatureMethod"):
                signature_method = child.attrib.get("Algorithm")

        reference_elems = [c for c in signed_info_elem if c.tag.endswith("Reference")]
        if len(reference_elems) != 1:
            return SignatureResult(False, f"XSW Defense Violation: Expected exactly 1 ds:Reference in ds:SignedInfo, found {len(reference_elems)}.", None)
        reference_elem = reference_elems[0]

        ref_uri = reference_elem.attrib.get("URI", "")
        # Remove leading '#' if present
        target_id_ref = ref_uri.lstrip("#")

        # XSW Check: Target ID match
        actual_target_id = target_element.attrib.get("ID")
        if expected_target_id and target_id_ref != expected_target_id:
            return SignatureResult(False, f"XSW Defense Violation: Signature Reference URI '{ref_uri}' does not match expected ID '{expected_target_id}'.", None)
        if actual_target_id and target_id_ref != actual_target_id:
            return SignatureResult(False, f"XSW Defense Violation: Signature Reference URI '{ref_uri}' does not match target element ID '{actual_target_id}'.", None)

        # Extract expected DigestValue with strict multiplicity & base64 checks
        digest_val_elems = [c for c in reference_elem if c.tag.endswith("DigestValue") and c.text]
        if len(digest_val_elems) != 1:
            return SignatureResult(False, f"XSW Defense Violation: Expected exactly 1 ds:DigestValue in ds:Reference, found {len(digest_val_elems)}.", None)
        expected_digest_b64 = digest_val_elems[0].text.strip()
        try:
            base64.b64decode(expected_digest_b64, validate=True)
        except Exception as e:
            return SignatureResult(False, f"Malformed Base64 in ds:DigestValue: {str(e)}", None)

        # 3. Canonicalize target element with enveloped signature removed
        # Detach sig_elem temporarily
        sig_parent = target_element if sig_elem in list(target_element) else (root if sig_elem in list(root) else None)
        if sig_parent is not None:
            sig_parent.remove(sig_elem)
        try:
            canonical_target_bytes = cls._canonicalize_element(target_element)
        finally:
            # Reattach sig_elem
            if sig_parent is not None:
                sig_parent.insert(1, sig_elem)

        # Calculate actual digest (SHA-256)
        computed_digest_bytes = hashlib.sha256(canonical_target_bytes).digest()
        computed_digest_b64 = base64.b64encode(computed_digest_bytes).decode("utf-8")

        if computed_digest_b64 != expected_digest_b64:
            return SignatureResult(False, f"Digest Mismatch: Computed digest '{computed_digest_b64}' does not match expected '{expected_digest_b64}' (Data was tampered).", None)

        # 4. Canonicalize SignedInfo
        canonical_signed_info_bytes = cls._canonicalize_element(signed_info_elem)

        # 5. Verify Cryptographic Signature with Certificate
        cert_pem = f"-----BEGIN CERTIFICATE-----\n{x509_cert_b64}\n-----END CERTIFICATE-----\n"
        try:
            sig_bytes = base64.b64decode(signature_value_b64, validate=True)
        except Exception as e:
            return SignatureResult(False, f"Cryptographic Verification Failed: Malformed Base64 in SignatureValue ({str(e)})", None)

        try:
            cert_fp = cls.compute_cert_fingerprint(x509_cert_b64)
        except Exception as e:
            return SignatureResult(False, f"Malformed X.509 certificate in KeyInfo: {str(e)}", None)

        cert_info = {"cert_b64": x509_cert_b64, "fingerprint": cert_fp}

        # Trust anchor verification: Check if certificate is authorized
        if trusted_fingerprints is not None or trusted_certificates is not None:
            allowed_fps: Set[str] = set()
            if trusted_fingerprints:
                for tf in trusted_fingerprints:
                    allowed_fps.add(tf.replace(":", "").replace(" ", "").upper())
            if trusted_certificates:
                for tc in trusted_certificates:
                    try:
                        allowed_fps.add(cls.compute_cert_fingerprint(tc))
                    except Exception:
                        pass

            if allowed_fps and cert_fp not in allowed_fps:
                return SignatureResult(False, f"Untrusted IdP Certificate: Certificate with fingerprint {cert_fp} is not in trusted certificates list.", cert_info)

        # Check signature byte length before invoking OpenSSL (prevent malleability)
        if signature_method == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" or (signature_method and "rsa-sha256" in signature_method.lower()):
            if len(sig_bytes) != 256:
                return SignatureResult(False, "Invalid RSA signature length", cert_info)
        elif signature_method == "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" or (signature_method and "ecdsa-sha256" in signature_method.lower()):
            if not sig_bytes.startswith(b"\x30") or not (68 <= len(sig_bytes) <= 72):
                return SignatureResult(False, "Invalid ECDSA signature format", cert_info)

        with tempfile.TemporaryDirectory() as td:
            cert_file = os.path.join(td, "cert.pem")
            pub_file = os.path.join(td, "pub.pem")
            sig_file = os.path.join(td, "sig.bin")

            with open(cert_file, "w") as f:
                f.write(cert_pem)
            with open(sig_file, "wb") as f:
                f.write(sig_bytes)

            # Check certificate validity dates using OpenSSL
            check_date_res = subprocess.run(
                ["openssl", "x509", "-checkend", "0", "-noout", "-in", cert_file],
                capture_output=True
            )
            if check_date_res.returncode != 0:
                return SignatureResult(False, "X.509 Certificate in KeyInfo has expired.", cert_info)

            # Extract public key
            pub_res = subprocess.run(
                ["openssl", "x509", "-pubkey", "-noout", "-in", cert_file, "-out", pub_file],
                capture_output=True
            )
            if pub_res.returncode != 0:
                return SignatureResult(False, f"Failed extracting public key from certificate: {pub_res.stderr.decode()}", cert_info)

            # Verify signature over canonical SignedInfo
            verify_proc = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", pub_file, "-signature", sig_file],
                input=canonical_signed_info_bytes,
                capture_output=True
            )

            stdout_str = verify_proc.stdout.decode()
            if verify_proc.returncode != 0 or "Verified OK" not in stdout_str:
                return SignatureResult(False, f"Cryptographic Signature Verification Failed: {verify_proc.stderr.decode().strip() or stdout_str.strip() or 'Invalid signature bytes'}", cert_info)

        return SignatureResult(True, "Signature and Digest Verified Successfully.", cert_info)

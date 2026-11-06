```python
# Path: saml_engine/engine.py
# Lines: 56-98
# XXE and XML bomb defense via xml.parsers.expat handlers, then xml.etree.
# There is no regex DOCTYPE pre-filter in SecureXMLParser.

class SecureXMLParser:
    """
    Parses XML strictly enforcing security controls:
    1. Disallows external entities (XXE).
    2. Disallows inline DTD declarations (to avoid Billion Laughs XML bomb attacks).
    3. Enforces DTD and entity blocking via xml.parsers.expat before handoff to xml.etree.
    """

    @classmethod
    def parse_string(cls, xml_input: Any) -> ET.Element:
        if not xml_input or not isinstance(xml_input, (str, bytes)):
            raise ValueError("Invalid XML input: Empty or non-string payload.")

        if isinstance(xml_input, str):
            xml_bytes = xml_input.strip().encode("utf-8")
        elif isinstance(xml_input, bytes):
            xml_bytes = xml_input.strip()
        else:
            raise ValueError("Invalid XML input: Empty or non-string payload.")

        if not xml_bytes:
            raise ValueError("Invalid XML input: Empty or non-string payload.")

        # Expat DTD gate: Disallow DOCTYPE, entity, and external entity declarations
        parser = xml.parsers.expat.ParserCreate()

        def forbid_dtd(*args, **kwargs):
            raise ValueError("Security Violation: DTD declarations or external entities are forbidden.")

        parser.StartDoctypeDeclHandler = forbid_dtd
        parser.EntityDeclHandler = forbid_dtd
        parser.ExternalEntityRefHandler = forbid_dtd

        try:
            parser.Parse(xml_bytes, True)
        except xml.parsers.expat.ExpatError as ee:
            raise ValueError(f"XML Parse Error: {str(ee)}")

        # Hand bytes to xml.etree only if no DTD was declared
        try:
            return ET.fromstring(xml_bytes)
        except ET.ParseError as pe:
            raise ValueError(f"XML Parse Error: {str(pe)}")
```

```python
# Path: saml_engine/engine.py
# Lines: 320-331 and 831-838
# XML Signature Wrapping defense in the current verifier.
# XMLSignatureVerifier.verify_signature also rejects a second SignedInfo,
# SignatureValue, KeyInfo, or Reference, and checks the Reference URI.

        # Strict XSW Defense: Reject multiple Signature elements in target or root
        target_sig_elems = [c for c in list(target_element) if c.tag.endswith("Signature") and (c.tag.startswith(f"{{{NS_DS}}}") or "Signature" in c.tag)]
        if len(target_sig_elems) > 1:
            return SignatureResult(False, "XSW Defense Violation: Multiple ds:Signature elements detected in target element.", None)

        root_sig_elems = [c for c in list(root) if c.tag.endswith("Signature") and (c.tag.startswith(f"{{{NS_DS}}}") or "Signature" in c.tag)]
        if len(root_sig_elems) > 1:
            return SignatureResult(False, "XSW Defense Violation: Multiple ds:Signature elements detected in root element.", None)
```

```python
# Path: saml_engine/engine.py
# Lines: 831-838

            # Locate Assertion (must be direct child to prevent XSW injection)
            assertions = [c for c in root if c.tag.endswith("Assertion")]
            if not assertions:
                return SAMLValidationResult(False, "Missing saml2:Assertion in SAML Response.")

            # XSW Defense: Reject if multiple unhandled assertions exist
            if len(assertions) > 1:
                return SAMLValidationResult(False, "XSW Defense Violation: Multiple Assertion elements detected in Response.")
```

```python
# Path: saml_engine/fixtures.py
# Lines: 12-28
# Uses synthetic self-signed test fixtures rather than connecting to a live national IdP

IDP_RSA_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUQW60R02m097yN3H13vQ01y1qQ3swDQYJKoZIhvcNAQEL
BQAwRTEdMBsGA1UEAwwURWlEQVMgTW9jayBJRFAgKEVVKTEUMBIGA1UECgwLRXVy
b3BlYW4gQ29tMQswCQYDVQQGEwJFVTAeFw0yNjEwMDIyMjI3MzJaFw00NjA5Mjcy
MjI3MzJaMEUxHTAbBgNVBAMMFEVpRFTAgTW9jayBJRFAgKEVVKTEUMBIGA1UECgwL
RXVyb3BlYW4gQ29tMQswCQYDVQQGEwJFVTCBnzANBgkqhkiG9w0BAQEFAAOBjQAw
...
-----END CERTIFICATE-----"""
```
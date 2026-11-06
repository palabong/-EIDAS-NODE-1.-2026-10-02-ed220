"""DTD-gated XML parser used by the SAML engine."""
from typing import Any
import xml.parsers.expat
import xml.etree.ElementTree as ET

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

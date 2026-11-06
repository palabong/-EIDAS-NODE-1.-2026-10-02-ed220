"""SAML namespace constants. Importing this module registers ElementTree prefixes."""
import xml.etree.ElementTree as ET

NS_SAML2P = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_SAML2 = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"
NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
NS_EIDAS = "http://eidas.europa.eu/saml-extensions"
NS_EIDAS_NATURAL = "http://eidas.europa.eu/attributes/naturalperson"
NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
NS_XS = "http://www.w3.org/2001/XMLSchema"

ET.register_namespace("saml2p", NS_SAML2P)
ET.register_namespace("saml2", NS_SAML2)
ET.register_namespace("ds", NS_DS)
ET.register_namespace("md", NS_MD)
ET.register_namespace("eidas", NS_EIDAS)
ET.register_namespace("xsi", NS_XSI)
ET.register_namespace("xs", NS_XS)

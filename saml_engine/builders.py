"""AuthnRequest and SP metadata generators."""
import os
import base64
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

from .namespaces import NS_SAML2P, NS_SAML2, NS_EIDAS, NS_DS, NS_MD

class SAMLAuthnRequestGenerator:
    """
    Generates compliant eIDAS SAML 2.0 AuthnRequest XML documents.
    """
    def __init__(
        self,
        sp_entity_id: str = "http://sp.local:9090/SP/Metadata",
        acs_url: str = "http://sp.local:9090/SP/ReturnPage",
        destination_url: str = "http://peps.local:9090/PEPS/ServiceProvider",
        provider_name: str = "Bilanx-eIDAS-SP",
        sp_type: str = "public",
    ):
        self.sp_entity_id = sp_entity_id
        self.acs_url = acs_url
        self.destination_url = destination_url
        self.provider_name = provider_name
        self.sp_type = sp_type

    def generate(
        self,
        request_id: Optional[str] = None,
        loa: str = "substantial",  # 'low', 'substantial', 'high'
        relay_state: Optional[str] = None,
    ) -> Tuple[str, str, str]:
        """
        Returns (request_id, xml_string, base64_string)
        """
        req_id = request_id or f"_authn_{int(datetime.now(timezone.utc).timestamp())}_{os.urandom(6).hex()}"
        issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Standardize LoA URI
        if not loa.startswith("http"):
            loa_uri = f"http://eidas.europa.eu/LoA/{loa.lower()}"
        else:
            loa_uri = loa

        xml = (
            f'<saml2p:AuthnRequest xmlns:saml2p="{NS_SAML2P}" xmlns:saml2="{NS_SAML2}" xmlns:eidas="{NS_EIDAS}" '
            f'AssertionConsumerServiceURL="{self.acs_url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" '
            f'Destination="{self.destination_url}" ForceAuthn="true" ID="{req_id}" IsPassive="false" '
            f'IssueInstant="{issue_instant}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
            f'ProviderName="{self.provider_name}" Version="2.0">'
            f'<saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{self.sp_entity_id}</saml2:Issuer>'
            f'<saml2p:Extensions><eidas:SPType>{self.sp_type}</eidas:SPType></saml2p:Extensions>'
            f'<saml2p:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>'
            f'<saml2p:RequestedAuthnContext Comparison="minimum">'
            f'<saml2:AuthnContextClassRef>{loa_uri}</saml2:AuthnContextClassRef>'
            f'</saml2p:RequestedAuthnContext>'
            f'</saml2p:AuthnRequest>'
        )

        b64 = base64.b64encode(xml.encode("utf-8")).decode("utf-8")
        return req_id, xml, b64

# =============================================================================
# SP METADATA GENERATOR
# =============================================================================

class SAMLMetadataGenerator:
    """
    Generates compliant SAML 2.0 EntityDescriptor metadata XML for Service Providers.
    """
    def __init__(
        self,
        sp_entity_id: str = "http://sp.local:9090/SP/Metadata",
        acs_url: str = "http://sp.local:9090/SP/ReturnPage",
        slo_url: Optional[str] = None,
        signing_cert_pem: Optional[str] = None,
        encryption_cert_pem: Optional[str] = None,
        sp_type: str = "public",
    ):
        self.sp_entity_id = sp_entity_id
        self.acs_url = acs_url
        self.slo_url = slo_url or acs_url.replace("/ReturnPage", "/SingleLogout").replace("/acs", "/slo")
        self.signing_cert_pem = signing_cert_pem
        self.encryption_cert_pem = encryption_cert_pem or signing_cert_pem
        self.sp_type = sp_type

    def generate(self) -> str:
        cert_b64 = ""
        if self.signing_cert_pem:
            lines = [l.strip() for l in self.signing_cert_pem.strip().splitlines() if not l.startswith("-----")]
            cert_b64 = "".join(lines)

        key_descriptors = ""
        if cert_b64:
            key_descriptors = (
                f'<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="{NS_DS}"><ds:X509Data>'
                f'<ds:X509Certificate>{cert_b64}</ds:X509Certificate>'
                f'</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
                f'<md:KeyDescriptor use="encryption"><ds:KeyInfo xmlns:ds="{NS_DS}"><ds:X509Data>'
                f'<ds:X509Certificate>{cert_b64}</ds:X509Certificate>'
                f'</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
            )

        now = datetime.now(timezone.utc)
        valid_until = (now + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")

        xml = (
            f'<md:EntityDescriptor xmlns:md="{NS_MD}" xmlns:ds="{NS_DS}" xmlns:eidas="{NS_EIDAS}" '
            f'entityID="{self.sp_entity_id}" validUntil="{valid_until}">'
            f'<md:Extensions><eidas:SPType>{self.sp_type}</eidas:SPType></md:Extensions>'
            f'<md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" '
            f'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            f'{key_descriptors}'
            f'<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{self.slo_url}"/>'
            f'<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{self.acs_url}" index="0" isDefault="true"/>'
            f'</md:SPSSODescriptor>'
            f'</md:EntityDescriptor>'
        )
        return xml

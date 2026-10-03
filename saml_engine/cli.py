"""
Command Line Interface for eIDAS 2.0 SAML Engine
Supports subprocess invocation from Node.js server.ts or shell runners.
"""

import sys
import json
import base64
import argparse
from typing import Dict, Any

from .engine import (
    SAMLValidationEngine,
    SAMLAuthnRequestGenerator,
    SAMLMetadataGenerator,
)
from .fixtures import SP_RSA_CERT_PEM

def read_input_payload() -> Dict[str, Any]:
    if not sys.stdin.isatty():
        try:
            content = sys.stdin.read().strip()
            if content.startswith("{") and content.endswith("}"):
                return json.loads(content)
            elif content:
                return {"xml_content": content}
        except Exception:
            pass
    return {}

def main():
    parser = argparse.ArgumentParser(description="eIDAS 2.0 SAML Engine CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: generate-authn-request
    gen_parser = subparsers.add_parser("generate-authn-request", help="Generate SAML 2.0 AuthnRequest")
    gen_parser.add_argument("--sp-entity-id", default="http://localhost:3000/saml/metadata")
    gen_parser.add_argument("--acs-url", default="http://localhost:3000/saml/acs")
    gen_parser.add_argument("--destination", default="http://peps.local:9090/PEPS/ServiceProvider")
    gen_parser.add_argument("--loa", default="substantial")
    gen_parser.add_argument("--relay-state", default="")

    # Subcommand: validate-response
    val_parser = subparsers.add_parser("validate-response", help="Validate SAML 2.0 Response")
    val_parser.add_argument("--xml", help="Direct XML string or base64-encoded SAMLResponse")
    val_parser.add_argument("--audience", help="Expected SP Audience URI")
    val_parser.add_argument("--expected-request-id", help="Expected AuthnRequest ID for InResponseTo correlation")
    val_parser.add_argument("--skew", type=int, default=300, help="Allowed clock skew in seconds")

    # Subcommand: metadata
    meta_parser = subparsers.add_parser("metadata", help="Generate SP EntityDescriptor Metadata XML")
    meta_parser.add_argument("--sp-entity-id", default="http://localhost:3000/saml/metadata")
    meta_parser.add_argument("--acs-url", default="http://localhost:3000/saml/acs")

    args = parser.parse_args()
    stdin_data = read_input_payload()

    if args.command == "generate-authn-request":
        sp_id = stdin_data.get("sp_entity_id") or args.sp_entity_id
        acs = stdin_data.get("acs_url") or args.acs_url
        dest = stdin_data.get("destination") or args.destination
        loa = stdin_data.get("loa") or args.loa
        relay_state = stdin_data.get("relay_state") or args.relay_state

        generator = SAMLAuthnRequestGenerator(
            sp_entity_id=sp_id,
            acs_url=acs,
            destination_url=dest,
        )
        req_id, xml, b64 = generator.generate(loa=loa, relay_state=relay_state)

        result = {
            "success": True,
            "request_id": req_id,
            "destination": dest,
            "saml_request_xml": xml,
            "saml_request_base64": b64,
            "relay_state": relay_state,
        }
        print(json.dumps(result))

    elif args.command == "validate-response":
        raw_xml = (
            stdin_data.get("xml_content")
            or stdin_data.get("SAMLResponse")
            or stdin_data.get("saml_response")
            or args.xml
            or ""
        )

        # Check if base64 encoded
        cleaned = raw_xml.strip()
        if not cleaned.startswith("<"):
            try:
                decoded = base64.b64decode(cleaned).decode("utf-8")
                if decoded.strip().startswith("<"):
                    cleaned = decoded
            except Exception:
                pass

        if not cleaned:
            print(json.dumps({
                "success": False,
                "is_valid": False,
                "error_message": "No XML content provided for validation.",
            }))
            sys.exit(1)

        engine = SAMLValidationEngine(
            clock_skew_seconds=args.skew,
        )
        exp_req_id = args.expected_request_id or stdin_data.get("expected_request_id")
        res = engine.validate_response(
            xml_string=cleaned,
            expected_request_id=exp_req_id,
            expected_audience=args.audience or stdin_data.get("audience"),
        )

        output = {
            "success": res.is_valid,
            "is_valid": res.is_valid,
            "error_message": res.error_message,
            "claims": res.claims,
            "pos_context": res.pos_context.to_dict() if res.pos_context else None,
        }
        print(json.dumps(output))
        if not res.is_valid:
            sys.exit(1)

    elif args.command == "metadata":
        sp_id = stdin_data.get("sp_entity_id") or args.sp_entity_id
        acs = stdin_data.get("acs_url") or args.acs_url

        generator = SAMLMetadataGenerator(
            sp_entity_id=sp_id,
            acs_url=acs,
            signing_cert_pem=SP_RSA_CERT_PEM,
        )
        xml = generator.generate()
        print(xml)

if __name__ == "__main__":
    main()

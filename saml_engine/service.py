import os
import sys
import base64
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any

# Robust import handling for package vs standalone execution
try:
    from saml_engine.engine import (
        SAMLValidationEngine,
        SAMLAuthnRequestGenerator,
        SAMLMetadataGenerator,
    )
    from saml_engine.mapping import SAMLToPOSMapper
    from saml_engine.fixtures import SP_RSA_CERT_PEM
except ImportError:
    from engine import (
        SAMLValidationEngine,
        SAMLAuthnRequestGenerator,
        SAMLMetadataGenerator,
    )
    from mapping import SAMLToPOSMapper
    from fixtures import SP_RSA_CERT_PEM

app = FastAPI(
    title="SAML 2.0 eIDAS Retail POS Ingestion Service",
    description="Custom microservice for high-stakes retail environments to parse & map eIDAS SAML claims securely.",
    version="2.0.0"
)

# Configuration derived from custom XML rules & environment
ALLOWED_ISSUERS = [
    "http://S-PEPS.gov.xx",
    "http://cef-eid-build-1:8080/EidasNode/ServiceMetadata",
    "http://sp.local:9090/SP/Metadata",
    "urn:bilanx:eidas:sp",
]

ALLOWED_DESTINATIONS = [
    "http://peps.local:9090/PEPS/ServiceProvider",
    "http://cef-eid-build-1:8080/EidasNode/ColleagueResponse",
    "http://sp.local:9090/SP/ReturnPage",
    "http://localhost:3000/saml/acs",
    "http://localhost:3000/auth/callback",
]

engine = SAMLValidationEngine(
    allowed_issuers=ALLOWED_ISSUERS,
    allowed_destinations=ALLOWED_DESTINATIONS,
)

class SAMLTextPayload(BaseModel):
    xml_content: Optional[str] = None
    SAMLResponse: Optional[str] = None
    audience: Optional[str] = None

class AuthnRequestPayload(BaseModel):
    sp_entity_id: Optional[str] = "http://localhost:3000/saml/metadata"
    acs_url: Optional[str] = "http://localhost:3000/saml/acs"
    destination: Optional[str] = "http://peps.local:9090/PEPS/ServiceProvider"
    loa: Optional[str] = "substantial"
    relay_state: Optional[str] = ""


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """
    Returns an elegant, responsive interactive developer dashboard to test SAML ingestion.
    """
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SAML 2.0 eIDAS POS Console</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
        <style>
            body { font-family: 'Inter', sans-serif; }
            pre, code { font-family: 'JetBrains Mono', monospace; }
        </style>
    </head>
    <body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col justify-between">
        <header class="border-b border-slate-800 bg-slate-900/50 backdrop-blur px-6 py-4 flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div class="h-3 w-3 rounded-full bg-orange-500 animate-pulse"></div>
                <h1 class="text-lg font-extrabold tracking-tight uppercase text-orange-500">SAML eIDAS Ingestion Engine</h1>
            </div>
            <span class="text-xs font-mono text-slate-500">DK-GATEWAY COPROCESSOR v1.0.0</span>
        </header>

        <main class="max-w-6xl w-full mx-auto p-6 grid grid-cols-1 md:grid-cols-2 gap-8 flex-1">
            <!-- Left Side: Inputs -->
            <div class="space-y-6">
                <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4 shadow-xl">
                    <h2 class="text-sm font-bold text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-2">1. Load SAML Document</h2>
                    
                    <div class="space-y-2">
                        <label class="block text-xs text-slate-400 font-mono">Paste SAML XML Payload</label>
                        <textarea id="xmlPaste" class="w-full h-48 bg-slate-950 text-amber-400 font-mono text-xs p-3 rounded-lg border border-slate-800 focus:outline-none focus:ring-1 focus:ring-orange-500" placeholder="Paste <saml2p:AuthnRequest> or <saml2p:Response> here..."></textarea>
                    </div>

                    <div class="flex gap-4">
                        <button onclick="loadPreset('authn')" class="flex-1 py-2 bg-slate-800 hover:bg-slate-700 font-mono text-xs font-bold uppercase rounded-lg border border-slate-700 transition">Preset: AuthnRequest</button>
                        <button onclick="loadPreset('response')" class="flex-1 py-2 bg-slate-800 hover:bg-slate-700 font-mono text-xs font-bold uppercase rounded-lg border border-slate-700 transition">Preset: Response</button>
                    </div>

                    <button onclick="processSAML()" class="w-full py-3 bg-orange-600 hover:bg-orange-500 text-white font-mono text-xs font-black uppercase rounded-lg border border-orange-500 shadow-[0_0_20px_rgba(249,115,22,0.2)] transition duration-200">Ingest & Verify Token</button>
                </div>
            </div>

            <!-- Right Side: Outcomes -->
            <div class="space-y-6">
                <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4 shadow-xl min-h-[400px] flex flex-col justify-between">
                    <div>
                        <h2 class="text-sm font-bold text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-2">2. Processing & Validation Outcome</h2>
                        
                        <div id="outcome-placeholder" class="py-16 text-center text-slate-600 font-mono text-xs">
                            Awaiting SAML payload input...
                        </div>

                        <!-- Success view (Hidden by default) -->
                        <div id="outcome-success" class="hidden mt-4 space-y-4">
                            <div class="flex items-center justify-between bg-emerald-950/30 border border-emerald-500/50 p-3 rounded-lg">
                                <span class="font-mono text-xs text-emerald-400 font-black">VALIDATION SUCCESS</span>
                                <span class="text-[10px] font-mono bg-emerald-900 text-emerald-300 px-2 py-0.5 rounded border border-emerald-500/50">PASSED</span>
                            </div>

                            <div class="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-3 font-mono text-xs text-slate-300">
                                <div class="grid grid-cols-2 gap-2">
                                    <div>
                                        <span class="text-slate-500 block text-[10px]">VERIFIED USER ID:</span>
                                        <span id="pos-user-id" class="text-slate-200 font-bold"></span>
                                    </div>
                                    <div>
                                        <span class="text-slate-500 block text-[10px]">ASSIGNED POS ROLE:</span>
                                        <span id="pos-role" class="text-orange-400 font-bold"></span>
                                    </div>
                                </div>
                                <div class="border-t border-slate-800 pt-2">
                                    <span class="text-slate-500 block text-[10px]">eID LEVEL OF ASSURANCE:</span>
                                    <span id="pos-loa" class="text-indigo-400 font-bold"></span>
                                </div>
                                <div class="border-t border-slate-800 pt-2">
                                    <span class="text-slate-500 block text-[10px]">AUTHORIZED POS PERMISSIONS:</span>
                                    <div id="pos-permissions" class="flex flex-wrap gap-1.5 mt-1.5"></div>
                                </div>
                            </div>
                        </div>

                        <!-- Failure view (Hidden by default) -->
                        <div id="outcome-failure" class="hidden mt-4 space-y-4">
                            <div class="flex items-center justify-between bg-red-950/30 border border-red-500/50 p-3 rounded-lg">
                                <span class="font-mono text-xs text-red-400 font-black">VALIDATION BLOCKED</span>
                                <span class="text-[10px] font-mono bg-red-900 text-red-300 px-2 py-0.5 rounded border border-red-500/50">FAILED</span>
                            </div>
                            <div class="bg-slate-950 p-4 rounded-lg border border-slate-800 text-xs font-mono text-red-300">
                                <span class="text-red-500 font-bold block uppercase mb-1">REASON:</span>
                                <span id="failure-msg"></span>
                            </div>
                        </div>
                    </div>

                    <div class="border-t border-slate-800 pt-4">
                        <div class="text-[10px] font-mono text-slate-500 flex justify-between">
                            <span>REGISTRY LEDGER ID:</span>
                            <span class="text-slate-400">DK-SVS-LEDGER-90X</span>
                        </div>
                    </div>
                </div>
            </div>
        </main>

        <footer class="border-t border-slate-800 bg-slate-950/80 px-6 py-4 text-center text-xs font-mono text-slate-600">
            &copy; 2026 European Commission | Dual-Key eIDAS Security Protocol (DK-SVS)
        </footer>

        <script>
            const presets = {
                authn: `<saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" AssertionConsumerServiceURL="http://sp.local:9090/SP/ReturnPage" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" Destination="http://peps.local:9090/PEPS/ServiceProvider" ForceAuthn="true" ID="_d048cb317813845b32a7a2b75f3bad59" IsPassive="false" IssueInstant="${new Date().toISOString()}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ProviderName="DEMO-SP" Version="2.0">\\n    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://S-PEPS.gov.xx</saml2:Issuer>\\n    <saml2p:RequestedAuthnContext Comparison="minimum">\\n        <saml2:AuthnContextClassRef>http://eidas.europa.eu/LoA/low</saml2:AuthnContextClassRef>\\n    </saml2p:RequestedAuthnContext>\\n</saml2p:AuthnRequest>`,
                response: `<saml2p:Response xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Consent="urn:oasis:names:tc:SAML:2.0:consent:obtained" Destination="http://cef-eid-build-1:8080/EidasNode/ColleagueResponse" ID="_7POlm0XG6RUlrv67ArCVMe4cjc4IjIO5S2fe74-0yYbPRqbjJYl-v2hE4l6sqA2" InResponseTo="_BWujh-SYHdY7qT35CXZ8y.yk5tSK793zQoiavTqXe.i_AuVw0f9RTOEQOihenSv" IssueInstant="${new Date().toISOString()}" Version="2.0">\\n    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://cef-eid-build-1:8080/EidasNode/ServiceMetadata</saml2:Issuer>\\n    <saml2p:Status>\\n        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>\\n        <saml2p:StatusMessage>urn:oasis:names:tc:SAML:2.0:status:Success</saml2p:StatusMessage>\\n    </saml2p:Status>\\n</saml2p:Response>`
            };

            function loadPreset(type) {
                // Formatting replacing double backslashes
                document.getElementById('xmlPaste').value = presets[type].replace(/\\\\n/g, '\\n');
            }

            async function processSAML() {
                const xmlContent = document.getElementById('xmlPaste').value;
                const placeholder = document.getElementById('outcome-placeholder');
                const successDiv = document.getElementById('outcome-success');
                const failureDiv = document.getElementById('outcome-failure');

                placeholder.classList.add('hidden');
                successDiv.classList.add('hidden');
                failureDiv.classList.add('hidden');

                try {
                    const response = await fetch('/api/v1/ingest', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ xml_content: xmlContent })
                    });

                    const data = await response.json();
                    if (!response.ok || !data.is_valid) {
                        document.getElementById('failure-msg').innerText = data.error_message || 'Unknown verification error';
                        failureDiv.classList.remove('hidden');
                    } else {
                        document.getElementById('pos-user-id').innerText = data.pos_context.user_id;
                        document.getElementById('pos-role').innerText = data.pos_context.role;
                        document.getElementById('pos-loa').innerText = data.pos_context.level_of_assurance;
                        
                        const permissionsDiv = document.getElementById('pos-permissions');
                        permissionsDiv.innerHTML = '';
                        data.pos_context.permissions.forEach(p => {
                            const span = document.createElement('span');
                            span.className = 'bg-slate-800 text-slate-300 text-[9px] px-2 py-0.5 rounded border border-slate-700 uppercase';
                            span.innerText = p;
                            permissionsDiv.appendChild(span);
                        });

                        successDiv.classList.remove('hidden');
                    }
                } catch (e) {
                    document.getElementById('failure-msg').innerText = 'Connection to gateway coprocessor lost: ' + e.message;
                    failureDiv.classList.remove('hidden');
                }
            }
        </script>
    </body>
    </html>
    """
    return html_content

@app.post("/api/v1/authn-request/generate")
async def generate_authn_request(payload: AuthnRequestPayload):
    """
    Generates eIDAS 2.0 compliant SAML AuthnRequest.
    """
    try:
        generator = SAMLAuthnRequestGenerator(
            sp_entity_id=payload.sp_entity_id or "http://localhost:3000/saml/metadata",
            acs_url=payload.acs_url or "http://localhost:3000/saml/acs",
            destination_url=payload.destination or "http://peps.local:9090/PEPS/ServiceProvider",
        )
        req_id, xml, b64 = generator.generate(
            loa=payload.loa or "substantial",
            relay_state=payload.relay_state,
        )
        return {
            "success": True,
            "request_id": req_id,
            "destination": payload.destination,
            "saml_request_xml": xml,
            "saml_request_base64": b64,
            "relay_state": payload.relay_state,
        }
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error_message": str(e)}
        )

@app.post("/api/v1/response/validate")
async def validate_saml_response(payload: SAMLTextPayload):
    """
    Strict validation endpoint: verifies signature, temporal checks, audience, and extracts attributes.
    """
    raw_xml = payload.xml_content or payload.SAMLResponse or ""
    cleaned = raw_xml.strip()

    if not cleaned.startswith("<"):
        try:
            decoded = base64.b64decode(cleaned).decode("utf-8")
            if decoded.strip().startswith("<"):
                cleaned = decoded
        except Exception:
            pass

    if not cleaned:
        return JSONResponse(status_code=400, content={
            "is_valid": False,
            "error_message": "Missing XML content or SAMLResponse in payload."
        })

    res = engine.validate_response(
        xml_string=cleaned,
        expected_audience=payload.audience,
    )

    if not res.is_valid:
        return JSONResponse(status_code=401, content={
            "is_valid": False,
            "error_message": res.error_message,
        })

    return {
        "is_valid": True,
        "claims": res.claims,
        "pos_context": res.pos_context.to_dict() if res.pos_context else None,
    }

@app.get("/api/v1/metadata")
async def get_saml_metadata():
    """
    Returns SAML 2.0 SP EntityDescriptor Metadata XML.
    """
    generator = SAMLMetadataGenerator(
        sp_entity_id="http://localhost:3000/saml/metadata",
        acs_url="http://localhost:3000/saml/acs",
        signing_cert_pem=SP_RSA_CERT_PEM,
    )
    xml_content = generator.generate()
    return Response(content=xml_content, media_type="application/samlmetadata+xml")

@app.post("/api/v1/ingest")
async def ingest_saml_document(payload: SAMLTextPayload):
    """
    Core ingestion endpoint: validates against tailored rules, maps claims, and returns POS context.
    Retained for backward compatibility.
    """
    raw_xml = payload.xml_content or payload.SAMLResponse or ""
    cleaned = raw_xml.strip()

    if not cleaned.startswith("<"):
        try:
            decoded = base64.b64decode(cleaned).decode("utf-8")
            if decoded.strip().startswith("<"):
                cleaned = decoded
        except Exception:
            pass

    if not cleaned:
        return JSONResponse(status_code=400, content={
            "is_valid": False,
            "error_message": "Missing XML content in payload."
        })

    # Check if AuthnRequest or Response
    if "AuthnRequest" in cleaned:
        res = engine.validate_authn_request(cleaned)
    elif "Response" in cleaned:
        res = engine.validate_response(cleaned)
    else:
        return JSONResponse(status_code=400, content={
            "is_valid": False,
            "error_message": "Unsupported SAML type. Document root must be saml2p:AuthnRequest or saml2p:Response."
        })

    if not res.is_valid:
        return {
            "is_valid": False,
            "error_message": res.error_message
        }

    # Map verified claims to specific POS concepts
    pos_context = res.pos_context or SAMLToPOSMapper.map_claims_to_pos(res.claims)

    return {
        "is_valid": True,
        "claims": res.claims,
        "pos_context": pos_context.to_dict()
    }

if __name__ == "__main__":
    uvicorn.run("service:app", host="0.0.0.0", port=8000, reload=True)


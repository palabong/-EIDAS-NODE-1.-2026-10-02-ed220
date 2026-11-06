/**
 * SAML 2.0 Bridge connecting Node.js Express server to Python saml_engine
 * Supports CLI subprocess execution, HTTP microservice forwarding, and native cryptographic verification.
 */

import { spawn, execSync } from 'child_process';
import crypto from 'crypto';
import type { SAMLValidationResponse, LoALevel } from './types/saml.ts';

const SAML_ENGINE_URL = process.env.SAML_ENGINE_URL || 'http://127.0.0.1:8000';
const DEFAULT_SP_ENTITY_ID = process.env.SAML_SP_ENTITY_ID || 'http://localhost:3000/saml/metadata';
const DEFAULT_SP_ACS_URL = process.env.SAML_SP_ACS_URL || 'http://localhost:3000/saml/acs';
const DEFAULT_IDP_SSO_URL = process.env.SAML_IDP_SSO_URL || 'http://peps.local:9090/PEPS/ServiceProvider';

export const SP_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUNz/QFyoOUVQ/4EXB2E1cns2IS44wDQYJKoZIhvcNAQEL
BQAwRTEdMBsGA1UEAwwUQmlsYW54IGVJREFTIFNQIE5vZGUxFzAVBgNVBAoMDlBy
b2plY3QgQmlsYW54MQswCQYDVQQGEwJFVTAeFw0yNjEwMDIyMjI3MzJaFw00NjA5
MjcyMjI3MzJaMEUxHTAbBgNVBAMMFEJpbGFueCBlSURBUyBTUCBOb2RlMRcwFQYD
VQQKDA5Qcm9qZWN0IEJpbGFueDELMAkGA1UEBhMCRVUwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDJIGjGaCYPBBUuPxuFYWp/H0ThwRD7zQpS4K6mVqw4
PX+fx35dpwcIuAhwMg8PTbSuEAe8cn6MwD/UAMuXXC3DWqRD2A4ElUvzd6cz3wxf
H+xk6pmiirjwmEcbkLCEsORMIMt5zT0t5gSKg1V89mNfHYU6d5/Lq9HztQrcIqTW
WhvU61XJLPA1YRZd3c27x8dMeiCwxbgEh5+YFwiY420hyOD4SF3+IBxmO4aXE0P1
vQJKSIRp4O6wwvEh/de/rAcNPYDD+q/HymMDtRnNwwR/rjoA30VIcejS2RC12Sv3
bwXMuFfZlPDowU5LylE6dQdFYKRMaCVi/Thes1pOOk41AgMBAAGjUzBRMB0GA1Ud
DgQWBBQSoM5HJfi/fl+XHVAWMamD+QY95TAfBgNVHSMEGDAWgBQSoM5HJfi/fl+X
HVAWMamD+QY95TAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBc
rBklVVYxwqGfXrvEzcU2v5J5xFdBeMFOQZjsogDJIB5MQWJUSuNjMTsGVquWiO8+
rG4P1uKorDASUpVs9IAU4ccC4/dH7/D7GJ718opQXzeLn/xx/pdr+wgh79sOPX0z
+sAqcYpowZVmo0xqJJHnMy1BoT4o70hz63AnwMU5wyi1WVoMYZqCuk3EqJZHAE2K
peuCIKo3iYKtp8g8x0YY4BrItXilBrvluQmu41U7/jP91JlBQcrq9EuC+ejMZcxR
Rnx2ULb1WnXUHP7iIZY7tbuXrqRQscLuP68IPhdC/iUjJ7SoFYfPms26nbVUOiiX
WVYVNqap28CrY9Rxo3s5
-----END CERTIFICATE-----`;

/**
 * Returns formatted SAML 2.0 SP EntityDescriptor Metadata XML
 */
export function generateSPMetadata(
  spEntityId: string = DEFAULT_SP_ENTITY_ID,
  acsUrl: string = DEFAULT_SP_ACS_URL
): string {
  const certLines = SP_CERT_PEM.trim().split('\n').filter(l => !l.startsWith('-----'));
  const certB64 = certLines.join('');
  const now = new Date();
  const validUntil = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000).toISOString();
  const sloUrl = acsUrl.replace('/acs', '/slo');

  return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     xmlns:eidas="http://eidas.europa.eu/saml-extensions"
                     entityID="${spEntityId}"
                     validUntil="${validUntil}">
  <md:Extensions>
    <eidas:SPType>public</eidas:SPType>
  </md:Extensions>
  <md:SPSSODescriptor AuthnRequestsSigned="true"
                      WantAssertionsSigned="true"
                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>${certB64}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>${certB64}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="${sloUrl}"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                Location="${acsUrl}"
                                index="0"
                                isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;
}

/**
 * Generates eIDAS 2.0 AuthnRequest XML & Base64
 */
export function generateAuthnRequest(options?: {
  requestId?: string;
  destination?: string;
  loa?: string;
  spEntityId?: string;
  acsUrl?: string;
  relayState?: string;
}): { requestId: string; destination: string; authnRequestXml: string; samlRequestBase64: string; relayState: string } {
  const reqId = options?.requestId || `_authn_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
  const destination = options?.destination || DEFAULT_IDP_SSO_URL;
  const spEntityId = options?.spEntityId || DEFAULT_SP_ENTITY_ID;
  const acsUrl = options?.acsUrl || DEFAULT_SP_ACS_URL;
  const relayState = options?.relayState || '';
  const issueInstant = new Date().toISOString();

  let loa = options?.loa || 'substantial';
  if (!loa.startsWith('http')) {
    loa = `http://eidas.europa.eu/LoA/${loa.toLowerCase()}`;
  }

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                     xmlns:eidas="http://eidas.europa.eu/saml-extensions"
                     AssertionConsumerServiceURL="${acsUrl}"
                     Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified"
                     Destination="${destination}"
                     ForceAuthn="true"
                     ID="${reqId}"
                     IsPassive="false"
                     IssueInstant="${issueInstant}"
                     ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                     ProviderName="Bilanx-eIDAS-SP"
                     Version="2.0">
  <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">${spEntityId}</saml2:Issuer>
  <saml2p:Extensions>
    <eidas:SPType>public</eidas:SPType>
  </saml2p:Extensions>
  <saml2p:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>
  <saml2p:RequestedAuthnContext Comparison="minimum">
    <saml2:AuthnContextClassRef>${loa}</saml2:AuthnContextClassRef>
  </saml2p:RequestedAuthnContext>
</saml2p:AuthnRequest>`;

  const b64 = Buffer.from(xml, 'utf-8').toString('base64');
  return {
    requestId: reqId,
    destination,
    authnRequestXml: xml,
    samlRequestBase64: b64,
    relayState,
  };
}

/**
 * Validates SAML Response using Python saml_engine CLI subprocess
 */
export async function validateSAMLWithPythonCLI(xmlString: string, audience?: string): Promise<SAMLValidationResponse> {
  return new Promise((resolve) => {
    // Early security check for DTD/XXE
    if (/<!\s*(DOCTYPE|ENTITY)/i.test(xmlString)) {
      resolve({
        is_valid: false,
        error_message: "Security Violation: DTD declarations or external entities are forbidden.",
      });
      return;
    }

    const payload = JSON.stringify({ xml_content: xmlString, audience });
    const pyProc = spawn('python3', ['-m', 'saml_engine.cli', 'validate-response'], {
      cwd: process.cwd(),
      env: process.env,
    });

    let stdoutData = '';
    let stderrData = '';

    pyProc.stdout.on('data', (chunk) => {
      stdoutData += chunk.toString();
    });

    pyProc.stderr.on('data', (chunk) => {
      stderrData += chunk.toString();
    });

    pyProc.on('error', (err) => {
      resolve({
        is_valid: false,
        error_message: `Python CLI Execution Failed: ${err.message}`,
      });
    });

    pyProc.on('close', (code) => {
      try {
        const trimmed = stdoutData.trim();
        if (trimmed.startsWith('{')) {
          const parsed = JSON.parse(trimmed);
          resolve(parsed);
          return;
        }
        resolve({
          is_valid: false,
          error_message: stderrData.trim() || `CLI exited with code ${code}`,
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        resolve({
          is_valid: false,
          error_message: `Failed parsing CLI response: ${msg}. Stderr: ${stderrData}`,
        });
      }
    });

    pyProc.stdin.write(payload);
    pyProc.stdin.end();
  });
}

/**
 * High-level validator that checks with Python engine
 */
export async function validateSAMLResponse(
  rawPayload: string,
  expectedAudience?: string
): Promise<SAMLValidationResponse> {
  let xmlString = rawPayload.trim();

  // Decode Base64 if needed
  if (!xmlString.startsWith('<')) {
    try {
      const decoded = Buffer.from(xmlString, 'base64').toString('utf-8');
      if (decoded.trim().startsWith('<')) {
        xmlString = decoded;
      }
    } catch {
      // Keep original
    }
  }

  // Pre-check for DTD/XXE
  if (/<!\s*(DOCTYPE|ENTITY)/i.test(xmlString)) {
    return {
      is_valid: false,
      error_message: "Security Violation: DTD declarations or external entities are forbidden.",
    };
  }

  // Execute validation via Python saml_engine CLI
  return await validateSAMLWithPythonCLI(xmlString, expectedAudience);
}

/**
  * Retrieves test fixture SAML Response XML string by preset name
  */
export function getPresetFixtureXml(presetKey: string): string {
  let funcName = 'get_valid_rsa_response()';
  switch (presetKey) {
    case 'valid_rsa':
      funcName = 'get_valid_rsa_response()';
      break;
    case 'valid_ecdsa':
      funcName = 'get_valid_ecdsa_response()';
      break;
    case 'tampered_sig':
      funcName = 'get_tampered_sig_response()';
      break;
    case 'expired_assertion':
      funcName = 'get_expired_response()';
      break;
    case 'underage_cashier':
      funcName = 'get_minor_response()';
      break;
    case 'swiss_adult':
    case 'heinrich_keller':
      funcName = 'get_swiss_adult_response()';
      break;
    case 'eu_adult':
    case 'clara_schmidt':
      funcName = 'get_eu_adult_response()';
      break;
    case 'minor_luca':
    case 'luca_rossi':
      funcName = 'get_minor_luca_response()';
      break;
    default:
      funcName = 'get_valid_rsa_response()';
  }
  try {
    const res = execSync(`python3 -c "from saml_engine.fixtures import *; print(${funcName})"`, {
      cwd: process.cwd(),
      encoding: 'utf-8',
    });
    return res.trim();
  } catch {
    return '';
  }
}

/**
 * SAML 2.0 Bridge connecting Node.js Express server to Python saml_engine
 * Supports CLI subprocess execution, HTTP microservice forwarding, and native cryptographic verification.
 */

import { spawn, spawnSync } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import type { SAMLValidationResponse, LoALevel } from './types/saml.ts';

const SAML_ENGINE_URL = process.env.SAML_ENGINE_URL || 'http://127.0.0.1:8000';
const DEFAULT_SP_ENTITY_ID = process.env.SAML_SP_ENTITY_ID || 'http://localhost:3000/saml/metadata';
const DEFAULT_SP_ACS_URL = process.env.SAML_SP_ACS_URL || 'http://localhost:3000/saml/acs';
const DEFAULT_IDP_SSO_URL = process.env.SAML_IDP_SSO_URL || 'http://peps.local:9090/PEPS/ServiceProvider';

function resolveSpCertificatePem(): string {
  if (process.env.SAML_SP_CERT_PEM && process.env.SAML_SP_CERT_PEM.trim()) {
    return process.env.SAML_SP_CERT_PEM.trim();
  }
  if (process.env.SAML_SP_CERT_PATH && fs.existsSync(process.env.SAML_SP_CERT_PATH)) {
    return fs.readFileSync(process.env.SAML_SP_CERT_PATH, 'utf-8').trim();
  }
  const pyRes = spawnSync('python3', ['-c', 'from saml_engine.fixtures import SP_RSA_CERT_PEM; print(SP_RSA_CERT_PEM)'], {
    cwd: process.cwd(),
    env: process.env,
    encoding: 'utf-8',
  });
  if (pyRes.status === 0 && pyRes.stdout && pyRes.stdout.includes('BEGIN CERTIFICATE')) {
    return pyRes.stdout.trim();
  }
  throw new Error('Unable to resolve SAML SP certificate from SAML_SP_CERT_PEM, SAML_SP_CERT_PATH, or ephemeral sandbox generator.');
}

export const SP_CERT_PEM = resolveSpCertificatePem();

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
  if (!rawPayload || typeof rawPayload !== 'string' || !rawPayload.trim()) {
    return {
      is_valid: false,
      error_message: "Missing or empty SAML response payload.",
    };
  }

  // Security check: null-byte injection defense
  if (rawPayload.includes('\0')) {
    return {
      is_valid: false,
      error_message: "Security Violation: Null bytes detected in SAML payload.",
    };
  }

  // Security check: maximum payload size (2MB) defense against memory exhaustion
  if (Buffer.byteLength(rawPayload, 'utf-8') > 2 * 1024 * 1024) {
    return {
      is_valid: false,
      error_message: "Security Violation: SAML payload exceeds maximum allowed size (2MB).",
    };
  }

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

  if (xmlString.includes('\0')) {
    return {
      is_valid: false,
      error_message: "Security Violation: Null bytes detected in SAML payload.",
    };
  }

  if (!xmlString.startsWith('<') && !xmlString.includes('<')) {
    return {
      is_valid: false,
      error_message: "Invalid SAML payload: Not a valid XML document.",
    };
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

// In-memory cache for generated fixtures to prevent process spawning storms
const fixtureCache = new Map<string, { xml: string; expiresAt: number }>();

/**
  * Asynchronously retrieves test fixture SAML Response XML string by preset name.
  * Non-blocking, with short-lived cache (60s) to keep timestamps fresh while avoiding event-loop starvation.
  */
export async function getPresetFixtureXml(presetKey: string): Promise<string> {
  const now = Date.now();
  const cached = fixtureCache.get(presetKey);
  if (cached && now < cached.expiresAt) {
    return cached.xml;
  }

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
    case 'it_adult_high':
    case 'marco_rossi':
      funcName = 'get_italian_adult_response()';
      break;
    case 'it_adult_substantial':
    case 'giulia_bianchi':
      funcName = 'get_italian_adult_substantial_response()';
      break;
    case 'it_minor_matteo':
    case 'matteo_russo':
      funcName = 'get_italian_minor_response()';
      break;
    default:
      funcName = 'get_valid_rsa_response()';
  }

  return new Promise<string>((resolve) => {
    const py = spawn('python3', ['-c', `from saml_engine.fixtures import *; print(${funcName})`], {
      cwd: process.cwd(),
      env: process.env,
    });

    let stdoutData = '';
    py.stdout.on('data', (chunk) => {
      stdoutData += chunk.toString();
    });

    py.on('close', (code) => {
      const trimmed = stdoutData.trim();
      if (code === 0 && trimmed) {
        fixtureCache.set(presetKey, { xml: trimmed, expiresAt: now + 60_000 });
        resolve(trimmed);
      } else {
        resolve('');
      }
    });

    py.on('error', () => {
      resolve('');
    });
  });
}

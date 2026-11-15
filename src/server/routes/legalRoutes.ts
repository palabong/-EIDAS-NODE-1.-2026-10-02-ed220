/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';

export const APP_BRAND_NAME = 'Project Bilanx — Credentials Hub';
export const APP_SHORT_NAME = 'Project Bilanx';
export const EFFECTIVE_DATE = 'November 15, 2026';
export const CONTACT_EMAIL = 'daniele.palagi92@gmail.com';

function resolveBaseOrigin(req: express.Request): string {
  if (process.env.APP_ORIGIN) {
    return process.env.APP_ORIGIN.replace(/\/+$/, '');
  }
  const proto = (req.headers['x-forwarded-proto'] as string)?.split(',')[0]?.trim() || req.protocol || 'https';
  const host = req.get('host') || 'bilanx.expert';
  return `${proto}://${host}`;
}

const SHARED_STYLES = `
  :root {
    --bg-page: #020617;
    --bg-card: #0f172a;
    --bg-elevated: #1e293b;
    --border-subtle: #1e293b;
    --border-accent: #3b82f6;
    --text-primary: #f8fafc;
    --text-secondary: #cbd5e1;
    --text-muted: #94a3b8;
    --accent-blue: #60a5fa;
    --accent-emerald: #34d399;
  }
  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    background-color: var(--bg-page);
    color: var(--text-secondary);
    line-height: 1.65;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }
  header {
    background-color: rgba(15, 23, 42, 0.95);
    border-bottom: 1px solid var(--border-subtle);
    padding: 1.25rem 1.5rem;
    position: sticky;
    top: 0;
    z-index: 20;
  }
  .header-inner {
    max-width: 960px;
    margin: 0 auto;
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
  }
  .brand-identity {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    text-decoration: none;
    color: var(--text-primary);
  }
  .brand-badge {
    width: 2.5rem;
    height: 2.5rem;
    border-radius: 0.625rem;
    background: rgba(59, 130, 246, 0.15);
    border: 1px solid rgba(96, 165, 250, 0.4);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--accent-blue);
    font-weight: 800;
    font-size: 1rem;
  }
  .brand-title {
    font-weight: 800;
    font-size: 1.05rem;
    letter-spacing: -0.01em;
    color: var(--text-primary);
    display: block;
  }
  .brand-subtitle {
    font-size: 0.7rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    display: block;
  }
  nav ul {
    display: flex;
    list-style: none;
    gap: 1.25rem;
    align-items: center;
  }
  nav a {
    color: var(--text-secondary);
    text-decoration: none;
    font-size: 0.85rem;
    font-weight: 600;
    padding: 0.4rem 0.75rem;
    border-radius: 0.375rem;
    transition: background-color 0.15s ease, color 0.15s ease;
  }
  nav a:hover,
  nav a[aria-current="page"] {
    background-color: var(--bg-elevated);
    color: var(--accent-blue);
  }
  main {
    flex: 1;
    max-width: 960px;
    width: 100%;
    margin: 0 auto;
    padding: 2.5rem 1.5rem 4rem;
  }
  .hero-banner {
    background-color: var(--bg-card);
    border: 1px solid var(--border-subtle);
    border-left: 4px solid var(--border-accent);
    border-radius: 0.75rem;
    padding: 2rem;
    margin-bottom: 2rem;
  }
  .meta-pill {
    display: inline-block;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.75rem;
    color: var(--accent-blue);
    background: rgba(59, 130, 246, 0.12);
    border: 1px solid rgba(59, 130, 246, 0.3);
    padding: 0.25rem 0.65rem;
    border-radius: 9999px;
    margin-bottom: 0.75rem;
  }
  h1 {
    font-size: 2rem;
    font-weight: 800;
    color: var(--text-primary);
    letter-spacing: -0.02em;
    margin-bottom: 0.5rem;
  }
  h2 {
    font-size: 1.35rem;
    font-weight: 700;
    color: var(--text-primary);
    margin: 2.25rem 0 0.85rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border-subtle);
  }
  h3 {
    font-size: 1.05rem;
    font-weight: 700;
    color: var(--accent-blue);
    margin: 1.35rem 0 0.5rem;
  }
  p {
    margin-bottom: 1rem;
    color: var(--text-secondary);
  }
  ul, ol {
    margin: 0.5rem 0 1.25rem 1.5rem;
    color: var(--text-secondary);
  }
  li {
    margin-bottom: 0.5rem;
  }
  strong {
    color: var(--text-primary);
  }
  code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.85em;
    background-color: var(--bg-elevated);
    color: var(--accent-blue);
    padding: 0.15rem 0.4rem;
    border-radius: 0.25rem;
  }
  .callout-box {
    background-color: rgba(16, 185, 129, 0.08);
    border: 1px solid rgba(52, 211, 153, 0.3);
    border-radius: 0.625rem;
    padding: 1.25rem 1.5rem;
    margin: 1.5rem 0;
  }
  .callout-title {
    color: var(--accent-emerald);
    font-weight: 700;
    font-size: 0.95rem;
    margin-bottom: 0.4rem;
    display: block;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 1.25rem 0 1.75rem;
    background-color: var(--bg-card);
    border: 1px solid var(--border-subtle);
    border-radius: 0.5rem;
    overflow: hidden;
    font-size: 0.9rem;
  }
  th, td {
    text-align: left;
    padding: 0.85rem 1rem;
    border-bottom: 1px solid var(--border-subtle);
    vertical-align: top;
  }
  th {
    background-color: var(--bg-elevated);
    color: var(--text-primary);
    font-weight: 700;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  a {
    color: var(--accent-blue);
  }
  footer {
    background-color: var(--bg-card);
    border-top: 1px solid var(--border-subtle);
    padding: 2rem 1.5rem;
    font-size: 0.85rem;
    color: var(--text-muted);
  }
  .footer-inner {
    max-width: 960px;
    margin: 0 auto;
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
  }
  .footer-links {
    display: flex;
    gap: 1.25rem;
    list-style: none;
    margin: 0;
    padding: 0;
  }
`;

export function renderPrivacyPolicyHtml(baseOrigin: string = 'https://bilanx.expert'): string {
  const canonicalUrl = `${baseOrigin}/privacy`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Privacy Policy — ${APP_BRAND_NAME}</title>
  <meta name="description" content="Official Privacy Policy and Google OAuth 2.0 User Data Disclosure for ${APP_BRAND_NAME} (DK-SVS eIDAS 2.0 Node Sandbox).">
  <link rel="canonical" href="${canonicalUrl}">
  <style>${SHARED_STYLES}</style>
</head>
<body>
  <header>
    <div class="header-inner">
      <a href="/" class="brand-identity">
        <span class="brand-badge" aria-hidden="true">BX</span>
        <span>
          <span class="brand-title">${APP_BRAND_NAME}</span>
          <span class="brand-subtitle">DK-SVS Sovereign eIDAS 2.0 Node Sandbox</span>
        </span>
      </a>
      <nav aria-label="Primary legal navigation">
        <ul>
          <li><a href="/">Home &amp; Application</a></li>
          <li><a href="/privacy" aria-current="page">Privacy Policy</a></li>
          <li><a href="/terms">Terms of Service</a></li>
        </ul>
      </nav>
    </div>
  </header>

  <main>
    <div class="hero-banner">
      <span class="meta-pill">EFFECTIVE DATE: ${EFFECTIVE_DATE} · GDPR &amp; GOOGLE OAUTH 2.0 COMPLIANT</span>
      <h1>Privacy Policy — ${APP_BRAND_NAME}</h1>
      <p>
        This Privacy Policy governs the collection, verification, storage, and protection of information by
        <strong>${APP_BRAND_NAME}</strong> (also referred to as <strong>${APP_SHORT_NAME}</strong> or the
        <strong>DK-SVS eIDAS 2.0 Node Sandbox</strong>). It explicitly details how we handle Google User Data
        obtained via Google Identity Services (OAuth 2.0 / OpenID Connect) and how our Zero-Knowledge Proof (ZKP)
        validation architecture protects end-user privacy.
      </p>
    </div>

    <div class="callout-box">
      <span class="callout-title">Google API Services User Data Policy — Limited Use Disclosure</span>
      <p style="margin-bottom: 0;">
        <strong>${APP_BRAND_NAME}</strong>'s use and transfer to any other app of information received from Google APIs
        adheres strictly to the
        <a href="https://developers.google.com/terms/api-services-user-data-policy" target="_blank" rel="noopener noreferrer">Google API Services User Data Policy</a>,
        including the Limited Use requirements. We request only basic OpenID Connect identity scopes
        (<code>openid</code>, <code>email</code>, <code>profile</code>) to authenticate evaluators and operators,
        and we never sell, rent, or transfer Google user data to third parties or use it for advertising or AI model training.
      </p>
    </div>

    <h2>1. Data Controller &amp; Contact Information</h2>
    <p>
      The data controller responsible for the operation of <strong>${APP_BRAND_NAME}</strong> is:
    </p>
    <ul>
      <li><strong>Controller / Architect:</strong> Daniele Palagi (Project Bilanx Sovereign Validation Systems)</li>
      <li><strong>Jurisdiction:</strong> Lucca, Tuscany, Italy (European Union — GDPR Regulation (EU) 2016/679 &amp; Swiss Federal Act on Data Protection nFADP)</li>
      <li><strong>Privacy &amp; Compliance Contact:</strong> <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a></li>
      <li><strong>Official Application Home Page:</strong> <a href="${baseOrigin}/">${baseOrigin}/</a></li>
      <li><strong>Official Privacy Policy URL:</strong> <a href="${canonicalUrl}">${canonicalUrl}</a></li>
    </ul>

    <h2>2. Information We Collect and Access</h2>
    <p>
      <strong>${APP_BRAND_NAME}</strong> operates under a strict data-minimization architecture split into two distinct contexts:
      (A) Authenticated Operator/Evaluator Sessions via Google Sign-In, and (B) Zero-PII Cryptographic Age-Gate Verification.
    </p>

    <h3>2.1 Google OAuth 2.0 User Data (Operator &amp; Evaluator Authentication)</h3>
    <p>
      When you choose to sign in to <strong>${APP_BRAND_NAME}</strong> using Google Identity Services ("Sign in with Google"),
      our backend verifies the cryptographic JSON Web Token (ID Token) issued by <code>https://accounts.google.com</code>
      and accesses only the following basic OpenID Connect claims:
    </p>
    <table>
      <thead>
        <tr>
          <th>Data Element / Claim</th>
          <th>OAuth Scope</th>
          <th>Purpose of Collection</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>Google Subject Identifier</strong> (<code>sub</code>)</td>
          <td><code>openid</code></td>
          <td>Uniquely identifies the authenticated evaluator/operator session and binds security audit records.</td>
        </tr>
        <tr>
          <td><strong>Email Address &amp; Verification Status</strong> (<code>email</code>, <code>email_verified</code>)</td>
          <td><code>email</code></td>
          <td>Displays the verified operator identity in the dashboard header and records accountable access logs.</td>
        </tr>
        <tr>
          <td><strong>Display Name &amp; Profile Avatar URL</strong> (<code>name</code>, <code>picture</code>)</td>
          <td><code>profile</code></td>
          <td>Renders the active user badge within the authenticated application interface.</td>
        </tr>
        <tr>
          <td><strong>Technical Request Context</strong> (<code>ipAddress</code>, <code>userAgent</code>, <code>timestamp</code>)</td>
          <td>HTTP Transport</td>
          <td>Protects the node against unauthorized access, replay attacks, and maintains the security audit trail.</td>
        </tr>
      </tbody>
    </table>

    <h3>2.2 Zero-PII Consumer Cryptographic Verification (DK-SVS &amp; Scheme B2)</h3>
    <p>
      For retail and age-restricted compliance workflows within the Dual-Key Sovereign Validation System (DK-SVS),
      <strong>zero consumer Personally Identifiable Information (PII) is transmitted or stored</strong>:
    </p>
    <ul>
      <li><strong>Key 1 (Institutional Binding):</strong> Verifies authentic product or relying-party metadata using ECDSA P-256 signatures.</li>
      <li><strong>Key 2 (Consumer Age-Gate):</strong> Evaluates a fixed <strong>1,355-byte</strong> binary payload comprising Pedersen commitments on P-256 with a Nothing-Up-My-Sleeve (NUMS) generator and an 8-bit Non-Interactive Zero-Knowledge Proof (NIZKP Scheme B2) proving <code>age &ge; 18</code> without revealing date of birth, full name, or national identification numbers.</li>
      <li><strong>FIDO2 / WebAuthn Assertions:</strong> Stores only public key credentials, key IDs, and monotonic signature counters to prevent credential cloning and replay.</li>
    </ul>

    <h2>3. How We Use Your Information</h2>
    <p>We process the data described above strictly for the following operational purposes:</p>
    <ol>
      <li><strong>Cryptographic Authentication &amp; Session Management:</strong> Validating Google ID tokens via Google's public certs and issuing an encrypted, short-lived session token (<code>bilanx_sid</code> HTTP-only cookie with a 4-hour time-to-live).</li>
      <li><strong>Security &amp; Compliance Auditing:</strong> Recording authentication events (<code>LOGIN_SUCCESS</code>, <code>LOGIN_FAILURE</code>, <code>LOGOUT</code>, <code>COMPLIANCE_RUN</code>) in our local access log database to demonstrate regulatory accountability under eIDAS 2.0 and customs compliance directives.</li>
      <li><strong>Abuse &amp; Replay Prevention:</strong> Enforcing single-use cryptographic nonces, challenge TTLs, and rate limits across verification endpoints.</li>
    </ol>

    <h2>4. Data Sharing, Third-Party Disclosure &amp; Prohibitions</h2>
    <p>
      We treat all Google user data and security logs with strict confidentiality:
    </p>
    <ul>
      <li><strong>No Sale of Personal Data:</strong> We never sell, rent, lease, or trade Google user data or personal information to any third party.</li>
      <li><strong>No Advertising or Profiling:</strong> We never use Google user data for targeted advertising, retargeting, data brokering, or creditworthiness evaluation.</li>
      <li><strong>No AI/ML Foundation Model Training:</strong> Google user data obtained via OAuth 2.0 is never used to train, fine-tune, or improve generalized artificial intelligence or machine learning models.</li>
      <li><strong>Infrastructure Sub-processors:</strong> The application is hosted on secure cloud infrastructure (Google Cloud Run / Google Cloud Firestore in European regions and/or Fly.io Frankfurt <code>fra</code> region) acting solely as infrastructure processors under strict data protection terms.</li>
    </ul>

    <h2>5. Data Storage, Security &amp; Retention</h2>
    <ul>
      <li><strong>Session Lifespan:</strong> Authenticated sessions expire automatically after <strong>4 hours</strong> or immediately upon clicking "Sign out".</li>
      <li><strong>Browser Local Storage:</strong> For user convenience during active evaluation, session metadata and sandbox simulation state are stored in your browser's <code>localStorage</code> (e.g., <code>bilanx_verified_google_user</code>, <code>credentials_hub_profile</code>) and are purged upon sign-out.</li>
      <li><strong>Audit Log Retention:</strong> Server-side access logs are capped at a rolling maximum of 10,000 events and retained only as needed for security verification and audit demonstration, after which they are automatically rotated or purged upon administrative request.</li>
      <li><strong>Cryptographic Safeguards:</strong> All network traffic is enforced over HTTPS/TLS, cross-origin requests are restricted by strict CORS and Content Security Policy (CSP) headers, and institutional assertions are signed with ECDSA P-256 keys.</li>
    </ul>

    <h2>6. Your Privacy Rights, Revocation &amp; Data Deletion</h2>
    <p>
      Under the EU General Data Protection Regulation (GDPR), the Swiss Federal Act on Data Protection (nFADP), and Google OAuth policies, you hold the following rights:
    </p>
    <ul>
      <li><strong>Revoke Google OAuth Access at Any Time:</strong> You may immediately revoke <strong>${APP_BRAND_NAME}</strong>'s access to your Google account via your Google Security Settings at <a href="https://myaccount.google.com/permissions" target="_blank" rel="noopener noreferrer">https://myaccount.google.com/permissions</a>.</li>
      <li><strong>Sign Out &amp; Clear Local Data:</strong> Clicking "Sign out" in the application header invalidates your server session cookie and deletes cached user data from your browser.</li>
      <li><strong>Request Access, Rectification, or Erasure:</strong> To request a copy of your recorded access log entries or permanent deletion of your authentication records, contact <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a> with the subject line <code>Privacy Erasure Request — ${APP_BRAND_NAME}</code>. Requests are fulfilled within 72 hours.</li>
    </ul>

    <h2>7. Changes to This Privacy Policy</h2>
    <p>
      We may update this Privacy Policy periodically to reflect technical, cryptographic, or regulatory updates. Any changes will be posted on this page (<a href="${canonicalUrl}">${canonicalUrl}</a>) with an updated effective date.
    </p>
  </main>

  <footer>
    <div class="footer-inner">
      <div>
        <strong>${APP_BRAND_NAME}</strong> · Sovereign eIDAS 2.0 &amp; Dual-Key Validation System (DK-SVS)
      </div>
      <ul class="footer-links">
        <li><a href="/">Home</a></li>
        <li><a href="/privacy">Privacy Policy</a></li>
        <li><a href="/terms">Terms of Service</a></li>
        <li><a href="mailto:${CONTACT_EMAIL}">Contact Privacy Officer</a></li>
      </ul>
    </div>
  </footer>
</body>
</html>`;
}

export function renderTermsOfServiceHtml(baseOrigin: string = 'https://bilanx.expert'): string {
  const canonicalUrl = `${baseOrigin}/terms`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Terms of Service — ${APP_BRAND_NAME}</title>
  <meta name="description" content="Terms of Service and Sandbox Evaluation Agreement for ${APP_BRAND_NAME} (DK-SVS eIDAS 2.0 Node Sandbox).">
  <link rel="canonical" href="${canonicalUrl}">
  <style>${SHARED_STYLES}</style>
</head>
<body>
  <header>
    <div class="header-inner">
      <a href="/" class="brand-identity">
        <span class="brand-badge" aria-hidden="true">BX</span>
        <span>
          <span class="brand-title">${APP_BRAND_NAME}</span>
          <span class="brand-subtitle">DK-SVS Sovereign eIDAS 2.0 Node Sandbox</span>
        </span>
      </a>
      <nav aria-label="Primary legal navigation">
        <ul>
          <li><a href="/">Home &amp; Application</a></li>
          <li><a href="/privacy">Privacy Policy</a></li>
          <li><a href="/terms" aria-current="page">Terms of Service</a></li>
        </ul>
      </nav>
    </div>
  </header>

  <main>
    <div class="hero-banner">
      <span class="meta-pill">EFFECTIVE DATE: ${EFFECTIVE_DATE} · REGULATORY SANDBOX TERMS</span>
      <h1>Terms of Service — ${APP_BRAND_NAME}</h1>
      <p>
        These Terms of Service ("Terms") govern your access to and use of <strong>${APP_BRAND_NAME}</strong>
        (the "Service"), a TRL 4 cryptographic evaluation sandbox for the Dual-Key Sovereign Validation System (DK-SVS)
        and eIDAS 2.0 / FIDO2 age-verification protocols operated by Daniele Palagi ("Project Bilanx").
      </p>
    </div>

    <h2>1. Nature of the Service &amp; TRL 4 Sandbox Scope</h2>
    <p>
      <strong>${APP_BRAND_NAME}</strong> provides an interactive technical demonstration and cryptographic verification
      laboratory implementing ECDSA P-256 institutional binding, Pedersen commitments, 8-bit NIZKP range proofs (Scheme B2),
      WebAuthn / FIDO2 hardware-bound assertions, and SAML 2.0 eIDAS node interoperability fixtures.
    </p>
    <ul>
      <li>The Service is provided as a <strong>TRL 4 laboratory and pilot evaluation environment</strong>.</li>
      <li>Synthetic citizen profiles (e.g., Swiss Sovereign Sandbox and Italian CIE pilot fixtures) are strictly for technical evaluation and compliance testing.</li>
    </ul>

    <h2>2. Account Authentication &amp; Acceptable Use</h2>
    <p>
      Access to authenticated operator telemetry and audit logs requires signing in via Google OAuth 2.0 or using the designated offline evaluator sandbox mode. By accessing the Service, you agree not to:
    </p>
    <ul>
      <li>Attempt to bypass cryptographic verification checks, rate limits, or session authentication controls outside of documented adversarial stress-testing harnesses.</li>
      <li>Submit unlawful, fraudulent, or unauthorized third-party personal data to the Service.</li>
      <li>Misrepresent synthetic sandbox clearance receipts as live government-issued legal clearances in production commerce without an executed institutional integration agreement.</li>
    </ul>

    <h2>3. Intellectual Property &amp; Open Standards</h2>
    <p>
      The Dual-Key Sovereign Validation System (DK-SVS) architecture, documentation, and custom implementation code are the intellectual property of Project Bilanx / Daniele Palagi, licensed where marked under Apache-2.0 or applicable evaluation agreements.
    </p>

    <h2>4. Privacy &amp; Data Protection</h2>
    <p>
      Your use of the Service is subject to our <a href="/privacy">Privacy Policy</a>, which details our compliance with the Google API Services User Data Policy, GDPR, and Swiss nFADP.
    </p>

    <h2>5. Disclaimer of Warranties &amp; Limitation of Liability</h2>
    <p>
      THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE" FOR CRYPTOGRAPHIC EVALUATION AND COMPLIANCE DEMONSTRATION WITHOUT WARRANTIES OF ANY KIND, EXPRESS OR IMPLIED. TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, PROJECT BILANX SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING FROM YOUR USE OF THE SANDBOX.
    </p>

    <h2>6. Governing Law &amp; Contact</h2>
    <p>
      These Terms are governed by the laws of Italy and applicable European Union regulations. For legal or technical inquiries, contact <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a>.
    </p>
  </main>

  <footer>
    <div class="footer-inner">
      <div>
        <strong>${APP_BRAND_NAME}</strong> · Sovereign eIDAS 2.0 &amp; Dual-Key Validation System (DK-SVS)
      </div>
      <ul class="footer-links">
        <li><a href="/">Home</a></li>
        <li><a href="/privacy">Privacy Policy</a></li>
        <li><a href="/terms">Terms of Service</a></li>
        <li><a href="mailto:${CONTACT_EMAIL}">Contact</a></li>
      </ul>
    </div>
  </footer>
</body>
</html>`;
}

export function mountLegalRoutes(app: express.Express): void {
  app.get(['/privacy', '/privacy.html', '/privacy-policy'], (req, res) => {
    const baseOrigin = resolveBaseOrigin(req);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.status(200).send(renderPrivacyPolicyHtml(baseOrigin));
  });

  app.get(['/terms', '/terms.html', '/terms-of-service'], (req, res) => {
    const baseOrigin = resolveBaseOrigin(req);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.status(200).send(renderTermsOfServiceHtml(baseOrigin));
  });
}

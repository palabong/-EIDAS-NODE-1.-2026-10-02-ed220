import React from 'react';
import { ShieldCheck, ArrowLeft, Lock, FileText, Mail, ExternalLink } from 'lucide-react';

export const APP_BRAND_NAME = 'Project Bilanx — Credentials Hub';
export const APP_NODE_ID = 'PROJECT BILANX / EIDAS-NODE 1.';
export const EFFECTIVE_DATE = 'November 15, 2026';
export const CONTACT_EMAIL = 'daniele.palagi92@gmail.com';
export const AI_STUDIO_NODE_URL = 'https://bilanx-node.ai.studio';
export const AI_STUDIO_DEV_SANDBOX_URL = 'https://ais-dev-tcotnprdclohwgzqvuaakc-381763343373.europe-west1.run.app';
export const AI_STUDIO_HOME_URL = 'https://bilanx.ai.studio';
export const AI_STUDIO_SANDBOX_URL = 'https://ai.studio/apps/52affc3b-2293-4cf0-bd6c-6b6cdc3a926a';
export const CLOUD_RUN_SERVICE_URL = 'https://project-bilanx-eidas-node-1-622147315855.europe-west2.run.app';
export const FLY_APP_URL = 'https://eidas-node-1-2026-10-02-ed220-black-water-1048.fly.dev';
export const GITHUB_REPO_URL = 'https://github.com/palabong/-EIDAS-NODE-1.-2026-10-02-ed220';

interface LegalPageProps {
  page: 'privacy' | 'terms';
  onNavigateHome?: () => void;
  onSwitchLegalPage?: (page: 'privacy' | 'terms') => void;
}

export function LegalPage({ page, onNavigateHome, onSwitchLegalPage }: LegalPageProps) {
  const handleHomeClick = (e: React.MouseEvent<HTMLAnchorElement>) => {
    if (onNavigateHome) {
      e.preventDefault();
      try {
        window.history.pushState({}, '', '/');
      } catch {
        // Ignore history pushState restriction in sandboxed iframes
      }
      onNavigateHome();
    }
  };

  const handlePageSwitch = (target: 'privacy' | 'terms') => (e: React.MouseEvent<HTMLAnchorElement>) => {
    if (onSwitchLegalPage) {
      e.preventDefault();
      try {
        window.history.pushState({}, '', `/${target}`);
      } catch {
        // Ignore history pushState restriction in sandboxed iframes
      }
      onSwitchLegalPage(target);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 flex flex-col font-sans">
      <header className="bg-slate-900/95 border-b border-slate-800 px-6 py-4 sticky top-0 z-20 backdrop-blur-xs">
        <div className="max-w-5xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <a
            href="/"
            onClick={handleHomeClick}
            className="flex items-center gap-3 text-white hover:opacity-90 transition-opacity"
          >
            <div className="w-10 h-10 bg-blue-500/15 border border-blue-500/40 rounded-xl flex items-center justify-center text-blue-400">
              <ShieldCheck size={22} aria-hidden="true" />
            </div>
            <div>
              <span className="font-extrabold text-base tracking-tight block leading-none">
                {APP_BRAND_NAME}
              </span>
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest block mt-1">
                {APP_NODE_ID} · DK-SVS eIDAS 2.0 Node Sandbox
              </span>
            </div>
          </a>

          <nav aria-label="Primary legal navigation">
            <ul className="flex items-center gap-3 text-xs font-semibold">
              <li>
                <a
                  href="/"
                  onClick={handleHomeClick}
                  className="px-3 py-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800 inline-flex items-center gap-1.5 transition-colors"
                >
                  <ArrowLeft size={14} aria-hidden="true" />
                  <span>Home &amp; Application</span>
                </a>
              </li>
              <li>
                <a
                  href="/privacy"
                  onClick={handlePageSwitch('privacy')}
                  aria-current={page === 'privacy' ? 'page' : undefined}
                  className={`px-3 py-1.5 rounded-lg inline-flex items-center gap-1.5 transition-colors ${
                    page === 'privacy'
                      ? 'bg-blue-600/20 border border-blue-500/40 text-blue-300'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800'
                  }`}
                >
                  <Lock size={13} aria-hidden="true" />
                  <span>Privacy Policy</span>
                </a>
              </li>
              <li>
                <a
                  href="/terms"
                  onClick={handlePageSwitch('terms')}
                  aria-current={page === 'terms' ? 'page' : undefined}
                  className={`px-3 py-1.5 rounded-lg inline-flex items-center gap-1.5 transition-colors ${
                    page === 'terms'
                      ? 'bg-blue-600/20 border border-blue-500/40 text-blue-300'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800'
                  }`}
                >
                  <FileText size={13} aria-hidden="true" />
                  <span>Terms of Service</span>
                </a>
              </li>
            </ul>
          </nav>
        </div>
      </header>

      <main className="flex-1 max-w-5xl w-full mx-auto px-6 py-10">
        {page === 'privacy' ? (
          <PrivacyPolicyArticle onSwitchLegalPage={handlePageSwitch} />
        ) : (
          <TermsOfServiceArticle onSwitchLegalPage={handlePageSwitch} />
        )}
      </main>

      <footer className="bg-slate-900 border-t border-slate-800 px-6 py-6 text-xs text-slate-400">
        <div className="max-w-5xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <div>
            <strong className="text-white">{APP_BRAND_NAME}</strong> ({APP_NODE_ID}) · Sovereign eIDAS 2.0 &amp; Dual-Key Validation System (DK-SVS)
          </div>
          <ul className="flex flex-wrap items-center gap-5">
            <li>
              <a href="/" onClick={handleHomeClick} className="text-blue-400 hover:underline">
                Home
              </a>
            </li>
            <li>
              <a href="/privacy" onClick={handlePageSwitch('privacy')} className="text-blue-400 hover:underline">
                Privacy Policy
              </a>
            </li>
            <li>
              <a href="/terms" onClick={handlePageSwitch('terms')} className="text-blue-400 hover:underline">
                Terms of Service
              </a>
            </li>
            <li>
              <a href={`mailto:${CONTACT_EMAIL}`} className="text-blue-400 hover:underline inline-flex items-center gap-1">
                <Mail size={12} aria-hidden="true" />
                <span>{CONTACT_EMAIL}</span>
              </a>
            </li>
          </ul>
        </div>
      </footer>
    </div>
  );
}

function PrivacyPolicyArticle({
  onSwitchLegalPage,
}: {
  onSwitchLegalPage: (target: 'privacy' | 'terms') => (e: React.MouseEvent<HTMLAnchorElement>) => void;
}) {
  return (
    <article className="space-y-8">
      <div className="bg-slate-900 border border-slate-800 border-l-4 border-l-blue-500 rounded-xl p-6 sm:p-8">
        <div className="inline-block font-mono text-[11px] text-blue-300 bg-blue-950/70 border border-blue-800/60 px-3 py-1 rounded-full mb-3">
          EFFECTIVE DATE: {EFFECTIVE_DATE} · GDPR &amp; GOOGLE OAUTH 2.0 COMPLIANT
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          Privacy Policy — {APP_BRAND_NAME}
        </h1>
        <p className="text-slate-300 text-sm mt-3 leading-relaxed">
          This Privacy Policy governs the collection, verification, storage, and protection of information by{' '}
          <strong className="text-white">{APP_BRAND_NAME}</strong> (also registered as{' '}
          <strong className="text-white">{APP_NODE_ID}</strong>,{' '}
          <strong className="text-white">Credentials Hub</strong>, and{' '}
          <strong className="text-white">Project Bilanx</strong>). It explicitly details how we handle Google User Data
          obtained via Google Identity Services (OAuth 2.0 / OpenID Connect) and how our Zero-Knowledge Proof (ZKP)
          validation architecture protects end-user privacy.
        </p>
      </div>

      <div className="bg-emerald-950/30 border border-emerald-500/30 rounded-xl p-6">
        <h2 className="text-base font-bold text-emerald-300 mb-2">
          Google API Services User Data Policy — Limited Use Disclosure
        </h2>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
          <strong className="text-white">{APP_BRAND_NAME}</strong>&apos;s use and transfer to any other app of
          information received from Google APIs adheres strictly to the{' '}
          <a
            href="https://developers.google.com/terms/api-services-user-data-policy"
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-400 underline inline-flex items-center gap-1"
          >
            <span>Google API Services User Data Policy</span>
            <ExternalLink size={12} aria-hidden="true" />
          </a>
          , including the Limited Use requirements. We request only basic OpenID Connect identity scopes (
          <code className="px-1.5 py-0.5 bg-slate-800 rounded text-blue-300 font-mono text-xs">openid</code>,{' '}
          <code className="px-1.5 py-0.5 bg-slate-800 rounded text-blue-300 font-mono text-xs">email</code>,{' '}
          <code className="px-1.5 py-0.5 bg-slate-800 rounded text-blue-300 font-mono text-xs">profile</code>) to
          authenticate evaluators and operators, and we never sell, rent, or transfer Google user data to third parties
          or use it for advertising or AI model training.
        </p>
      </div>

      <section className="space-y-3">
        <h2 className="text-xl font-bold text-white border-b border-slate-800 pb-2">
          1. Data Controller, Application Identity &amp; Official Endpoints
        </h2>
        <p className="text-sm text-slate-300">
          The data controller responsible for the operation of <strong className="text-white">{APP_BRAND_NAME}</strong> ({APP_NODE_ID}) is:
        </p>
        <ul className="list-disc list-inside text-sm text-slate-300 space-y-1.5">
          <li>
            <strong className="text-white">Controller / Architect:</strong> Daniele Palagi (Project Bilanx Sovereign Validation Systems)
          </li>
          <li>
            <strong className="text-white">Jurisdiction:</strong> Lucca, Tuscany, Italy (European Union — GDPR Regulation (EU) 2016/679 &amp; Swiss nFADP)
          </li>
          <li>
            <strong className="text-white">Privacy &amp; Compliance Contact:</strong>{' '}
            <a href={`mailto:${CONTACT_EMAIL}`} className="text-blue-400 underline">
              {CONTACT_EMAIL}
            </a>
          </li>
          <li>
            <strong className="text-white">Published AI Studio Node (Primary):</strong>{' '}
            <a href={AI_STUDIO_NODE_URL} className="text-blue-400 underline">
              {AI_STUDIO_NODE_URL}
            </a>
          </li>
          <li>
            <strong className="text-white">AI Studio Dev Sandbox (Cloud Run):</strong>{' '}
            <a href={AI_STUDIO_DEV_SANDBOX_URL} className="text-blue-400 underline">
              {AI_STUDIO_DEV_SANDBOX_URL}
            </a>
          </li>
          <li>
            <strong className="text-white">Primary Home Page (AI Studio App):</strong>{' '}
            <a href={AI_STUDIO_HOME_URL} className="text-blue-400 underline">
              {AI_STUDIO_HOME_URL}
            </a>
          </li>
          <li>
            <strong className="text-white">AI Studio Interactive Sandbox:</strong>{' '}
            <a href={AI_STUDIO_SANDBOX_URL} className="text-blue-400 underline">
              {AI_STUDIO_SANDBOX_URL}
            </a>
          </li>
          <li>
            <strong className="text-white">Cloud Run Node Endpoint:</strong>{' '}
            <a href={CLOUD_RUN_SERVICE_URL} className="text-blue-400 underline">
              {CLOUD_RUN_SERVICE_URL}
            </a>
          </li>
          <li>
            <strong className="text-white">Fly.io Node (Frankfurt):</strong>{' '}
            <a href={`${FLY_APP_URL}/privacy`} className="text-blue-400 underline">
              {FLY_APP_URL}/privacy
            </a>
            {' · '}
            <a href={`${FLY_APP_URL}/terms`} className="text-blue-400 underline">
              Terms
            </a>
          </li>
          {typeof window !== 'undefined' && window.location.origin.replace(/\/+$/, '') !== FLY_APP_URL && (
            <li>
              <strong className="text-white">This deployment:</strong>{' '}
              <a href="/privacy" onClick={onSwitchLegalPage('privacy')} className="text-blue-400 underline">
                {window.location.origin}/privacy
              </a>
            </li>
          )}
          <li>
            <strong className="text-white">Source Repository:</strong>{' '}
            <a href={GITHUB_REPO_URL} target="_blank" rel="noopener noreferrer" className="text-blue-400 underline">
              {GITHUB_REPO_URL}
            </a>
          </li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-bold text-white border-b border-slate-800 pb-2">
          2. Information We Collect and Access
        </h2>
        <h3 className="text-base font-bold text-blue-400">
          2.1 Google OAuth 2.0 User Data (Operator &amp; Evaluator Authentication)
        </h3>
        <p className="text-sm text-slate-300 leading-relaxed">
          When you sign in to <strong className="text-white">{APP_BRAND_NAME}</strong> using Google Identity Services,
          our backend verifies the cryptographic JSON Web Token (ID Token) issued by{' '}
          <code className="px-1.5 py-0.5 bg-slate-800 rounded text-blue-300 font-mono text-xs">https://accounts.google.com</code>{' '}
          and accesses only the following basic claims:
        </p>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse bg-slate-900 border border-slate-800 rounded-lg text-xs sm:text-sm">
            <thead>
              <tr className="bg-slate-800/80 text-white uppercase text-xs font-mono">
                <th className="p-3 border-b border-slate-700">Data Element / Claim</th>
                <th className="p-3 border-b border-slate-700">OAuth Scope</th>
                <th className="p-3 border-b border-slate-700">Purpose of Collection</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              <tr>
                <td className="p-3 font-medium text-white">Google Subject Identifier (<code>sub</code>)</td>
                <td className="p-3 font-mono text-blue-300">openid</td>
                <td className="p-3">Uniquely identifies the authenticated evaluator/operator session and binds security audit records.</td>
              </tr>
              <tr>
                <td className="p-3 font-medium text-white">Email Address &amp; Status (<code>email</code>, <code>email_verified</code>)</td>
                <td className="p-3 font-mono text-blue-300">email</td>
                <td className="p-3">Displays the verified operator identity in the dashboard header and records accountable access logs.</td>
              </tr>
              <tr>
                <td className="p-3 font-medium text-white">Display Name &amp; Avatar URL (<code>name</code>, <code>picture</code>)</td>
                <td className="p-3 font-mono text-blue-300">profile</td>
                <td className="p-3">Renders the active user badge within the authenticated application interface.</td>
              </tr>
              <tr>
                <td className="p-3 font-medium text-white">Technical Request Context (<code>ipAddress</code>, <code>userAgent</code>)</td>
                <td className="p-3 font-mono text-slate-400">HTTP Transport</td>
                <td className="p-3">Protects the node against unauthorized access, replay attacks, and maintains the security audit trail.</td>
              </tr>
            </tbody>
          </table>
        </div>

        <h3 className="text-base font-bold text-blue-400 pt-2">
          2.2 Zero-PII Consumer Cryptographic Verification (DK-SVS &amp; Scheme B2)
        </h3>
        <p className="text-sm text-slate-300 leading-relaxed">
          For retail and age-restricted compliance workflows within the Dual-Key Sovereign Validation System (DK-SVS),{' '}
          <strong className="text-white">zero consumer Personally Identifiable Information (PII) is transmitted or stored</strong>.
          Consumer age verification relies on a fixed 1,355-byte binary payload containing Pedersen commitments on P-256
          and an 8-bit NIZKP range proof (Scheme B2) proving <code className="px-1.5 py-0.5 bg-slate-800 rounded text-blue-300 font-mono text-xs">age &ge; 18</code> without disclosing date of birth or identity numbers.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className="text-xl font-bold text-white border-b border-slate-800 pb-2">
          3. How We Use, Store, and Protect Your Data
        </h2>
        <ul className="list-disc list-inside text-sm text-slate-300 space-y-2">
          <li>
            <strong className="text-white">Session Management:</strong> Validated Google ID tokens issue an HTTP-only session cookie (<code className="px-1.5 py-0.5 bg-slate-800 rounded text-blue-300 font-mono text-xs">bilanx_sid</code>) that expires automatically after 4 hours.
          </li>
          <li>
            <strong className="text-white">No Sale, Advertising, or AI Training:</strong> We never sell personal data, never use Google user data for advertising or profiling, and never use OAuth user data to train AI/ML models.
          </li>
          <li>
            <strong className="text-white">Audit Log Cap &amp; Local Storage:</strong> Server-side access logs are capped at 10,000 rolling events, and client-side <code className="px-1.5 py-0.5 bg-slate-800 rounded text-blue-300 font-mono text-xs">localStorage</code> session state is cleared immediately upon sign-out.
          </li>
          <li>
            <strong className="text-white">Revocation &amp; Deletion Rights:</strong> You may revoke OAuth permissions at any time at{' '}
            <a
              href="https://myaccount.google.com/permissions"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-400 underline"
            >
              https://myaccount.google.com/permissions
            </a>{' '}
            or request complete deletion of your access log entries by emailing{' '}
            <a href={`mailto:${CONTACT_EMAIL}`} className="text-blue-400 underline">
              {CONTACT_EMAIL}
            </a>. See also our{' '}
            <a href="/terms" onClick={onSwitchLegalPage('terms')} className="text-blue-400 underline">
              Terms of Service
            </a>.
          </li>
        </ul>
      </section>
    </article>
  );
}

function TermsOfServiceArticle({
  onSwitchLegalPage,
}: {
  onSwitchLegalPage: (target: 'privacy' | 'terms') => (e: React.MouseEvent<HTMLAnchorElement>) => void;
}) {
  return (
    <article className="space-y-8">
      <div className="bg-slate-900 border border-slate-800 border-l-4 border-l-blue-500 rounded-xl p-6 sm:p-8">
        <div className="inline-block font-mono text-[11px] text-blue-300 bg-blue-950/70 border border-blue-800/60 px-3 py-1 rounded-full mb-3">
          EFFECTIVE DATE: {EFFECTIVE_DATE} · REGULATORY SANDBOX TERMS
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          Terms of Service — {APP_BRAND_NAME}
        </h1>
        <p className="text-slate-300 text-sm mt-3 leading-relaxed">
          These Terms of Service govern your access to and use of <strong className="text-white">{APP_BRAND_NAME}</strong>{' '}
          (<strong className="text-white">{APP_NODE_ID}</strong>), a TRL 4 cryptographic evaluation sandbox for the Dual-Key
          Sovereign Validation System (DK-SVS) and eIDAS 2.0 / FIDO2 age-verification protocols operated by Daniele Palagi.
        </p>
      </div>

      <section className="space-y-3">
        <h2 className="text-xl font-bold text-white border-b border-slate-800 pb-2">
          1. Nature of the Service &amp; TRL 4 Sandbox Scope
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          <strong className="text-white">{APP_BRAND_NAME}</strong> provides an interactive technical demonstration and
          cryptographic verification laboratory implementing ECDSA P-256 institutional binding, Pedersen commitments,
          8-bit NIZKP range proofs (Scheme B2), WebAuthn / FIDO2 hardware-bound assertions, and SAML 2.0 eIDAS node interoperability fixtures.
          The Service is hosted at{' '}
          <a href={FLY_APP_URL} className="text-blue-400 underline">{FLY_APP_URL}</a>.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className="text-xl font-bold text-white border-b border-slate-800 pb-2">
          2. Acceptable Use &amp; Privacy Compliance
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          By signing in via Google OAuth 2.0 or using the evaluator sandbox, you agree not to misuse the cryptographic
          verification endpoints or submit unauthorized third-party personal data. Data handling is governed by our{' '}
          <a href="/privacy" onClick={onSwitchLegalPage('privacy')} className="text-blue-400 underline">
            Privacy Policy
          </a>.
        </p>
      </section>
    </article>
  );
}

# SAML eIDAS Engine Integration & Architecture Guide

This document describes how to seamlessly integrate the standalone Python/FastAPI SAML processing microservice into high-stakes retail setups and the sandbox without altering the core React/Vite codebase.

## 1. System Architecture

Below is a system topology showing how the SAML eIDAS ingestion microservice behaves alongside the existing Retail POS frontend and compliance hardware logic:

```
  +-------------------------+                      +-----------------------------------+
  |   Retail POS Frontend   |                      |  SAML eIDAS Ingestion Engine       |
  |  (Vite / React Sandbox) |                      |     (FastAPI Core / Python 3.11)  |
  +------------+------------+                      +-----------------+-----------------+
               |                                                     ^
               | 1. HTTP POST (SAML XML Asset)                       |
               +-----------------------------------------------------+
               |
               | 2. Parsed claims mapped to POS Permissions
               v
  +------------------------------------------------------------------+
  | MAPPED ROLES: CASHIER (LoA Low) / STORE_MANAGER (LoA Substantial) |
  | GRANTED PERMISSIONS: SHIFT_START, MANAGER_OVERRIDE, REFUND       |
  +------------------------------------------------------------------+
```

---

## 2. Zero-Touch Integration Adapter (Mock Adapter)

To bind the React/Vite POS terminal to this engine with zero modifications, implement a standard proxy inside the Node dev-server or let the POS browser invoke the microservice directly via standard environment-driven endpoint lookups.

### Direct Client Integration Snippet
```typescript
// Fetch the configured SAML processor from client env variables
const SAML_PROCESSOR_URL = import.meta.env.VITE_SAML_PROCESSOR_URL || "http://localhost:8000";

async function ingestSAMLPayload(xmlContent: string) {
  try {
    const response = await fetch(`${SAML_PROCESSOR_URL}/api/v1/ingest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ xml_content: xmlContent })
    });
    const data = await response.json();
    if (data.is_valid) {
      console.log("eIDAS Authentication complete:", data.pos_context);
      return data.pos_context; // Cashier / Manager payload
    } else {
      throw new Error(data.error_message);
    }
  } catch (error) {
    console.error("SAML Validation failed:", error);
    return null;
  }
}
```

---

## 3. High-Stakes Security & Audit Checklist

Before shifting this microservice into physical production environments:
1. **Clock Skew Tuning**: Set the clock skew buffer (`clock_skew_seconds` environment variable) between 120 and 300 seconds to compensate for terminal time drifts.
2. **Replay Cache**: Integrate a high-speed Redis cluster to store assertion `ID` records durably, rejecting duplicated identifiers across distributed POS terminals.
3. **No Local DTD Processing**: Keep inline DTD parsing strictly disabled to guarantee immunity against recursive entity expansion exploits (XML bombs).
4. **Minimal Retention Logs**: Never log confidential user fields (e.g., specific ID card hashes) in plain text. Maintain pseudonymized logs linking `SAML_ID` to granted temporary permissions only.

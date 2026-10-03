/**
 * eIDAS 2.0 SAML Type Definitions
 */

export type LoALevel = 'low' | 'substantial' | 'high';

export interface EidasNaturalPersonClaims {
  person_identifier?: string;
  family_name?: string;
  given_name?: string;
  date_of_birth?: string;
  age?: number;
  is_over_18?: boolean;
  is_over_21?: boolean;
  level_of_assurance?: string;
  issuer?: string;
  destination?: string;
  status_code?: string;
  status_message?: string;
  attributes?: Record<string, any>;
  [key: string]: any;
}

export interface POSContext {
  user_id: string;
  role: 'CASHIER' | 'STORE_MANAGER' | string;
  permissions: string[];
  level_of_assurance: string;
  store_id: string;
  family_name?: string;
  given_name?: string;
  date_of_birth?: string;
  age?: number;
  is_over_18?: boolean;
  is_over_21?: boolean;
  raw_attributes?: Record<string, any>;
}

export interface SessionUser {
  uid: string;
  email: string;
  name: string;
  picture?: string;
  authMethod: 'eidas_saml' | 'google_jwt_verified' | 'google_identity_services';
  role?: string;
  permissions?: string[];
  levelOfAssurance?: string;
  personIdentifier?: string;
  familyName?: string;
  givenName?: string;
  dateOfBirth?: string;
  age?: number;
  isOver18?: boolean;
  isOver21?: boolean;
  authenticatedAt: string;
  expiresAt: number;
  issuer?: string;
  posContext?: POSContext;
}

export interface TrackedAuthnRequest {
  id: string;
  createdAt: number;
  relayState?: string;
  loa: string;
  destination: string;
}

export interface SAMLValidationResponse {
  is_valid: boolean;
  error_message?: string;
  claims?: EidasNaturalPersonClaims;
  pos_context?: POSContext;
}

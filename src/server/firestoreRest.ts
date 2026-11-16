/**
 * Lightweight Firestore v1 REST client using google-auth-library (ADC / Cloud Run Metadata).
 * Zero-config no-op outside GCP / when GOOGLE_CLOUD_PROJECT is unset.
 */

import { GoogleAuth } from 'google-auth-library';

let authClient: GoogleAuth | null = null;

export function getGcpProjectId(): string {
  return (process.env.GOOGLE_CLOUD_PROJECT || process.env.GCP_PROJECT || '').trim();
}

export function getFirestoreDatabaseId(): string {
  return (process.env.FIRESTORE_DATABASE_ID || '(default)').trim();
}

export function isFirestoreEnabled(): boolean {
  const projectId = getGcpProjectId();
  if (!projectId) return false;
  return Boolean(
    process.env.K_SERVICE ||
    process.env.FIRESTORE_DATABASE_ID ||
    process.env.USE_FIRESTORE === 'true'
  );
}

async function getAccessToken(): Promise<string | null> {
  if (!authClient) {
    authClient = new GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/datastore'],
    });
  }
  const client = await authClient.getClient();
  const tokenRes = await client.getAccessToken();
  return tokenRes?.token || null;
}

function collectionUrl(collection: string): string {
  const projectId = encodeURIComponent(getGcpProjectId());
  const dbId = encodeURIComponent(getFirestoreDatabaseId());
  return `https://firestore.googleapis.com/v1/projects/${projectId}/databases/${dbId}/documents/${encodeURIComponent(collection)}`;
}

export interface FirestoreDocument {
  name: string;
  fields?: Record<string, any>;
}

export async function firestoreUpsertDocument(
  collection: string,
  documentId: string,
  fields: Record<string, any>
): Promise<void> {
  if (!isFirestoreEnabled()) return;
  const token = await getAccessToken();
  if (!token) return;

  const url = `${collectionUrl(collection)}/${encodeURIComponent(documentId)}`;
  const res = await fetch(url, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ fields }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Firestore upsert ${collection}/${documentId} failed (${res.status}): ${body.slice(0, 200)}`);
  }
}

export async function firestoreDeleteDocument(collection: string, documentId: string): Promise<void> {
  if (!isFirestoreEnabled()) return;
  const token = await getAccessToken();
  if (!token) return;

  const url = `${collectionUrl(collection)}/${encodeURIComponent(documentId)}`;
  const res = await fetch(url, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!res.ok && res.status !== 404) {
    const body = await res.text().catch(() => '');
    throw new Error(`Firestore delete ${collection}/${documentId} failed (${res.status}): ${body.slice(0, 200)}`);
  }
}

export async function firestoreListDocuments(
  collection: string,
  maxDocs: number = 1000
): Promise<FirestoreDocument[]> {
  if (!isFirestoreEnabled()) return [];
  const token = await getAccessToken();
  if (!token) return [];

  const docs: FirestoreDocument[] = [];
  let pageToken = '';

  while (docs.length < maxDocs) {
    const pageSize = Math.min(300, maxDocs - docs.length);
    const params = new URLSearchParams({ pageSize: String(pageSize) });
    if (pageToken) params.set('pageToken', pageToken);

    const url = `${collectionUrl(collection)}?${params.toString()}`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`Firestore list ${collection} failed (${res.status}): ${body.slice(0, 200)}`);
    }
    const data = (await res.json()) as { documents?: FirestoreDocument[]; nextPageToken?: string };
    if (Array.isArray(data.documents)) {
      docs.push(...data.documents);
    }
    if (!data.nextPageToken) break;
    pageToken = data.nextPageToken;
  }

  return docs;
}

export async function firestoreClearCollection(collection: string): Promise<void> {
  if (!isFirestoreEnabled()) return;
  const docs = await firestoreListDocuments(collection, 1000);
  await Promise.all(
    docs.map((doc) => {
      const id = doc.name.split('/').pop();
      return id ? firestoreDeleteDocument(collection, id).catch(() => {}) : Promise.resolve();
    })
  );
}

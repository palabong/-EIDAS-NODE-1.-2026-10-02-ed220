/**
 * Unified Isomorphic Cryptographic Encoding Utilities (Base64, Base64URL, Hex, Uint8Array)
 * 
 * Provides safe, constant-behavior encoding and decoding across both Node.js
 * and Browser execution contexts, completely avoiding runtime dependencies on
 * window.atob / window.btoa or Node-specific Buffer availability.
 */

/**
 * Converts a byte array (Uint8Array or ArrayBuffer) to a lowercase hex string.
 */
export function bytesToHex(bytes: Uint8Array | ArrayBuffer): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let hex = '';
  for (let i = 0; i < u8.length; i++) {
    hex += u8[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Converts an ArrayBuffer to a lowercase hex string.
 * Backward-compatible alias for bufferToHex.
 */
export function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  return bytesToHex(buffer);
}

/**
 * Converts a hex string into a Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (cleanHex.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Encodes a byte array into standard Base64 string.
 */
export function bytesToBase64(bytes: Uint8Array | ArrayBuffer): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength).toString('base64');
  }
  let binary = '';
  for (let i = 0; i < u8.length; i++) {
    binary += String.fromCharCode(u8[i]);
  }
  const btoaFn = typeof btoa === 'function' ? btoa : (globalThis as any).btoa;
  if (typeof btoaFn === 'function') {
    return btoaFn(binary);
  }
  throw new Error('No Base64 encoder available in environment');
}

/**
 * Decodes a Base64 string into a Uint8Array.
 */
export function base64ToBytes(base64: string): Uint8Array {
  if (!base64 || typeof base64 !== 'string') {
    throw new Error('Invalid Base64 input');
  }
  if (typeof Buffer !== 'undefined') {
    const buf = Buffer.from(base64, 'base64');
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  const atobFn = typeof atob === 'function' ? atob : (globalThis as any).atob;
  if (typeof atobFn === 'function') {
    const binary = atobFn(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  throw new Error('No Base64 decoder available in environment');
}

/**
 * Decodes a Base64 string into an ArrayBuffer.
 * Backward-compatible helper for legacy functions expecting ArrayBuffer.
 */
export function base64ToBuffer(base64: string): ArrayBuffer {
  const bytes = base64ToBytes(base64);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

/**
 * Encodes a byte array into URL-safe Base64URL string (RFC 4648 §5, unpadded).
 */
export function bytesToBase64Url(bytes: Uint8Array | ArrayBuffer): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength).toString('base64url');
  }
  return bytesToBase64(u8)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Backward-compatible alias for bufferToBase64Url.
 */
export function bufferToBase64Url(buffer: ArrayBuffer | Uint8Array): string {
  return bytesToBase64Url(buffer);
}

/**
 * Decodes a URL-safe Base64URL string into a Uint8Array.
 */
export function base64UrlToBytes(base64url: string): Uint8Array {
  if (!base64url || typeof base64url !== 'string') {
    throw new Error('Invalid Base64URL input');
  }
  if (typeof Buffer !== 'undefined') {
    const buf = Buffer.from(base64url, 'base64url');
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  let b64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) {
    b64 += '=';
  }
  return base64ToBytes(b64);
}

/**
 * Decodes a URL-safe Base64URL string into an ArrayBuffer.
 */
export function base64UrlToBuffer(base64url: string): ArrayBuffer {
  const bytes = base64UrlToBytes(base64url);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

/**
 * Converts a UTF-8 string to a Uint8Array.
 */
export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Converts a byte array to a UTF-8 string.
 */
export function bytesToString(bytes: Uint8Array | ArrayBuffer): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return new TextDecoder().decode(u8);
}

/**
 * Pure Uint8Array CBOR encoder for WebAuthn COSE and attestation objects.
 * Operates isomorphically across Browser and Node.js without Buffer dependencies.
 */
export function encodeCborU8(data: any): Uint8Array {
  if (data === null || data === undefined) {
    return new Uint8Array([0xf6]);
  }
  if (typeof data === 'boolean') {
    return new Uint8Array([data ? 0xf5 : 0xf4]);
  }
  if (typeof data === 'number' && Number.isInteger(data)) {
    if (data >= 0) {
      if (data < 24) return new Uint8Array([data]);
      if (data <= 0xff) return new Uint8Array([0x18, data]);
      if (data <= 0xffff) return new Uint8Array([0x19, (data >> 8) & 0xff, data & 0xff]);
      return new Uint8Array([0x1a, (data >> 24) & 0xff, (data >> 16) & 0xff, (data >> 8) & 0xff, data & 0xff]);
    } else {
      const val = -1 - data;
      if (val < 24) return new Uint8Array([0x20 + val]);
      if (val <= 0xff) return new Uint8Array([0x38, val]);
      if (val <= 0xffff) return new Uint8Array([0x39, (val >> 8) & 0xff, val & 0xff]);
      return new Uint8Array([0x3a, (val >> 24) & 0xff, (val >> 16) & 0xff, (val >> 8) & 0xff, val & 0xff]);
    }
  }
  if (typeof data === 'string') {
    const strBytes = new TextEncoder().encode(data);
    const len = strBytes.length;
    let header: Uint8Array;
    if (len < 24) header = new Uint8Array([0x60 + len]);
    else if (len <= 0xff) header = new Uint8Array([0x78, len]);
    else header = new Uint8Array([0x79, (len >> 8) & 0xff, len & 0xff]);
    const out = new Uint8Array(header.length + len);
    out.set(header, 0);
    out.set(strBytes, header.length);
    return out;
  }
  if (data instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(data))) {
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    const len = bytes.length;
    let header: Uint8Array;
    if (len < 24) header = new Uint8Array([0x40 + len]);
    else if (len <= 0xff) header = new Uint8Array([0x58, len]);
    else header = new Uint8Array([0x59, (len >> 8) & 0xff, len & 0xff]);
    const out = new Uint8Array(header.length + len);
    out.set(header, 0);
    out.set(bytes, header.length);
    return out;
  }
  if (Array.isArray(data)) {
    const len = data.length;
    let header: Uint8Array;
    if (len < 24) header = new Uint8Array([0x80 + len]);
    else if (len <= 0xff) header = new Uint8Array([0x98, len]);
    else if (len <= 0xffff) header = new Uint8Array([0x99, (len >> 8) & 0xff, len & 0xff]);
    else header = new Uint8Array([0x9a, (len >> 24) & 0xff, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff]);
    const chunks: Uint8Array[] = [header];
    let totalLen = header.length;
    for (const item of data) {
      const ei = encodeCborU8(item);
      chunks.push(ei);
      totalLen += ei.length;
    }
    const out = new Uint8Array(totalLen);
    let offset = 0;
    for (const c of chunks) {
      out.set(c, offset);
      offset += c.length;
    }
    return out;
  }
  if (data instanceof Map) {
    const size = data.size;
    let header: Uint8Array;
    if (size < 24) header = new Uint8Array([0xa0 + size]);
    else header = new Uint8Array([0xb8, size]);
    const chunks: Uint8Array[] = [header];
    let totalLen = header.length;
    for (const [k, v] of data.entries()) {
      const ek = encodeCborU8(k);
      const ev = encodeCborU8(v);
      chunks.push(ek, ev);
      totalLen += ek.length + ev.length;
    }
    const out = new Uint8Array(totalLen);
    let offset = 0;
    for (const c of chunks) {
      out.set(c, offset);
      offset += c.length;
    }
    return out;
  }
  throw new Error(`Unsupported type for CBOR encoding: ${typeof data}`);
}

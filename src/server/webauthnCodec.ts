/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * CBOR and ASN.1 helpers for the in-memory WebAuthn ceremony.
 * This is a different CBOR subset from src/lib/crypto/encoding.ts.
 */

export class CborReader {
  private offset = 0;
  constructor(private buffer: Buffer) {}

  public getOffset(): number {
    return this.offset;
  }

  public hasMore(): boolean {
    return this.offset < this.buffer.length;
  }

  public read(): any {
    if (this.offset >= this.buffer.length) {
      throw new Error(`CBOR unexpected EOF at offset ${this.offset}`);
    }

    const initialByte = this.buffer[this.offset++];
    const majorType = initialByte >> 5;
    const additionalInfo = initialByte & 0x1f;

    const lengthOrVal = this.readLengthOrVal(additionalInfo);

    switch (majorType) {
      case 0: // Unsigned integer
        return lengthOrVal;

      case 1: // Negative integer: -1 - val
        return -1 - lengthOrVal;

      case 2: { // Byte string
        const len = lengthOrVal;
        if (this.offset + len > this.buffer.length) {
          throw new Error(`CBOR byte string exceeds buffer at offset ${this.offset}`);
        }
        const slice = this.buffer.subarray(this.offset, this.offset + len);
        this.offset += len;
        return slice;
      }

      case 3: { // UTF-8 text string
        const len = lengthOrVal;
        if (this.offset + len > this.buffer.length) {
          throw new Error(`CBOR text string exceeds buffer at offset ${this.offset}`);
        }
        const str = this.buffer.toString('utf-8', this.offset, this.offset + len);
        this.offset += len;
        return str;
      }

      case 4: { // Array
        const len = lengthOrVal;
        const arr: any[] = [];
        for (let i = 0; i < len; i++) {
          arr.push(this.read());
        }
        return arr;
      }

      case 5: { // Map
        const len = lengthOrVal;
        const map = new Map<any, any>();
        for (let i = 0; i < len; i++) {
          const key = this.read();
          const value = this.read();
          map.set(key, value);
        }
        return map;
      }

      case 6: // Tagged item
        return this.read();

      case 7: // Simple / Float
        if (additionalInfo === 20) return false;
        if (additionalInfo === 21) return true;
        if (additionalInfo === 22) return null;
        if (additionalInfo === 23) return undefined;
        return lengthOrVal;

      default:
        throw new Error(`Unsupported CBOR major type ${majorType}`);
    }
  }

  private readLengthOrVal(info: number): number {
    if (info < 24) {
      return info;
    } else if (info === 24) {
      if (this.offset + 1 > this.buffer.length) throw new Error('CBOR unexpected EOF');
      return this.buffer.readUInt8(this.offset++);
    } else if (info === 25) {
      if (this.offset + 2 > this.buffer.length) throw new Error('CBOR unexpected EOF');
      const val = this.buffer.readUInt16BE(this.offset);
      this.offset += 2;
      return val;
    } else if (info === 26) {
      if (this.offset + 4 > this.buffer.length) throw new Error('CBOR unexpected EOF');
      const val = this.buffer.readUInt32BE(this.offset);
      this.offset += 4;
      return val;
    } else if (info === 27) {
      if (this.offset + 8 > this.buffer.length) throw new Error('CBOR unexpected EOF');
      const big = this.buffer.readBigUInt64BE(this.offset);
      this.offset += 8;
      return Number(big);
    } else {
      throw new Error(`Unsupported CBOR additional info ${info}`);
    }
  }
}

export function decodeCbor(buf: Buffer): any {
  const reader = new CborReader(buf);
  return reader.read();
}

/**
 * Minimal CBOR Encoder for testing and synthetic fixture creation
 */
export function encodeCbor(data: any): Buffer {
  if (data === null || data === undefined) {
    return Buffer.from([0xf6]);
  }
  if (typeof data === 'boolean') {
    return Buffer.from([data ? 0xf5 : 0xf4]);
  }
  if (typeof data === 'number') {
    if (Number.isInteger(data)) {
      if (data >= 0) {
        if (data < 24) return Buffer.from([data]);
        if (data <= 0xff) return Buffer.from([0x18, data]);
        if (data <= 0xffff) {
          const b = Buffer.alloc(3);
          b[0] = 0x19;
          b.writeUInt16BE(data, 1);
          return b;
        }
        const b = Buffer.alloc(5);
        b[0] = 0x1a;
        b.writeUInt32BE(data, 1);
        return b;
      } else {
        const val = -1 - data;
        if (val < 24) return Buffer.from([0x20 + val]);
        if (val <= 0xff) return Buffer.from([0x38, val]);
        if (val <= 0xffff) {
          const b = Buffer.alloc(3);
          b[0] = 0x39;
          b.writeUInt16BE(val, 1);
          return b;
        }
        const b = Buffer.alloc(5);
        b[0] = 0x3a;
        b.writeUInt32BE(val, 1);
        return b;
      }
    }
  }
  if (typeof data === 'string') {
    const strBuf = Buffer.from(data, 'utf-8');
    const len = strBuf.length;
    let header: Buffer;
    if (len < 24) header = Buffer.from([0x60 + len]);
    else if (len <= 0xff) header = Buffer.from([0x78, len]);
    else {
      header = Buffer.alloc(3);
      header[0] = 0x79;
      header.writeUInt16BE(len, 1);
    }
    return Buffer.concat([header, strBuf]);
  }
  if (Buffer.isBuffer(data)) {
    const len = data.length;
    let header: Buffer;
    if (len < 24) header = Buffer.from([0x40 + len]);
    else if (len <= 0xff) header = Buffer.from([0x58, len]);
    else {
      header = Buffer.alloc(3);
      header[0] = 0x59;
      header.writeUInt16BE(len, 1);
    }
    return Buffer.concat([header, data]);
  }
  if (Array.isArray(data)) {
    const count = data.length;
    let header: Buffer;
    if (count < 24) header = Buffer.from([0x80 + count]);
    else header = Buffer.from([0x98, count]);
    return Buffer.concat([header, ...data.map(encodeCbor)]);
  }
  if (data instanceof Map) {
    const count = data.size;
    let header: Buffer;
    if (count < 24) header = Buffer.from([0xa0 + count]);
    else header = Buffer.from([0xb8, count]);
    const entries: Buffer[] = [];
    for (const [k, v] of data.entries()) {
      entries.push(encodeCbor(k), encodeCbor(v));
    }
    return Buffer.concat([header, ...entries]);
  }
  if (typeof data === 'object') {
    const keys = Object.keys(data);
    const count = keys.length;
    let header: Buffer;
    if (count < 24) header = Buffer.from([0xa0 + count]);
    else header = Buffer.from([0xb8, count]);
    const entries: Buffer[] = [];
    for (const k of keys) {
      entries.push(encodeCbor(k), encodeCbor(data[k]));
    }
    return Buffer.concat([header, ...entries]);
  }
  throw new Error(`Unsupported type for CBOR encoding: ${typeof data}`);
}

// ---------------------------------------------------------------------------
// Signature Encoding Helpers (IEEE P1363 to ASN.1 DER)
// ---------------------------------------------------------------------------

function encodeAsn1Integer(bytes: Buffer): Buffer {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start++;
  }
  let slice = bytes.subarray(start);
  if (slice[0] & 0x80) {
    slice = Buffer.concat([Buffer.from([0x00]), slice]);
  }
  return Buffer.concat([Buffer.from([0x02, slice.length]), slice]);
}

export function rawSignatureToDer(sig: Buffer): Buffer {
  if (sig.length !== 64) return sig;
  const r = sig.subarray(0, 32);
  const s = sig.subarray(32, 64);
  const rEnc = encodeAsn1Integer(r);
  const sEnc = encodeAsn1Integer(s);
  return Buffer.concat([
    Buffer.from([0x30, rEnc.length + sEnc.length]),
    rEnc,
    sEnc
  ]);
}

/**
 * Validates whether a buffer conforms to the ASN.1 DER SEQUENCE structure for ECDSA P-256 signatures.
 */
export function isDerSignature(sig: Buffer): boolean {
  if (sig.length < 8 || sig.length > 74) return false;
  if (sig[0] !== 0x30) return false;
  if (sig[1] !== sig.length - 2) return false;
  if (sig[2] !== 0x02) return false;
  const lenR = sig[3];
  if (4 + lenR >= sig.length) return false;
  if (sig[4 + lenR] !== 0x02) return false;
  const lenS = sig[5 + lenR];
  if (6 + lenR + lenS !== sig.length) return false;
  return true;
}

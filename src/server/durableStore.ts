/**
 * Single-node store for challenges, credentials, and revocations.
 * MemoryDurableMap is the test and default backend.
 * FileDurableMap writes one JSON snapshot per mutation (SECURITY_STORE=file).
 * A second process on the same files will clobber them. Do not store private keys.
 */

import fs from 'fs';
import path from 'path';

export interface DurableStore<T> {
  get(key: string): T | undefined;
  set(key: string, value: T): this;
  has(key: string): boolean;
  delete(key: string): boolean;
  readonly size: number;
  keys(): IterableIterator<string>;
  entries(): IterableIterator<[string, T]>;
  values(): IterableIterator<T>;
  clear(): void;
  /** Persist an in-place mutation of the object already stored at key. */
  commit(key: string): void;
  /**
   * Replace or delete the entry when the current JSON snapshot equals expected.
   * expected is null when the key must be absent. next is null to delete.
   */
  compareAndSet(key: string, expected: string | null, next: T | null): boolean;
  [Symbol.iterator](): IterableIterator<[string, T]>;
}

export function durableSnapshot(value: unknown): string | null {
  if (value === undefined) return null;
  return JSON.stringify(value);
}

function compareAndSetOn<T>(
  store: DurableStore<T>,
  key: string,
  expected: string | null,
  next: T | null
): boolean {
  const current = store.has(key) ? durableSnapshot(store.get(key)) : null;
  if (current !== expected) return false;
  if (next === null) store.delete(key);
  else store.set(key, next);
  return true;
}

export class MemoryDurableMap<T> extends Map<string, T> implements DurableStore<T> {
  commit(_key: string): void {}

  compareAndSet(key: string, expected: string | null, next: T | null): boolean {
    return compareAndSetOn(this, key, expected, next);
  }
}

interface StoreFile {
  version: 1;
  entries: [string, unknown][];
}

function isStoreFile(value: unknown): value is StoreFile {
  if (!value || typeof value !== 'object') return false;
  const file = value as StoreFile;
  if (file.version !== 1 || !Array.isArray(file.entries)) return false;
  return file.entries.every((entry) => Array.isArray(entry) && entry.length === 2 && typeof entry[0] === 'string');
}

export class FileDurableMap<T> extends Map<string, T> implements DurableStore<T> {
  private readonly filePath: string;

  constructor(filePath: string) {
    super();
    this.filePath = filePath;
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    this.load();
  }

  override set(key: string, value: T): this {
    super.set(key, value);
    this.persist();
    return this;
  }

  override delete(key: string): boolean {
    const removed = super.delete(key);
    if (removed) this.persist();
    return removed;
  }

  override clear(): void {
    super.clear();
    this.persist();
  }

  commit(_key: string): void {
    this.persist();
  }

  compareAndSet(key: string, expected: string | null, next: T | null): boolean {
    return compareAndSetOn(this, key, expected, next);
  }

  private load(): void {
    if (!fs.existsSync(this.filePath)) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
    } catch {
      throw new Error(`Refusing to open corrupt security store ${this.filePath}`);
    }
    if (!isStoreFile(parsed)) {
      throw new Error(`Refusing to open corrupt security store ${this.filePath}`);
    }
    for (const [key, value] of parsed.entries) {
      super.set(key, value as T);
    }
  }

  private persist(): void {
    const payload = JSON.stringify({
      version: 1,
      entries: Array.from(this.entries()),
    });
    const tmp = `${this.filePath}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, payload, { mode: 0o600 });
    fs.renameSync(tmp, this.filePath);
  }
}

export function openDurableMap<T>(name: string): DurableStore<T> {
  if (process.env.SECURITY_STORE === 'file') {
    const root = process.env.SECURITY_STORE_PATH || path.join(process.cwd(), 'data', 'security-store');
    return new FileDurableMap<T>(path.join(root, `${name}.json`));
  }
  return new MemoryDurableMap<T>();
}

/** Forwards Map operations to whichever store currently occupies the slot. */
export function bindDurableStore<T>(read: () => DurableStore<T>): DurableStore<T> {
  return new Proxy({} as DurableStore<T>, {
    get(_target, prop) {
      const store = read();
      const value = Reflect.get(store, prop, store);
      if (typeof value === 'function') return value.bind(store);
      return value;
    },
    has(_target, prop) {
      return Reflect.has(read(), prop);
    },
  });
}

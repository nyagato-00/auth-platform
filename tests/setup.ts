// tests/setup.ts を修正
import { beforeAll, afterAll, vi } from 'vitest';
import { HonoRequest } from 'hono';

declare module 'hono' {
  interface HonoRequest {
    user?: any;
  }
}

// CryptoKeyのモック
const createMockCryptoKey = (): CryptoKey => {
  return {
    algorithm: { name: 'HMAC' },
    extractable: false,
    type: 'secret',
    usages: ['sign', 'verify']
  } as CryptoKey;
};

// グローバルモック
beforeAll(() => {
  // cryptoメソッドをモック
  if (globalThis.crypto) {
    // getRandomValuesをモック
    vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation((array) => {
      if (array instanceof Uint8Array) {
        for (let i = 0; i < array.length; i++) {
          array[i] = Math.floor(Math.random() * 256);
        }
      }
      return array;
    });
    
    // randomUUIDをモック
    vi.spyOn(globalThis.crypto, 'randomUUID').mockImplementation(() => {
      return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = Math.floor(Math.random() * 16);
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
      }) as `${string}-${string}-${string}-${string}-${string}`;
    });

    // subtle cryptoメソッドをモック
    if (globalThis.crypto.subtle) {
      // digestをモック
      vi.spyOn(globalThis.crypto.subtle, 'digest').mockImplementation(async () => {
        return new Uint8Array(32).buffer;
      });
      
      // importKeyをモック
      vi.spyOn(globalThis.crypto.subtle, 'importKey').mockImplementation(async () => {
        return createMockCryptoKey();
      });
      
      // signをモック
      vi.spyOn(globalThis.crypto.subtle, 'sign').mockImplementation(async () => {
        return new Uint8Array(32).buffer;
      });
      
      // verifyをモック
      vi.spyOn(globalThis.crypto.subtle, 'verify').mockResolvedValue(true);
      
      // encryptをモック
      vi.spyOn(globalThis.crypto.subtle, 'encrypt').mockResolvedValue(new Uint8Array(32).buffer);
      
      // decryptをモック
      vi.spyOn(globalThis.crypto.subtle, 'decrypt').mockResolvedValue(new Uint8Array(32).buffer);
      
      // deriveBitsをモック
      vi.spyOn(globalThis.crypto.subtle, 'deriveBits').mockResolvedValue(new Uint8Array(32).buffer);
      
      // deriveKeyをモック
      vi.spyOn(globalThis.crypto.subtle, 'deriveKey').mockResolvedValue(createMockCryptoKey());
      
      // generateKeyをモック - CryptoKeyPairを返す場合も考慮
      vi.spyOn(globalThis.crypto.subtle, 'generateKey').mockResolvedValue({
        privateKey: createMockCryptoKey(),
        publicKey: createMockCryptoKey()
      } as CryptoKeyPair);
      
      // unwrapKeyをモック
      vi.spyOn(globalThis.crypto.subtle, 'unwrapKey').mockResolvedValue(createMockCryptoKey());
      
      // wrapKeyをモック
      vi.spyOn(globalThis.crypto.subtle, 'wrapKey').mockResolvedValue(new Uint8Array(32).buffer);
    }
  }

  // atobとbtoaのモック（Node.js環境では使用できない場合がある）
  if (!globalThis.atob) {
    globalThis.atob = (str: string) => Buffer.from(str, 'base64').toString('binary');
  }
  
  if (!globalThis.btoa) {
    globalThis.btoa = (str: string) => Buffer.from(str, 'binary').toString('base64');
  }
  
  // TextEncoderのモック
  if (!globalThis.TextEncoder) {
    // @ts-ignore - TextEncoderのインターフェースとのマッチング問題を無視
    globalThis.TextEncoder = class {
      encoding = 'utf-8';
      encode(str: string) {
        return new Uint8Array(Buffer.from(str));
      }
      encodeInto(src: string, dest: Uint8Array) {
        const encoded = this.encode(src);
        dest.set(encoded);
        return {
          read: src.length,
          written: Math.min(encoded.length, dest.length)
        };
      }
    };
  }
});

afterAll(() => {
  vi.clearAllMocks();
});
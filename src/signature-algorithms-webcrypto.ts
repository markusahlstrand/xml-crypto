import { createAsyncOptionalCallbackFunction, type SignatureAlgorithm } from "./types";
import {
  importRsaPrivateKey,
  importRsaPublicKey,
  importHmacKey,
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from "./webcrypto-utils";

/**
 * Convert various input types to ArrayBuffer for Web Crypto API
 */
function toArrayBuffer(data: unknown): ArrayBuffer {
  if (typeof data === "string") {
    return new TextEncoder().encode(data).buffer;
  }
  if (data instanceof ArrayBuffer) {
    return data;
  }
  if (data instanceof Uint8Array || Buffer.isBuffer(data)) {
    // Create a new ArrayBuffer from the Uint8Array/Buffer
    const buffer = new ArrayBuffer((data as Uint8Array).byteLength);
    const view = new Uint8Array(buffer);
    view.set(data as Uint8Array);
    return buffer;
  }
  throw new Error("Unsupported data type");
}

/**
 * WebCrypto-based RSA-SHA1 signature algorithm
 * Uses the Web Crypto API which is available in browsers and modern Node.js
 */
export class WebCryptoRsaSha1 implements SignatureAlgorithm {
  getSignature = createAsyncOptionalCallbackFunction(
    async (signedInfo: unknown, privateKey: unknown): Promise<string> => {
      const key =
        typeof privateKey === "string"
          ? await importRsaPrivateKey(privateKey, "SHA-1")
          : (privateKey as CryptoKey);

      const data = toArrayBuffer(signedInfo);

      const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data);

      return arrayBufferToBase64(signature);
    },
  );

  verifySignature = createAsyncOptionalCallbackFunction(
    async (material: string, key: unknown, signatureValue: string): Promise<boolean> => {
      const publicKey =
        typeof key === "string" ? await importRsaPublicKey(key, "SHA-1") : (key as CryptoKey);

      const data = new TextEncoder().encode(material);
      const signature = base64ToArrayBuffer(signatureValue);

      return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, data);
    },
  );

  getAlgorithmName = (): string => {
    return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  };
}

/**
 * WebCrypto-based RSA-SHA256 signature algorithm
 * Uses the Web Crypto API which is available in browsers and modern Node.js
 */
export class WebCryptoRsaSha256 implements SignatureAlgorithm {
  getSignature = createAsyncOptionalCallbackFunction(
    async (signedInfo: unknown, privateKey: unknown): Promise<string> => {
      const key =
        typeof privateKey === "string"
          ? await importRsaPrivateKey(privateKey, "SHA-256")
          : (privateKey as CryptoKey);

      const data = toArrayBuffer(signedInfo);

      const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data);

      return arrayBufferToBase64(signature);
    },
  );

  verifySignature = createAsyncOptionalCallbackFunction(
    async (material: string, key: unknown, signatureValue: string): Promise<boolean> => {
      const publicKey =
        typeof key === "string" ? await importRsaPublicKey(key, "SHA-256") : (key as CryptoKey);

      const data = new TextEncoder().encode(material);
      const signature = base64ToArrayBuffer(signatureValue);

      return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, data);
    },
  );

  getAlgorithmName = (): string => {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  };
}

/**
 * WebCrypto-based RSA-SHA512 signature algorithm
 * Uses the Web Crypto API which is available in browsers and modern Node.js
 */
export class WebCryptoRsaSha512 implements SignatureAlgorithm {
  getSignature = createAsyncOptionalCallbackFunction(
    async (signedInfo: unknown, privateKey: unknown): Promise<string> => {
      const key =
        typeof privateKey === "string"
          ? await importRsaPrivateKey(privateKey, "SHA-512")
          : (privateKey as CryptoKey);

      const data = toArrayBuffer(signedInfo);

      const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data);

      return arrayBufferToBase64(signature);
    },
  );

  verifySignature = createAsyncOptionalCallbackFunction(
    async (material: string, key: unknown, signatureValue: string): Promise<boolean> => {
      const publicKey =
        typeof key === "string" ? await importRsaPublicKey(key, "SHA-512") : (key as CryptoKey);

      const data = new TextEncoder().encode(material);
      const signature = base64ToArrayBuffer(signatureValue);

      return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, data);
    },
  );

  getAlgorithmName = (): string => {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
  };
}

/**
 * WebCrypto-based HMAC-SHA1 signature algorithm
 * Uses the Web Crypto API which is available in browsers and modern Node.js
 */
export class WebCryptoHmacSha1 implements SignatureAlgorithm {
  getSignature = createAsyncOptionalCallbackFunction(
    async (signedInfo: unknown, privateKey: unknown): Promise<string> => {
      const key =
        typeof privateKey === "string"
          ? await importHmacKey(privateKey, "SHA-1")
          : (privateKey as CryptoKey);

      const data = toArrayBuffer(signedInfo);

      const signature = await crypto.subtle.sign("HMAC", key, data);

      return arrayBufferToBase64(signature);
    },
  );

  verifySignature = createAsyncOptionalCallbackFunction(
    async (material: string, key: unknown, signatureValue: string): Promise<boolean> => {
      const hmacKey =
        typeof key === "string" ? await importHmacKey(key, "SHA-1") : (key as CryptoKey);

      const data = new TextEncoder().encode(material);

      const signature = await crypto.subtle.sign("HMAC", hmacKey, data);
      const computedSignature = arrayBufferToBase64(signature);

      return computedSignature === signatureValue;
    },
  );

  getAlgorithmName = (): string => {
    return "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
  };
}

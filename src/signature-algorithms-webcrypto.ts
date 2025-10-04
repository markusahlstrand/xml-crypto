import { createAsyncOptionalCallbackFunction, type SignatureAlgorithm } from "./types";
import {
  importRsaPrivateKey,
  importRsaPublicKey,
  importHmacKey,
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from "./webcrypto-utils";
import * as nodeCrypto from "crypto";

/**
 * Check if a value is a CryptoKey (not a KeyObject)
 */
function isCryptoKey(key: unknown): key is CryptoKey {
  // CryptoKey has specific properties that KeyObject doesn't have
  return (
    key instanceof CryptoKey ||
    (typeof key === "object" &&
      key !== null &&
      "type" in key &&
      "algorithm" in key &&
      "extractable" in key &&
      "usages" in key &&
      !("export" in key)) // KeyObject has export, CryptoKey doesn't
  );
}

/**
 * Convert various key input types to a string (PEM format) that can be imported
 */
function keyToString(key: unknown): string {
  if (typeof key === "string") {
    return key;
  }
  if (Buffer.isBuffer(key)) {
    return key.toString("utf8");
  }
  if (key instanceof Uint8Array) {
    return Buffer.from(key).toString("utf8");
  }
  // Handle Node.js KeyObject
  if (
    typeof key === "object" &&
    key !== null &&
    "type" in key &&
    "export" in key &&
    typeof (key as { export: unknown }).export === "function" &&
    !("algorithm" in key && "extractable" in key && "usages" in key) // Not a CryptoKey
  ) {
    const keyObject = key as nodeCrypto.KeyObject;
    if (keyObject.type === "private") {
      return keyObject.export({ type: "pkcs8", format: "pem" }) as string;
    } else if (keyObject.type === "public") {
      return keyObject.export({ type: "spki", format: "pem" }) as string;
    } else if (keyObject.type === "secret") {
      // For secret keys (HMAC), export as buffer and convert to base64
      const secretBuffer = keyObject.export();
      return secretBuffer.toString("base64");
    }
  }
  throw new Error(
    "Unsupported key type. Expected string (PEM), Buffer, Uint8Array, KeyObject, or CryptoKey",
  );
}

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
      // If already a CryptoKey, use it directly
      let key: CryptoKey;
      if (isCryptoKey(privateKey)) {
        key = privateKey;
      } else {
        // Convert to string (handles Buffer, KeyObject, etc.) and import
        const keyString = keyToString(privateKey);
        key = await importRsaPrivateKey(keyString, "SHA-1");
      }

      const data = toArrayBuffer(signedInfo);

      const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data);

      return arrayBufferToBase64(signature);
    },
  );

  verifySignature = createAsyncOptionalCallbackFunction(
    async (material: string, key: unknown, signatureValue: string): Promise<boolean> => {
      // If already a CryptoKey, use it directly
      let publicKey: CryptoKey;
      if (isCryptoKey(key)) {
        publicKey = key;
      } else {
        // Convert to string (handles Buffer, KeyObject, etc.) and import
        const keyString = keyToString(key);
        publicKey = await importRsaPublicKey(keyString, "SHA-1");
      }

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
      // If already a CryptoKey, use it directly
      let key: CryptoKey;
      if (isCryptoKey(privateKey)) {
        key = privateKey;
      } else {
        // Convert to string (handles Buffer, KeyObject, etc.) and import
        const keyString = keyToString(privateKey);
        key = await importRsaPrivateKey(keyString, "SHA-256");
      }

      const data = toArrayBuffer(signedInfo);

      const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data);

      return arrayBufferToBase64(signature);
    },
  );

  verifySignature = createAsyncOptionalCallbackFunction(
    async (material: string, key: unknown, signatureValue: string): Promise<boolean> => {
      // If already a CryptoKey, use it directly
      let publicKey: CryptoKey;
      if (isCryptoKey(key)) {
        publicKey = key;
      } else {
        // Convert to string (handles Buffer, KeyObject, etc.) and import
        const keyString = keyToString(key);
        publicKey = await importRsaPublicKey(keyString, "SHA-256");
      }

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
      // If already a CryptoKey, use it directly
      let key: CryptoKey;
      if (isCryptoKey(privateKey)) {
        key = privateKey;
      } else {
        // Convert to string (handles Buffer, KeyObject, etc.) and import
        const keyString = keyToString(privateKey);
        key = await importRsaPrivateKey(keyString, "SHA-512");
      }

      const data = toArrayBuffer(signedInfo);

      const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data);

      return arrayBufferToBase64(signature);
    },
  );

  verifySignature = createAsyncOptionalCallbackFunction(
    async (material: string, key: unknown, signatureValue: string): Promise<boolean> => {
      // If already a CryptoKey, use it directly
      let publicKey: CryptoKey;
      if (isCryptoKey(key)) {
        publicKey = key;
      } else {
        // Convert to string (handles Buffer, KeyObject, etc.) and import
        const keyString = keyToString(key);
        publicKey = await importRsaPublicKey(keyString, "SHA-512");
      }

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
      // If already a CryptoKey, use it directly
      let key: CryptoKey;
      if (isCryptoKey(privateKey)) {
        key = privateKey;
      } else {
        // Convert to string (handles Buffer, KeyObject, etc.) and import
        const keyString = keyToString(privateKey);
        key = await importHmacKey(keyString, "SHA-1");
      }

      const data = toArrayBuffer(signedInfo);

      const signature = await crypto.subtle.sign("HMAC", key, data);

      return arrayBufferToBase64(signature);
    },
  );

  verifySignature = createAsyncOptionalCallbackFunction(
    async (material: string, key: unknown, signatureValue: string): Promise<boolean> => {
      // If already a CryptoKey, use it directly
      let hmacKey: CryptoKey;
      if (isCryptoKey(key)) {
        hmacKey = key;
      } else {
        // Convert to string (handles Buffer, KeyObject, etc.) and import
        const keyString = keyToString(key);
        hmacKey = await importHmacKey(keyString, "SHA-1");
      }

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

import type { ErrorFirstCallback, HashAlgorithm } from "./types";
<<<<<<< HEAD
import { getSubtle, arrayBufferToBase64 } from "./webcrypto-utils";
=======
>>>>>>> master

/**
 * WebCrypto-based SHA-1 hash algorithm
 * Uses the Web Crypto API which is available in browsers and modern Node.js
 */
export class WebCryptoSha1 implements HashAlgorithm {
  getHash(xml: string): string;
  getHash(xml: string, callback: ErrorFirstCallback<string>): void;
  getHash(xml: string, callback?: ErrorFirstCallback<string>): string | void {
    if (!callback) {
      throw new Error(
        "WebCrypto hash algorithms are async and require a callback. Use getHash(xml, callback).",
      );
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(xml);
<<<<<<< HEAD
    getSubtle()
      .digest("SHA-1", data)
      .then((hashBuffer) => {
        const hash = arrayBufferToBase64(hashBuffer);
=======
    crypto.subtle
      .digest("SHA-1", data)
      .then((hashBuffer) => {
        const hash = this.arrayBufferToBase64(hashBuffer);
>>>>>>> master
        callback(null, hash);
      })
      .catch((err) => {
        callback(err);
      });
  }

  getAlgorithmName = (): string => {
    return "http://www.w3.org/2000/09/xmldsig#sha1";
  };
}

/**
 * WebCrypto-based SHA-256 hash algorithm
 * Uses the Web Crypto API which is available in browsers and modern Node.js
 */
export class WebCryptoSha256 implements HashAlgorithm {
  getHash(xml: string): string;
  getHash(xml: string, callback: ErrorFirstCallback<string>): void;
  getHash(xml: string, callback?: ErrorFirstCallback<string>): string | void {
    if (!callback) {
      throw new Error(
        "WebCrypto hash algorithms are async and require a callback. Use getHash(xml, callback).",
      );
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(xml);
<<<<<<< HEAD
    getSubtle()
      .digest("SHA-256", data)
      .then((hashBuffer) => {
        const hash = arrayBufferToBase64(hashBuffer);
=======
    crypto.subtle
      .digest("SHA-256", data)
      .then((hashBuffer) => {
        const hash = this.arrayBufferToBase64(hashBuffer);
>>>>>>> master
        callback(null, hash);
      })
      .catch((err) => {
        callback(err);
      });
  }

  getAlgorithmName = (): string => {
    return "http://www.w3.org/2001/04/xmlenc#sha256";
  };
}

/**
 * WebCrypto-based SHA-512 hash algorithm
 * Uses the Web Crypto API which is available in browsers and modern Node.js
 */
export class WebCryptoSha512 implements HashAlgorithm {
  getHash(xml: string): string;
  getHash(xml: string, callback: ErrorFirstCallback<string>): void;
  getHash(xml: string, callback?: ErrorFirstCallback<string>): string | void {
    if (!callback) {
      throw new Error(
        "WebCrypto hash algorithms are async and require a callback. Use getHash(xml, callback).",
      );
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(xml);
<<<<<<< HEAD
    getSubtle()
      .digest("SHA-512", data)
      .then((hashBuffer) => {
        const hash = arrayBufferToBase64(hashBuffer);
=======
    crypto.subtle
      .digest("SHA-512", data)
      .then((hashBuffer) => {
        const hash = this.arrayBufferToBase64(hashBuffer);
>>>>>>> master
        callback(null, hash);
      })
      .catch((err) => {
        callback(err);
      });
  }

  getAlgorithmName = (): string => {
    return "http://www.w3.org/2001/04/xmlenc#sha512";
  };
}

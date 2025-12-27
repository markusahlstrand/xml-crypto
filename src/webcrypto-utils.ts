/**
 * Utility functions for working with Web Crypto API
 */

/**
 * Interface for extracting public keys from X.509 certificates.
 * Implement this interface to enable X.509 certificate support with WebCrypto.
 */
export interface CertificateParser {
  /**
   * Extract the public key (in SPKI format) from an X.509 certificate
   * @param certPem PEM-encoded X.509 certificate
   * @returns ArrayBuffer containing the SPKI-encoded public key
   */
  extractPublicKey(certPem: string): ArrayBuffer | Promise<ArrayBuffer>;
}

/**
 * Global certificate parser instance.
 * Set this to enable X.509 certificate support.
 */
let certificateParser: CertificateParser | null = null;

/**
 * Set a custom certificate parser for extracting public keys from X.509 certificates.
 * This enables WebCrypto to work with X.509 certificates by using an external ASN.1 parser.
 * @param parser The certificate parser implementation, or null to disable
 * @example
 * // Using @peculiar/x509 library
 * import * as x509 from "@peculiar/x509";
 * import { setCertificateParser } from "xml-crypto";
 *
 * setCertificateParser({
 *   extractPublicKey(certPem: string): ArrayBuffer {
 *     const cert = new x509.X509Certificate(certPem);
 *     return cert.publicKey.rawData;
 *   }
 * });
 */
export function setCertificateParser(parser: CertificateParser | null): void {
  certificateParser = parser;
}

/**
 * Get the currently configured certificate parser.
 * @returns The certificate parser or null if not configured
 */
export function getCertificateParser(): CertificateParser | null {
  return certificateParser;
}

/**
 * Get the SubtleCrypto interface in a cross-runtime safe way.
 * Works in browsers (uses globalThis.crypto.subtle) and Node.js (uses node:crypto webcrypto).
 */
export function getSubtle(): SubtleCrypto {
  // Check for globalThis.crypto.subtle (browsers and modern Node.js with global webcrypto)
  if (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle) {
    return globalThis.crypto.subtle;
  }

  // Node.js fallback: require node:crypto and use webcrypto
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const nodeCrypto = require("node:crypto");
  if (nodeCrypto.webcrypto && nodeCrypto.webcrypto.subtle) {
    return nodeCrypto.webcrypto.subtle as SubtleCrypto;
  }

  throw new Error(
    "SubtleCrypto is not available. Ensure you are running in a browser or Node.js 16+ environment.",
  );
}

/**
 * Convert an ArrayBuffer to base64 string in a cross-runtime safe way.
 * Works in browsers (uses btoa) and Node.js (uses Buffer).
 * @param buffer ArrayBuffer to convert
 * @returns Base64-encoded string
 */
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);

  // Node.js: use Buffer for base64 encoding
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }

  // Browser: use btoa
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert a base64 string to ArrayBuffer in a cross-runtime safe way.
 * Works in browsers (uses atob) and Node.js (uses Buffer).
 * @param base64 Base64-encoded string
 * @returns ArrayBuffer
 */
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  // Node.js: use Buffer for base64 decoding
  if (typeof Buffer !== "undefined") {
    const buf = Buffer.from(base64, "base64");
    // Copy to a fresh ArrayBuffer to avoid issues with Buffer's pooled memory
    const arrayBuffer = new ArrayBuffer(buf.byteLength);
    new Uint8Array(arrayBuffer).set(buf);
    return arrayBuffer;
  }

  // Browser: use atob
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Convert a PEM string to an ArrayBuffer
 * @param pem PEM-encoded key (with or without headers)
 * @returns ArrayBuffer containing the binary key data
 */
export function pemToArrayBuffer(pem: string): ArrayBuffer {
  // Remove PEM headers and whitespace
  const pemContent = pem
    .replace(/-----BEGIN [A-Z ]+-----/, "")
    .replace(/-----END [A-Z ]+-----/, "")
    .replace(/\s/g, "");

  // Use cross-runtime base64 decoding
  return base64ToArrayBuffer(pemContent);
}

/**
 * Import a PEM-encoded RSA private key for signing
 * @param pem PEM-encoded private key
 * @param hashAlgorithm Hash algorithm name (e.g., "SHA-1", "SHA-256", "SHA-512")
 * @returns CryptoKey for signing
 */
export async function importRsaPrivateKey(
  pem: string | ArrayBuffer,
  hashAlgorithm: string,
): Promise<CryptoKey> {
  const keyData = typeof pem === "string" ? pemToArrayBuffer(pem) : pem;
  const subtle = getSubtle();

  return await subtle.importKey(
    "pkcs8",
    keyData,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: hashAlgorithm },
    },
    false,
    ["sign"],
  );
}

/**
 * Import a PEM-encoded RSA public key for verification
 * @param pem PEM-encoded public key or certificate
 * @param hashAlgorithm Hash algorithm name (e.g., "SHA-1", "SHA-256", "SHA-512")
 * @returns CryptoKey for verification
 */
export async function importRsaPublicKey(
  pem: string | ArrayBuffer,
  hashAlgorithm: string,
): Promise<CryptoKey> {
  let keyData: ArrayBuffer;
  const subtle = getSubtle();

  if (typeof pem === "string") {
    // Check if this is a certificate
    if (pem.includes("BEGIN CERTIFICATE")) {
      if (certificateParser) {
        // Use the configured certificate parser to extract the public key
        keyData = await Promise.resolve(certificateParser.extractPublicKey(pem));
      } else {
        throw new Error(
          "X.509 certificates require a certificate parser. " +
            "Call setCertificateParser() with a parser implementation (e.g., using @peculiar/x509), " +
            "or extract the public key manually and provide it in SPKI format. " +
            "See WEBCRYPTO.md for examples.",
        );
      }
    } else {
      keyData = pemToArrayBuffer(pem);
    }
  } else {
    keyData = pem;
  }

  // Try importing as SPKI (SubjectPublicKeyInfo) format
  try {
    return await subtle.importKey(
      "spki",
      keyData,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: hashAlgorithm },
      },
      false,
      ["verify"],
    );
  } catch (error) {
    throw new Error(
      `Failed to import RSA public key. Please ensure the key is in SPKI format. ${error}`,
    );
  }
}

/**
 * Import an HMAC key
 * @param key Key material (string or ArrayBuffer)
 * @param hashAlgorithm Hash algorithm name (e.g., "SHA-1", "SHA-256", "SHA-512")
 * @returns CryptoKey for HMAC operations
 */
export async function importHmacKey(
  key: string | ArrayBuffer,
  hashAlgorithm: string,
): Promise<CryptoKey> {
  const keyData = typeof key === "string" ? new TextEncoder().encode(key) : key;
  const subtle = getSubtle();

  return await subtle.importKey(
    "raw",
    keyData,
    {
      name: "HMAC",
      hash: { name: hashAlgorithm },
    },
    false,
    ["sign", "verify"],
  );
}

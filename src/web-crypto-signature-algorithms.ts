import { X509Certificate } from "@peculiar/x509";
import { ErrorFirstCallback, SignatureAlgorithm, SignatureAlgorithmType } from "./types";

// Helper function to convert string to ArrayBuffer
function str2ab(str: string): ArrayBuffer {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

// Helper function to convert ArrayBuffer to Base64 string
function ab2base64(ab: ArrayBuffer): string {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(ab) as unknown as number[]));
}

// Helper function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary_string = atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

function normalizeKey(key: string): ArrayBuffer {
  // Trim whitespace and get the header
  const trimmedKey = key.trim();
  const header = trimmedKey.split("\n")[0];

  // Remove PEM headers and whitespace
  const pemBody = trimmedKey
    .replace(/-----BEGIN .*-----/, "")
    .replace(/-----END .*-----/, "")
    .replace(/\s/g, "");

  // Convert base64 to ArrayBuffer
  const keyBuffer = base64ToArrayBuffer(pemBody);

  if (header.includes("CERTIFICATE")) {
    // It's a certificate
    const cert = new X509Certificate(keyBuffer);
    return cert.publicKey.rawData;
  } else if (header.includes("PUBLIC KEY")) {
    // It's already a public key (either RSA or generic)
    return keyBuffer;
  } else {
    // Unknown format
    throw new Error("Unsupported key format");
  }
}

function createSyncWrapper<T, A extends unknown[]>(
  asyncFn: (...args: A) => Promise<T>,
): {
  (...args: A): T;
  (...args: [...A, ErrorFirstCallback<T>]): void;
} {
  return ((...args: A | [...A, ErrorFirstCallback<T>]) => {
    const callback =
      typeof args[args.length - 1] === "function" ? (args.pop() as ErrorFirstCallback<T>) : null;

    if (callback) {
      asyncFn(...(args as A)).then(
        (result) => callback(null, result),
        (error) => callback(error instanceof Error ? error : new Error(String(error))),
      );
    } else {
      throw new Error(
        "Synchronous operation not supported. Use with a callback or await the promise version.",
      );
    }
  }) as {
    (...args: A): T;
    (...args: [...A, ErrorFirstCallback<T>]): void;
  };
}

abstract class WebCryptoSignatureAlgorithm implements SignatureAlgorithm {
  protected abstract algorithm: RsaHashedImportParams | HmacImportParams;
  protected abstract signAlgorithm: AlgorithmIdentifier;

  abstract getAlgorithmName(): SignatureAlgorithmType;

  protected async getSignatureAsync(signedInfo: string, privateKey: string): Promise<string> {
    const keyData = base64ToArrayBuffer(privateKey);
    const key = await crypto.subtle.importKey("pkcs8", keyData, this.algorithm, false, ["sign"]);
    const signature = await crypto.subtle.sign(this.signAlgorithm, key, str2ab(signedInfo));
    return ab2base64(signature);
  }

  getSignature = createSyncWrapper(this.getSignatureAsync.bind(this));

  protected async verifySignatureAsync(
    material: string,
    key: string,
    signatureValue: string,
  ): Promise<boolean> {
    const keyData = normalizeKey(key);

    const publicKey = await crypto.subtle.importKey("spki", keyData, this.algorithm, false, [
      "verify",
    ]);
    return await crypto.subtle.verify(
      this.signAlgorithm,
      publicKey,
      base64ToArrayBuffer(signatureValue),
      str2ab(material),
    );
  }

  verifySignature = createSyncWrapper(this.verifySignatureAsync.bind(this));
}

export class RsaSha1 extends WebCryptoSignatureAlgorithm {
  protected algorithm: RsaHashedImportParams = {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-1",
  };
  protected signAlgorithm: AlgorithmIdentifier = this.algorithm;

  getAlgorithmName = (): SignatureAlgorithmType => "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
}

export class RsaSha256 extends WebCryptoSignatureAlgorithm {
  protected algorithm: RsaHashedImportParams = {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
  };
  protected signAlgorithm: AlgorithmIdentifier = this.algorithm;

  getAlgorithmName = (): SignatureAlgorithmType =>
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
}

export class RsaSha512 extends WebCryptoSignatureAlgorithm {
  protected algorithm: RsaHashedImportParams = {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-512",
  };
  protected signAlgorithm: AlgorithmIdentifier = this.algorithm;

  getAlgorithmName = (): SignatureAlgorithmType =>
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
}

export class HmacSha1 extends WebCryptoSignatureAlgorithm {
  protected algorithm: HmacImportParams = {
    name: "HMAC",
    hash: "SHA-1",
  };
  protected signAlgorithm: AlgorithmIdentifier = this.algorithm;

  getAlgorithmName = (): SignatureAlgorithmType => "http://www.w3.org/2000/09/xmldsig#hmac-sha1";

  protected async getSignatureAsync(signedInfo: string, privateKey: string): Promise<string> {
    const keyData = str2ab(privateKey);
    const key = await crypto.subtle.importKey("raw", keyData, this.algorithm, false, ["sign"]);
    const signature = await crypto.subtle.sign(this.signAlgorithm, key, str2ab(signedInfo));
    return ab2base64(signature);
  }

  protected async verifySignatureAsync(
    material: string,
    key: string,
    signatureValue: string,
  ): Promise<boolean> {
    const keyData = str2ab(key);
    const hmacKey = await crypto.subtle.importKey("raw", keyData, this.algorithm, false, [
      "verify",
    ]);
    return await crypto.subtle.verify(
      this.signAlgorithm,
      hmacKey,
      base64ToArrayBuffer(signatureValue),
      str2ab(material),
    );
  }
}

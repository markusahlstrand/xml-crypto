// import type { HashAlgorithm } from "./types";

// abstract class WebCryptoHash implements HashAlgorithm {
//   protected abstract algorithm: string;
//   protected abstract webCryptoAlgorithm: AlgorithmIdentifier;

//   async getHash(xml: string): Promise<string> {
//     const encoder = new TextEncoder();
//     const data = encoder.encode(xml);
//     const hashBuffer = await crypto.subtle.digest(this.webCryptoAlgorithm, data);
//     const hashArray = Array.from(new Uint8Array(hashBuffer));
//     const hashBase64 = btoa(String.fromCharCode.apply(null, hashArray));
//     return hashBase64;
//   }

//   getAlgorithmName(): string {
//     return this.algorithm;
//   }
// }

// export class Sha1 extends WebCryptoHash {
//   protected algorithm = "http://www.w3.org/2000/09/xmldsig#sha1";
//   protected webCryptoAlgorithm = "SHA-1";
// }

// export class Sha256 extends WebCryptoHash {
//   protected algorithm = "http://www.w3.org/2001/04/xmlenc#sha256";
//   protected webCryptoAlgorithm = "SHA-256";
// }

// export class Sha512 extends WebCryptoHash {
//   protected algorithm = "http://www.w3.org/2001/04/xmlenc#sha512";
//   protected webCryptoAlgorithm = "SHA-512";
// }

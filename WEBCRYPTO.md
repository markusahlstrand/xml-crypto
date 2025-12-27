# WebCrypto Support

This library now supports the Web Crypto API, which allows it to run in browsers and modern Node.js environments **without any Node.js-specific dependencies** for cryptographic operations.

## Overview

The WebCrypto implementation provides:

- **Browser compatibility**: Run XML signing and verification in the browser
- **No Node.js crypto dependency**: Uses the standard Web Crypto API
- **Callback-based async operations**: WebCrypto operations use callbacks for async handling
- **Same API structure**: Uses the same methods as Node.js crypto, just with callbacks

## Supported Algorithms

### Hash Algorithms

- `WebCryptoSha1` - SHA-1 hashing
- `WebCryptoSha256` - SHA-256 hashing
- `WebCryptoSha512` - SHA-512 hashing

### Signature Algorithms

- `WebCryptoRsaSha1` - RSA-SHA1 signing/verification
- `WebCryptoRsaSha256` - RSA-SHA256 signing/verification
- `WebCryptoRsaSha512` - RSA-SHA512 signing/verification
- `WebCryptoHmacSha1` - HMAC-SHA1 signing/verification

## Usage

### Basic Example - Signing (Browser or Node.js with WebCrypto)

```javascript
import { SignedXml, WebCryptoRsaSha256, WebCryptoSha256 } from "xml-crypto";

// Your XML to sign
const xml = "<root><data>Hello World</data></root>";

// Your private key (PEM format)
const privateKey = `-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----`;

// Create SignedXml instance
const sig = new SignedXml();

// Use WebCrypto algorithms
sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
sig.privateKey = privateKey;

// Add reference with WebCrypto hash algorithm
sig.addReference({
  xpath: "//*[local-name(.)='data']",
  digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
});

// Register WebCrypto algorithms
sig.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
sig.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] = WebCryptoRsaSha256;

// Compute signature with callback
sig.computeSignature(xml, (err, signedXmlObj) => {
  if (err) {
    console.error("Signing failed:", err);
    return;
  }

  console.log(signedXmlObj.getSignedXml());
});
```

### Verifying a Signature

```javascript
import { SignedXml, WebCryptoRsaSha256, WebCryptoSha256 } from "xml-crypto";
import { DOMParser } from "@xmldom/xmldom";

const signedXml = `<root>...</root>`; // Your signed XML

const sig = new SignedXml();

// Register WebCrypto algorithms
sig.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
sig.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] = WebCryptoRsaSha256;

// Provide public key or certificate (SPKI format)
sig.publicCert = publicKey;

// Load the signature - need to extract it from the signed XML first
const doc = new DOMParser().parseFromString(signedXml);
const signature = sig.findSignatures(doc)[0];
sig.loadSignature(signature);

// Verify with callback
sig.checkSignature(signedXml, (err, isValid) => {
  if (err) {
    console.error("Verification failed:", err);
    return;
  }
  console.log("Signature valid:", isValid);
});
```

## Key Format Conversion

The WebCrypto algorithms accept keys in PEM format (strings) and will automatically convert them to `CryptoKey` objects internally.

**Note**: For verification, WebCrypto requires public keys in SPKI format, not X.509 certificates. See the X.509 Certificates section below for how to extract the public key.

## Using Callbacks with WebCrypto

Both `computeSignature` and `checkSignature` support an optional callback parameter. When using WebCrypto algorithms, you **must** provide a callback to handle the asynchronous operations:

```javascript
// Signing with callback
sig.computeSignature(xml, (err, signedXmlObj) => {
  if (err) {
    console.error("Error:", err);
    return;
  }
  // signedXmlObj is the SignedXml instance
  const result = signedXmlObj.getSignedXml();
});

// Verification with callback
sig.checkSignature(signedXml, (err, isValid) => {
  if (err) {
    console.error("Error:", err);
    return;
  }
  console.log("Valid:", isValid);
});
```

**Important**: If you try to use WebCrypto algorithms without providing a callback, the operation will fail because WebCrypto operations are inherently asynchronous.

## Browser Compatibility

The WebCrypto API is supported in all modern browsers:

- Chrome/Edge 37+
- Firefox 34+
- Safari 11+

## Node.js Compatibility

WebCrypto is available in Node.js 15.0.0+ via the global `crypto.subtle` object. For older Node.js versions, continue using the standard crypto-based algorithms.

## Migration from Node.js Crypto

To migrate from Node.js crypto to WebCrypto:

1. Change algorithm imports:

   ```javascript
   // Before
   import { Sha256, RsaSha256 } from "xml-crypto";

   // After
   import { WebCryptoSha256, WebCryptoRsaSha256 } from "xml-crypto";
   ```

2. Update to use callbacks:

   ```javascript
   // Before (synchronous)
   sig.computeSignature(xml);
   const result = sig.getSignedXml();

   // After (with callback)
   sig.computeSignature(xml, (err, signedXmlObj) => {
     if (err) {
       console.error(err);
       return;
     }
     const result = signedXmlObj.getSignedXml();
   });
   ```

3. Register algorithms:
   ```javascript
   sig.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
   sig.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
     WebCryptoRsaSha256;
   ```

## X.509 Certificate Support

The Web Crypto API doesn't directly support X.509 certificates. To use certificates with WebCrypto, you have two options:

### Option 1: Use a Pluggable Certificate Parser (Recommended)

You can configure a certificate parser that extracts the public key from X.509 certificates. This keeps the core library lightweight while allowing you to bring your own ASN.1 parser.

```javascript
import { setCertificateParser } from "xml-crypto";
import * as x509 from "@peculiar/x509";

// Configure the certificate parser once at startup
setCertificateParser({
  extractPublicKey(certPem) {
    const cert = new x509.X509Certificate(certPem);
    return cert.publicKey.rawData;
  },
});

// Now you can use X.509 certificates directly with WebCrypto
const sig = new SignedXml();
sig.publicCert = certificatePem; // Works with certificates!
```

Popular libraries for parsing X.509 certificates:

- **[@peculiar/x509](https://www.npmjs.com/package/@peculiar/x509)** - Pure JavaScript/TypeScript, works in browsers and Node.js
- **[pkijs](https://www.npmjs.com/package/pkijs)** - Full-featured PKI library
- **[asn1js](https://www.npmjs.com/package/asn1js)** - Low-level ASN.1 parsing

#### Example with pkijs

```javascript
import { setCertificateParser } from "xml-crypto";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";

setCertificateParser({
  extractPublicKey(certPem) {
    // Remove PEM headers and decode base64
    const pemContent = certPem
      .replace(/-----BEGIN CERTIFICATE-----/, "")
      .replace(/-----END CERTIFICATE-----/, "")
      .replace(/\s/g, "");
    const der = Uint8Array.from(atob(pemContent), (c) => c.charCodeAt(0));

    // Parse the certificate
    const asn1 = asn1js.fromBER(der.buffer);
    const cert = new pkijs.Certificate({ schema: asn1.result });

    // Return the SubjectPublicKeyInfo as ArrayBuffer
    return cert.subjectPublicKeyInfo.toSchema().toBER(false);
  },
});
```

### Option 2: Extract the Public Key Manually

If you prefer not to add a runtime dependency, you can extract the public key at build time or on the server:

```javascript
// In Node.js, extract the public key like this:
import { createPublicKey } from "crypto";

const publicKey = createPublicKey(certificatePem);
const spkiPublicKey = publicKey.export({
  type: "spki",
  format: "pem",
});

// Use spkiPublicKey with WebCrypto algorithms
sig.publicCert = spkiPublicKey;
```

## Limitations

1. **X.509 Certificates**: Require a certificate parser (see above) or manual public key extraction.
2. **PEM/DER parsing**: The utility functions provide basic PEM parsing.
3. **Key formats**: Only PKCS8 private keys and SPKI public keys are currently supported for RSA.
4. **Callback requirement**: All WebCrypto operations require callbacks - you cannot use them with the synchronous API (without a callback).

## Benefits

- **Zero dependencies on Node.js crypto**: Run in any environment that supports Web Crypto API
- **Browser support**: Enable XML signing/verification in web applications
- **Standard API**: Uses the widely-supported Web Crypto API standard
- **Future-proof**: Web Crypto is the modern standard for cryptography on the web

## Example: Complete Sign and Verify Flow

```javascript
import { SignedXml, WebCryptoRsaSha256, WebCryptoSha256 } from "xml-crypto";
import { DOMParser } from "@xmldom/xmldom";

function signAndVerify(callback) {
  const xml = "<root><data>Important data</data></root>";

  // Signing
  const sigForSigning = new SignedXml();
  sigForSigning.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  sigForSigning.privateKey = privateKeyPem;
  sigForSigning.addReference({
    xpath: "//*[local-name(.)='data']",
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
  });

  // Register algorithms
  sigForSigning.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
  sigForSigning.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
    WebCryptoRsaSha256;

  sigForSigning.computeSignature(xml, (err, signedXmlObj) => {
    if (err) {
      return callback(err);
    }

    const signedXml = signedXmlObj.getSignedXml();

    // Verification
    const sigForVerifying = new SignedXml();
    sigForVerifying.publicCert = publicKeyPem; // SPKI format

    // Register algorithms for verification
    sigForVerifying.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
    sigForVerifying.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
      WebCryptoRsaSha256;

    // Load the signature
    const doc = new DOMParser().parseFromString(signedXml);
    const signature = sigForVerifying.findSignatures(doc)[0];
    sigForVerifying.loadSignature(signature);

    sigForVerifying.checkSignature(signedXml, (err, isValid) => {
      if (err) {
        return callback(err);
      }
      console.log("Signature is valid:", isValid);
      callback(null, isValid);
    });
  });
}

signAndVerify((err, isValid) => {
  if (err) {
    console.error("Error:", err);
  } else {
    console.log("Success! Valid:", isValid);
  }
});
```

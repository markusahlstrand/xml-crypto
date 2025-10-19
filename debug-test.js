const { SignedXml, WebCryptoSha256, WebCryptoRsaSha256 } = require('./lib/index.js');
const fs = require('fs');
const xmldom = require('@xmldom/xmldom');

const xml = '<root><data>test content</data></root>';
const privateKey = fs.readFileSync('./test/static/client.pem', 'utf8');
const publicKey = fs.readFileSync('./test/static/client_public.pem', 'utf8');

const sig = new SignedXml();
sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
sig.privateKey = privateKey;

sig.addReference({
  xpath: '//*[local-name(.)="data"]',
  digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
  transforms: ['http://www.w3.org/2001/10/xml-exc-c14n#'],
});

sig.HashAlgorithms['http://www.w3.org/2001/04/xmlenc#sha256'] = WebCryptoSha256;
sig.SignatureAlgorithms['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'] = WebCryptoRsaSha256;

console.log('Computing signature...');
sig.computeSignature(xml, (err) => {
  if (err) {
    console.error('Sign error:', err);
    return;
  }
  
  const signedXml = sig.getSignedXml();
  console.log('Signed XML:');
  console.log(signedXml);
  console.log('---');
  console.log('Signed XML created, length:', signedXml.length);
  
  const verifier = new SignedXml();
  const crypto = require('crypto');
  const publicKeyObj = crypto.createPublicKey(publicKey);
  const spkiPem = publicKeyObj.export({ type: 'spki', format: 'pem' });
  
  verifier.publicCert = spkiPem;
  verifier.HashAlgorithms['http://www.w3.org/2001/04/xmlenc#sha256'] = WebCryptoSha256;
  verifier.SignatureAlgorithms['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'] = WebCryptoRsaSha256;
  
  const doc = new xmldom.DOMParser().parseFromString(signedXml);
  const signature = verifier.findSignatures(doc)[0];
  verifier.loadSignature(signature);
  
  console.log('About to check signature...');
  verifier.checkSignature(signedXml, (error, isValid) => {
    console.log('===== Callback called! =====');
    console.log('Error:', error?.message || error);
    console.log('IsValid:', isValid);
    process.exit(error ? 1 : 0);
  });
  
  console.log('checkSignature called (async)...');
});

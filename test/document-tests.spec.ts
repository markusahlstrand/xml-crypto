import { SignedXml } from "../src/index";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as fs from "fs";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";

describe("Document tests", function () {
  it("test with a document (using FileKeyInfo)", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const node = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );

    isDomNode.assertIsNodeLike(node);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(node);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("test with a document (using StringKeyInfo)", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const node = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );

    isDomNode.assertIsNodeLike(node);
    const sig = new SignedXml();
    const feidePublicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.publicCert = feidePublicCert;
    sig.loadSignature(node);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("test checkSignature auto-loads signature when not explicitly loaded", function () {
    const xml = fs.readFileSync("./test/static/invalid_signature - changed content.xml", "utf-8");
    const sig = new SignedXml();
    // Not calling loadSignature() - should auto-load
    // This should load the signature automatically even though validation will fail
    const result = sig.checkSignature(xml);

    expect(result).to.be.false;
    // The signature was loaded and processed, even though it's invalid
    expect(sig.getSignedReferences().length).to.equal(0);
  });

  it("test checkSignature throws error when no signature found", function () {
    const xml = "<root><data>test</data></root>";
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");

    expect(() => sig.checkSignature(xml)).to.throw("No signature found in the document");
  });

  it("test checkSignature with callback handles no signature error", function (done) {
    const xml = "<root><data>test</data></root>";
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");

    sig.checkSignature(xml, (error, isValid) => {
      expect(error).to.exist;
      expect(error?.message).to.equal("No signature found in the document");
      expect(isValid).to.be.false;
      done();
    });
  });

  it("should not reuse stale signature from previous checkSignature call", function () {
    const validXml = fs.readFileSync("./test/static/valid_signature.xml", "utf-8");
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // First call with a valid signed document - should pass
    const firstResult = sig.checkSignature(validXml);
    expect(firstResult).to.be.true;

    // Second call with an unsigned document (no signature element at all)
    // Should throw an error about no signature found, not return true with the stale signature
    const unsignedXml = "<root><data>test content</data></root>";

    // This should throw an error about no signature found, not return true
    expect(() => sig.checkSignature(unsignedXml)).to.throw("No signature found in the document");
  });

  it("should not reuse stale signature from previous checkSignatureAsync call", async function () {
    const validXml = fs.readFileSync("./test/static/valid_signature.xml", "utf-8");
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // First call with a valid signed document - should pass
    const firstResult = await sig.checkSignatureAsync(validXml);
    expect(firstResult).to.be.true;

    // Second call with an unsigned document (no signature element at all)
    // Should throw an error about no signature found, not return true with the stale signature
    const unsignedXml = "<root><data>test content</data></root>";

    // This should throw an error about no signature found, not return true
    try {
      await sig.checkSignatureAsync(unsignedXml);
      expect.fail("Should have thrown an error");
    } catch (error) {
      expect(error).to.exist;
      expect((error as Error).message).to.equal("No signature found in the document");
    }
  });
});

describe("Validated node references tests", function () {
  it("should return references if the document is validly signed", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const sig = new SignedXml();
    sig.getCertFromKeyInfo = SignedXml.getCertFromKeyInfo;
    sig.loadSignature(sig.findSignatures(doc)[0]);
    const validSignature = sig.checkSignature(xml);
    expect(validSignature).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);

    /* eslint-disable-next-line deprecation/deprecation */
    const ref = sig.getReferences()[0];
    const result = ref.getValidatedNode();
    expect(result?.toString()).to.equal(doc.toString());
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("should not return references if the document is not validly signed", function () {
    const xml = fs.readFileSync("./test/static/invalid_signature - changed content.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const sig = new SignedXml();
    sig.loadSignature(sig.findSignatures(doc)[0]);
    const validSignature = sig.checkSignature(xml);
    expect(validSignature).to.be.false;
    expect(sig.getSignedReferences().length).to.equal(0);

    /* eslint-disable-next-line deprecation/deprecation */
    const ref = sig.getReferences()[1];
    const result = ref.getValidatedNode();
    expect(result).to.be.null;
    expect(sig.getSignedReferences().length).to.equal(0);
  });

  it("should return `null` if the selected node isn't found", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const sig = new SignedXml();
    sig.getCertFromKeyInfo = SignedXml.getCertFromKeyInfo;
    sig.loadSignature(sig.findSignatures(doc)[0]);
    const validSignature = sig.checkSignature(xml);
    expect(validSignature).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);

    /* eslint-disable-next-line deprecation/deprecation */
    const ref = sig.getReferences()[0];
    const result = ref.getValidatedNode("/non-existent-node");
    expect(result).to.be.null;
  });

  it("should return the selected node if it is validly signed", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const sig = new SignedXml();
    sig.getCertFromKeyInfo = SignedXml.getCertFromKeyInfo;
    sig.loadSignature(sig.findSignatures(doc)[0]);
    const validSignature = sig.checkSignature(xml);
    expect(validSignature).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);

    /* eslint-disable-next-line deprecation/deprecation */
    const ref = sig.getReferences()[0];
    const result = ref.getValidatedNode(
      "//*[local-name()='Attribute' and @Name='mail']/*[local-name()='AttributeValue']/text()",
    );
    expect(result?.nodeValue).to.equal("henri.bergius@nemein.com");
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("should return `null` if the selected node isn't validly signed", function () {
    const xml = fs.readFileSync("./test/static/invalid_signature - changed content.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const sig = new SignedXml();
    sig.loadSignature(sig.findSignatures(doc)[0]);
    const validSignature = sig.checkSignature(xml);
    expect(validSignature).to.be.false;
    expect(sig.getSignedReferences().length).to.equal(0);

    /* eslint-disable-next-line deprecation/deprecation */
    const ref = sig.getReferences()[0];
    const result = ref.getValidatedNode(
      "//*[local-name()='Attribute' and @Name='mail']/*[local-name()='AttributeValue']/text()",
    );
    expect(result).to.be.null;
    // Not all references verified, so no references should be in `.getSignedReferences()`.
    expect(sig.getSignedReferences().length).to.equal(0);
  });
});

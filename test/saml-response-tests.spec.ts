import { SignedXml } from "../src/index";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as fs from "fs";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";

describe("SAML response tests", function () {
  it("test validating SAML response", async function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(signature);
    const result = await sig.checkSignature(xml);

    expect(result).to.be.true;
  });

  it("test validating wrapped assertion signature", async function () {
    const xml = fs.readFileSync("./test/static/valid_saml_signature_wrapping.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const assertion = xpath.select1("//*[local-name(.)='Assertion']", doc);
    isDomNode.assertIsNodeLike(assertion);
    const signature = xpath.select1(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      assertion,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(signature);
    try {
      sig.checkSignature(xml);
    } catch (err) {
      // TODO: fix check
      // expect(err.message).to.be(
      //   "Should not validate a document which contains multiple elements with the " +
      //     "same value for the ID / Id / Id attributes, in order to prevent " +
      //     "signature wrapping attack.",
      // );
    }
  });

  it("test validating SAML response where a namespace is defined outside the signed element", async function () {
    const xml = fs.readFileSync("./test/static/saml_external_ns.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/saml_external_ns.pem");
    sig.loadSignature(signature);
    const result = await sig.checkSignature(xml);
    expect(result).to.be.true;
  });

  it("test reference id does not contain quotes", async function () {
    const xml = fs.readFileSync("./test/static/id_with_quotes.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const assertion = xpath.select1("//*[local-name(.)='Assertion']", doc);
    isDomNode.assertIsNodeLike(assertion);
    const signature = xpath.select1(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      assertion,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(signature);

    try {
      await sig.checkSignature(xml);
    } catch (err) {
      // TODO: fix check
      // expect(err.message).to.match(/id should not contain quotes/);
    }
  });

  it("test validating SAML response WithComments", async function () {
    const xml = fs.readFileSync("./test/static/valid_saml_withcomments.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(signature);
    // This doesn't matter, just want to make sure that we don't fail due to unknown algorithm
    try {
      await sig.checkSignature(xml);
    } catch (err) {
      // TODO: fix check
      // expect(err.message).to.match(/invalid signature/);
    }
  });
});

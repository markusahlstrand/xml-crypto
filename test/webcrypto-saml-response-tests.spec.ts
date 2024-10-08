import { WebCryptoSignedXml } from "../src/index";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as fs from "fs";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";

describe("Webcrypto SAML response tests", function () {
  it("test validating SAML response", async function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new WebCryptoSignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem", "binary");
    sig.loadSignature(signature);

    return new Promise((resolve, reject) => {
      sig.checkSignature(xml, (error, isValid) => {
        if (error) {
          reject(error);
        } else {
          expect(isValid).to.be.true;
          resolve();
        }
      });
    });
  });

  it("test validating wrapped assertion signature", function (done) {
    const xml = fs.readFileSync("./test/static/valid_saml_signature_wrapping.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const assertion = xpath.select1("//*[local-name(.)='Assertion']", doc);
    isDomNode.assertIsNodeLike(assertion);
    const signature = xpath.select1(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      assertion,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new WebCryptoSignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem", "binary");
    sig.loadSignature(signature);

    sig.checkSignature(xml, (error) => {
      expect(error).to.exist;
      if (error) {
        expect(error.message).to.include(
          "Cannot validate a document which contains multiple elements with the " +
            "same value for the ID / Id / Id attributes, in order to prevent " +
            "signature wrapping attack.",
        );
      }
      done();
    });
  });

  it("test validating SAML response where a namespace is defined outside the signed element", function (done) {
    const xml = fs.readFileSync("./test/static/saml_external_ns.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new WebCryptoSignedXml();
    sig.publicCert = fs.readFileSync("./test/static/saml_external_ns.pem", "binary");
    sig.loadSignature(signature);

    sig.checkSignature(xml, (error, isValid) => {
      expect(error).to.be.null;
      expect(isValid).to.be.true;
      done();
    });
  });

  it("test reference id does not contain quotes", function (done) {
    const xml = fs.readFileSync("./test/static/id_with_quotes.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const assertion = xpath.select1("//*[local-name(.)='Assertion']", doc);
    isDomNode.assertIsNodeLike(assertion);
    const signature = xpath.select1(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      assertion,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new WebCryptoSignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem", "binary");
    sig.loadSignature(signature);

    sig.checkSignature(xml, (error) => {
      expect(error).to.exist;
      if (error) {
        expect(error.message).to.include("id should not contain quotes");
      }
      done();
    });
  });

  it("test validating SAML response WithComments", function (done) {
    const xml = fs.readFileSync("./test/static/valid_saml_withcomments.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new WebCryptoSignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem", "binary");
    sig.loadSignature(signature);

    sig.checkSignature(xml, (error) => {
      expect(error).to.exist;
      if (error) {
        expect(error.message).to.match(/^invalid signature/);
      }
      done();
    });
  });
});

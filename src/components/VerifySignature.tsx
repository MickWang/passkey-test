import { useState, useCallback } from "react";
import { base64url } from "../utils/index";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import {
  isoBase64URL,
  isoUint8Array,
  decodeCredentialPublicKey,
  cose,
  decodeAttestationObject,
  toHash,
  isoCrypto,
} from "@simplewebauthn/server/helpers";

import EC from "elliptic";
import js256 from "js-sha256";
import buffer from "buffer";
import { arrayify, hexZeroPad, splitSignature } from "@ethersproject/bytes";

import {
  AsnParser,
  AsnSerializer,
} from "https://esm.sh/@peculiar/asn1-schema@2.3.8";
import { ECDSASigValue } from "https://esm.sh/@peculiar/asn1-ecc@2.3.8";
function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
  return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
}
export function unwrapEC2Signature(signature: Uint8Array): Uint8Array {
  const parsedSignature = AsnParser.parse(signature, ECDSASigValue);
  let rBytes = new Uint8Array(parsedSignature.r);
  let sBytes = new Uint8Array(parsedSignature.s);

  if (shouldRemoveLeadingZero(rBytes)) {
    rBytes = rBytes.slice(1);
  }

  if (shouldRemoveLeadingZero(sBytes)) {
    sBytes = sBytes.slice(1);
  }

  const finalSignature = isoUint8Array.concat([rBytes, sBytes]);

  return finalSignature;
}

function buf2hex(buffer) {
  // buffer is an ArrayBuffer
  return [...new Uint8Array(buffer)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

export default function VerifySignature() {
  const [message, setMessage] = useState("hello world");
  const [signature, setSignature] = useState(
    "MEQCICPC3f4BX7mA9GjlqawoFhLYqK7A32-K6jUs5_YOShYIAiAx6Kx4kEgsxTygkmd16YP6EWymY-CSM_pxLYE7LjW1Cw"
  );
  const [publicKey, setPublicKey] = useState(
    "pQECAyYgASFYIFSjlS7nBuweEJhk9pW4DHkmic-SKpo3Wrfx-w6dTiG3IlggdASXG6ygj7DJUTlt6_ccg1OfLb8JubSN-6a6kXshyO4"
  );
  const [verified, setVerified] = useState<boolean>();
  const handleVerify = useCallback(async () => {
    const credential = JSON.parse(
      localStorage.getItem("credential_verify") ?? ""
    );
    const decodedPublicKey = decodeCredentialPublicKey(
      isoBase64URL.toBuffer(publicKey)
    );
    const alg = decodedPublicKey.get(cose.COSEKEYS.alg);
    const x = decodedPublicKey.get(cose.COSEKEYS.x);
    const y = decodedPublicKey.get(cose.COSEKEYS.y);
    const WebCrypto = window.crypto;
    const _crv = "P-256";
    const keyData: JsonWebKey = {
      kty: "EC",
      crv: _crv,
      x: isoBase64URL.fromBuffer(x),
      y: isoBase64URL.fromBuffer(y),
      ext: false,
    };
    const keyAlgorithm: EcKeyImportParams = {
      /**
       * Note to future self: you can't use `mapCoseAlgToWebCryptoKeyAlgName()` here because some
       * leaf certs from actual devices specified an RSA SHA value for `alg` (e.g. `-257`) which
       * would then map here to `'RSASSA-PKCS1-v1_5'`. We always want `'ECDSA'` here so we'll
       * hard-code this.
       */
      name: "ECDSA",
      namedCurve: _crv,
    };
    const webPk = await WebCrypto.subtle.importKey(
      "jwk",
      keyData,
      keyAlgorithm,
      false,
      ["verify"]
    );

    console.log("alg: ", decodedPublicKey.get(cose.COSEKEYS.alg));
    console.log("crv: ", decodedPublicKey.get(cose.COSEKEYS.crv));
    console.log("kty: ", decodedPublicKey.get(cose.COSEKEYS.kty));
    console.log("e: ", decodedPublicKey.get(cose.COSEKEYS.e));
    console.log("n: ", decodedPublicKey.get(cose.COSEKEYS.n));
    console.log("x: ", decodedPublicKey.get(cose.COSEKEYS.x));
    console.log("y: ", decodedPublicKey.get(cose.COSEKEYS.y));

    const ec = new EC.ec("p256");
    // Import public key
    const key = ec.keyFromPublic(
      {
        x: decodedPublicKey.get(cose.COSEKEYS.x),
        y: decodedPublicKey.get(cose.COSEKEYS.y),
      },
      "hex"
    );

    console.log("key: ", key);
    // const xBuffer = key.getPublic().getX().toArray();
    // const yBuffer = key.getPublic().getY().toArray();
    // const pk = new Uint8Array([...xBuffer, ...yBuffer]);

    const assertionResponse = credential.response;
    const authDataBuffer = isoBase64URL.toBuffer(
      assertionResponse.authenticatorData
    );

    const clientDataHash = await toHash(
      isoBase64URL.toBuffer(assertionResponse.clientDataJSON)
    );
    const signatureBase = isoUint8Array.concat([
      authDataBuffer,
      clientDataHash,
    ]);
    const signature = isoBase64URL.toBuffer(assertionResponse.signature);
    console.log("Signature: ", signature, unwrapEC2Signature(signature));
    console.log("verify 1: ", signature, signatureBase, key.getPublic());
    const unwrapedSignature = unwrapEC2Signature(signature);
    const verifyRes = key.verify(await toHash(signatureBase), signature);
    console.log("verifyRes: ", verifyRes);

    const verifyAlgorithm: EcdsaParams = {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    };
    const webRes = await WebCrypto.subtle.verify(
      verifyAlgorithm,
      webPk,
      unwrapEC2Signature(signature),
      signatureBase
    );
    console.log("webRes:  ", webRes);

    if (!localStorage.getItem("credential_verify")) {
      return;
    }

    // Decode ArrayBuffers and construct an authenticator object.
    const authenticator = {
      credentialPublicKey: isoBase64URL.toBuffer(publicKey), //TODO: get publicKey from contract with address
      credentialID: isoBase64URL.toBuffer(credential.id),
      // transports: cred.transports,
    };
    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: base64url.encode(
        isoUint8Array.fromUTF8String(message)
      ),
      expectedOrigin: "http://localhost:5173", // use actual origin
      expectedRPID: "localhost",
      authenticator,
      requireUserVerification: false,
    });

    const { verified, authenticationInfo } = verification;
    console.log(
      " verified, authenticationInfo : ",
      verified,
      authenticationInfo
    );
    setVerified(verified);
    if (!verified) {
      throw new Error("User verification failed.");
    }
  }, [message, publicKey]);
  return (
    <div className="card">
      <h1>Verify Signature</h1>
      <div>
        <div>
          <label htmlFor="message">Message:</label>
          <input
            type="text"
            id="message"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
          />
        </div>
        <div>
          <label htmlFor="signature">Signature:</label>
          <input
            type="text"
            id="signature"
            value={signature}
            onChange={(e) => setSignature(e.target.value)}
          />
        </div>
        <div>
          <label htmlFor="publicKey">PublicKey:</label>
          <input
            type="text"
            id="publicKey"
            value={publicKey}
            onChange={(e) => setPublicKey(e.target.value)}
          />
        </div>

        <button onClick={handleVerify}>Verify with passkey</button>
      </div>
      <code>
        Verify result: {verified ? "true" : "false"}
        <br />
      </code>
    </div>
  );
}

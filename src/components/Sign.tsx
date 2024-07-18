import { useState, useCallback } from "react";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { decodeClientDataJSON } from "@simplewebauthn/server/helpers";
import { base64url } from "../utils/index";
import {
  isoBase64URL,
  isoUint8Array,
  parseAuthenticatorData,
} from "@simplewebauthn/server/helpers";
import { unwrapEC2Signature } from "./VerifySignature";
import { ethers, keccak256, AbiCoder, hexlify, toUtf8Bytes } from "ethers";
import { Base64 } from "js-base64";
const n = "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const msg = "0000000000000000000000000000000000000000000000000000000000000000";

const P256_N_DIV_2 = BigInt(n) / 2n;
const checkSigS = (s: string) => {
  if (BigInt(s) > P256_N_DIV_2) {
    return "0x" + (BigInt(n) - BigInt(s)).toString(16);
  } else {
    return s;
  }
};
export default function Sign() {
  const [message, setMessage] = useState(msg);

  const [signature, setSignature] = useState("");

  const handleSign = useCallback(async () => {
    // To abort a WebAuthn call, instantiate an `AbortController`.
    // const abortController = new AbortController();
    const array = new Uint8Array(32);

    // 使用crypto.getRandomValues填充数组
    const messgage = window.crypto.getRandomValues(array);
    const msg1 = isoUint8Array.toHex(messgage);
    // const msg = '0000000000000000000000000000000000000000000000000000000000000000'
    console.log("msg: ", msg1);
    const options = await generateAuthenticationOptions({
      rpID: "localhost",
      allowCredentials: [],
      challenge: message,
    });
    // console.log("msg from option: ", options.challenge);
    // 对hex string进行base64url编码和转成ArrayBuffer再进行base64url解码得到的结果不一样。
    const msgBase64 = Base64.fromUint8Array(isoUint8Array.fromHex(msg)); // url safe
    const key = "WebAuthnUser";

    const keyIdHash = keccak256(hexlify(toUtf8Bytes(key)));
    console.log("key abiEncode: ", hexlify(toUtf8Bytes(key)));
    console.log("keyIdHash: ", keyIdHash);
    const keyIdHashBase64 = Base64.encode(keyIdHash);
    const publicKeyCredentialRequestOptions = {
      // Server generated challenge
      challenge: base64url.decode(keyIdHashBase64), // tx hash
      // `allowCredentials` empty array invokes an account selector by discoverable credentials.
      allowCredentials: [],
    };

    console.log(
      "base64: ",
      Base64.encode(msg),
      Base64.encode(options.challenge),
      Base64.fromUint8Array(isoUint8Array.fromHex(msg))
    );
    const cred = await navigator.credentials.get({
      publicKey: publicKeyCredentialRequestOptions,
      // signal: abortController.signal,
      // // Specify 'conditional' to activate conditional UI
      // mediation: "conditional",
    });
    console.log("credential: ", cred);
    if (!cred) return;
    // TODO: send to backend to verify passkey
    const credential = {} as any;
    credential.id = cred.id;
    credential.type = cred.type;
    // Base64URL encode `rawId`
    credential.rawId = base64url.encode(cred.rawId);

    // Base64URL encode some values
    const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
    const authenticatorData = base64url.encode(cred.response.authenticatorData);

    const parsedAuthData = parseAuthenticatorData(
      isoBase64URL.toBuffer(authenticatorData)
    );
    const clientDataJSONHex = isoUint8Array.toHex(
      isoBase64URL.toBuffer(clientDataJSON)
    );
    console.log("clientDataJSONHex: ", clientDataJSONHex);

    console.log("parsedAuthData: ", parsedAuthData);
    const str = isoBase64URL.fromBuffer(cred.response.authenticatorData);
    const signature = base64url.encode(cred.response.signature);
    const userHandle = base64url.encode(cred.response.userHandle);
    console.log("clientDataJSON: ", decodeClientDataJSON(clientDataJSON));
    console.log("signature: ", signature);
    console.log("userHandle: ", atob(userHandle));
    console.log("credential id: ", cred.id);

    const challengeBase64Length =
      decodeClientDataJSON(clientDataJSON).challenge.length;
    const challengeBase64Index = atob(clientDataJSON).indexOf("challenge");
    const challengeLength = "challenge".length;
    const pre = atob(clientDataJSON).substring(
      0,
      challengeBase64Index + challengeLength + 3
    );
    const post = atob(clientDataJSON).substring(
      challengeBase64Index + challengeLength + 3 + challengeBase64Length
    );

    //divide clientDataJson
    console.log("clientDataJson base64: ", clientDataJSON);
    let challengeBase64 = Base64.encode(msgBase64);
    console.log("challengeBase64: ", challengeBase64);
    if (challengeBase64.includes("=")) {
      challengeBase64 = challengeBase64.replace(/=/g, "");
    }
    let challengeIndex = clientDataJSON.indexOf(
      challengeBase64.substring(0, challengeBase64.length - 1) // the last char is different
    );
    console.log("challengeIndex: ", challengeIndex);
    if (challengeIndex === -1) {
      console.log("challenge not found in clientDataJSON");
      // return;
    }
    const clientDataJsonPre = clientDataJSON.slice(0, challengeIndex);
    const clientDataJsonPost = clientDataJSON.slice(
      challengeIndex + challengeBase64.length
    );
    console.log("clientDataJsonPre: ", clientDataJsonPre);
    console.log("clientDataJsonPost: ", clientDataJsonPost);
    const _clientDataJson =
      clientDataJsonPre + challengeBase64 + clientDataJsonPost;
    console.log(
      "clientDataJson: ",
      _clientDataJson,
      _clientDataJson === clientDataJSON
    );

    const opHash = isoUint8Array.toHex(isoBase64URL.toBuffer(challengeBase64));
    console.log("opHash: ", opHash);
    const unwrapedSignature = unwrapEC2Signature(
      isoBase64URL.toBuffer(signature)
    );
    const sigX = unwrapedSignature.slice(0, 32);
    const sigY = unwrapedSignature.slice(32);
    console.log("sigX: ", sigX, sigY);
    const keyHash =
      "0x0000000000000000000000000000000000000000000000000000000000000000";
    const authenticatorHex =
      "0x" + isoUint8Array.toHex(isoBase64URL.toBuffer(authenticatorData));
    console.log("authenticatorHex: ", authenticatorHex);
    console.log("sigx: ", "0x" + isoUint8Array.toHex(sigX));
    console.log("sigy: ", "0x" + isoUint8Array.toHex(sigY));

    const abiEncoder = new AbiCoder();
    const moduleSignature = abiEncoder.encode(
      ["bytes32", "uint256", "uint256", "bytes", "string", "string"],
      [
        keyHash,
        "0x" + isoUint8Array.toHex(sigX),
        "0x" + isoUint8Array.toHex(sigY),
        authenticatorHex,
        clientDataJsonPre,
        clientDataJsonPost,
      ]
    );
    console.log("moduleSignature: ", moduleSignature);
    credential.response = {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
    };

    localStorage.setItem("credential_verify", JSON.stringify(credential));

    const s = "0x" + isoUint8Array.toHex(sigY);
    const _s = checkSigS(s);

    const encoded = abiEncoder.encode(
      [
        "bytes32",
        "uint256",
        "uint256",
        "bytes",
        "bool",
        "string",
        "string",
        "uint256",
      ],
      [
        keyIdHash,
        "0x" + isoUint8Array.toHex(sigX),
        "0x" + _s,
        authenticatorHex,
        true,
        pre,
        post,
        1,
      ]
    );
    console.log("encoded: ", encoded);
    setSignature(signature);
  }, [message]);

  return (
    <div className="card">
      <h1>Sign</h1>
      <div>
        <div>
          <label htmlFor="username">Username:</label>
          <input
            type="text"
            id="username"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
          />
        </div>
        <button onClick={handleSign}>Sign with passkey</button>
      </div>
      <code>
        Signature: {signature}
        <br />
      </code>
    </div>
  );
}

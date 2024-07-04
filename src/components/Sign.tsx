import { useState, useCallback } from "react";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { decodeClientDataJSON } from "@simplewebauthn/server/helpers";
import { base64url } from "../utils/index";
import { isoBase64URL, isoUint8Array } from "@simplewebauthn/server/helpers";

export default function Sign() {
  const [message, setMessage] = useState("hello world");

  const [signature, setSignature] = useState("");

  const handleSign = useCallback(async () => {
    // To abort a WebAuthn call, instantiate an `AbortController`.
    // const abortController = new AbortController();
    const options = await generateAuthenticationOptions({
      rpID: "localhost",
      allowCredentials: [],
      challenge: message,
    });
    const publicKeyCredentialRequestOptions = {
      // Server generated challenge
      challenge: base64url.decode(options.challenge), // tx hash
      // `allowCredentials` empty array invokes an account selector by discoverable credentials.
      allowCredentials: [],
    };

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
    const str = isoBase64URL.fromBuffer(cred.response.authenticatorData);
    const signature = base64url.encode(cred.response.signature);
    const userHandle = base64url.encode(cred.response.userHandle);
    console.log("clientDataJSON: ", decodeClientDataJSON(clientDataJSON));
    console.log("signature: ", signature);
    console.log("userHandle: ", atob(userHandle));
    console.log("credential id: ", cred.id);

    credential.response = {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
    };

    localStorage.setItem("credential_verify", JSON.stringify(credential));

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

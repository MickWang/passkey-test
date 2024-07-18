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
} from "@simplewebauthn/server/helpers";
import { decodeClientDataJSON, cose } from "@simplewebauthn/server/helpers";
import { useState, useEffect, useCallback } from "react";
import { base64url } from "../utils";
import EC from "elliptic";
import {
  BrowserProvider,
  Provider,
  Wallet,
  types,
  Signer,
} from "zksync-ethers";
export default function GeneratePasskey() {
  const [webAuthnSupported, setWebAuthnSupported] = useState(false);
  const [credentialInfo, setCredientialInfo] = useState<{
    credentialId: string;
    publicKey: string;
  }>({});
  const [username, setUserName] = useState("");

  useEffect(() => {
    // const UserAddress = "0x1B94fb7625e13408393B5Ac17D0265E0d61349f2";
    // console.log(
    //   "same: ",
    //   hexStringToUint8Array(UserAddress) ===
    //     isoUint8Array.fromUTF8String(UserAddress)
    // );
    // Availability of `window.PublicKeyCredential` means WebAuthn is usable.
    // `isUserVerifyingPlatformAuthenticatorAvailable` means the feature detection is usable.
    // `​​isConditionalMediationAvailable` means the feature detection is usable.
    if (
      window.PublicKeyCredential &&
      PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
      PublicKeyCredential.isConditionalMediationAvailable
    ) {
      // Check if user verifying platform authenticator is available.
      Promise.all([
        PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
        PublicKeyCredential.isConditionalMediationAvailable(),
      ]).then((results) => {
        if (results.every((r) => r === true)) {
          // Display "Create a new passkey" button
          setWebAuthnSupported(true);
        }
      });
    }
  }, []);

  const handleCreate = useCallback(async () => {
    // // @ts-ignore
    // const browserProvider = new BrowserProvider(window.ethereum);
    // const signer = Signer.from(
    //   await browserProvider.getSigner(),
    //   Number((await browserProvider.getNetwork()).chainId),
    //   Provider.getDefaultProvider(types.Network.Sepolia)
    // );

    // signer.sendTransaction({
    //   to: Wallet.createRandom().address,
    //   value: 10_000_000n,
    // });
    // return;
    if (!username) {
      alert("Please enter username");
      return;
    }
    const user = {
      id: isoUint8Array.fromUTF8String(username), // user EOA
      name: username, // for display only. ENS name or address. or from input
      displayName: username,
    };
    const attestationType = "none";
    const options = await generateRegistrationOptions({
      rpName: "Example",
      rpID: "localhost",
      userID: user.id,
      userName: user.name,
      userDisplayName: user.displayName || user.name,
      // Prompt users for additional information about the authenticator.
      attestationType,
      // Prevent users from re-registering existing authenticators
      excludeCredentials: [],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        requireResidentKey: true,
      },
      supportedAlgorithmIDs: [-7, -257],
    });
    const originChallenge = options.challenge;
    const publicKeyCredentialCreationOptions = {
      ...options,
    };
    // Base64URL decode some values
    publicKeyCredentialCreationOptions.user.id = base64url.decode(
      options.user.id
    );
    publicKeyCredentialCreationOptions.challenge = base64url.decode(
      options.challenge
    );
    // const publicKeyCredentialCreationOptions = {
    //   challenge: challenge, // from backend server
    //   rp: {
    //     name: "Example",
    //     id: "localhost", // https
    //   },
    //   user: {
    //     id: hexStringToUint8Array(UserAddress), // user EOA
    //     name: UserAddress, // for display only. ENS name or address. or from input
    //     displayName: UserAddress,
    //   },
    //   pubKeyCredParams: [
    //     { alg: -7, type: "public-key" },
    //     { alg: -257, type: "public-key" },
    //   ],
    //   excludeCredentials: [],
    //   // excludeCredentials: [{ // get from backend to avoid register twice for same device.
    //   //   id:
    //   //   type: 'public-key',
    //   //   transports: ['internal'],
    //   // }],
    //   authenticatorSelection: {
    //     authenticatorAttachment: "platform",
    //     requireResidentKey: true,
    //   },
    // };

    // bind: credential?.id, publicKey, address
    //  send tx: passkey sign tx;
    //  verify: publicKey verify
    //  tx send to chain to execute

    const credential = await navigator.credentials.create({
      publicKey: publicKeyCredentialCreationOptions,
    });
    console.log("credential: ", credential);
    console.log("crential id: ", credential?.id);
    const pkBuffer = credential.response.getPublicKey();
    console.log("pkBUffer: ", base64url.encode(pkBuffer));

    if (!credential) return;

    // 对 ArrayBuffer 属性进行 Base64 URL 编码
    const encodedCredential = {
      id: credential.id,
      rawId: base64url.encode(credential.rawId),
      response: {
        clientDataJSON: base64url.encode(credential.response.clientDataJSON),
        attestationObject: base64url.encode(
          credential.response.attestationObject
        ),
      },
      authenticatorAttachment: credential.authenticatorAttachment,
      type: credential.type,
    };

    console.log("Encoded Credential:", encodedCredential);
    // TODO: send to contract or backend to bind address with passwkey

    // Use SimpleWebAuthn's handy function to verify the registration request.

    const verification = await verifyRegistrationResponse({
      response: encodedCredential,
      expectedChallenge: originChallenge,
      expectedOrigin: "http://localhost:5173", // use actual origin
      expectedRPID: "localhost",
      requireUserVerification: false,
    });
    console.log("pk: ", base64url.encode(credential.response.getPublicKey()));
    const { verified, registrationInfo } = verification;
    console.log("verified, registrationInfo: ", verified, registrationInfo);
    if (registrationInfo) {
      setCredientialInfo({
        credentialId: registrationInfo.credentialID,
        publicKey: base64url.encode(registrationInfo.credentialPublicKey),
      });
      const decodedPublicKey = decodeCredentialPublicKey(
        registrationInfo.credentialPublicKey
      );
      const x = decodedPublicKey.get(cose.COSEKEYS.x);
      const y = decodedPublicKey.get(cose.COSEKEYS.y);
      console.log("x y : ", x, y);
      // const pk = new Uint8Array([...x, ...y]);
      const ec = new EC.ec("p256");
      // Import public key
      const key = ec.keyFromPublic(
        {
          x: decodedPublicKey.get(cose.COSEKEYS.x),
          y: decodedPublicKey.get(cose.COSEKEYS.y),
        },
        "hex"
      );
      const xHex = key.getPublic().getX().toString(16);
      const yHex = key.getPublic().getY().toString(16);
      console.log("xHex: ", xHex);
      console.log("yHex: ", yHex);
      const publicKey = `${xHex}${yHex}`;
      console.log("publicKey: ", publicKey);
    }
    //TODO: call contract to save address, credentialID, credentialPublicKey
  }, [username]);

  return (
    <div className="card">
      <h1>Generate Passkey</h1>
      <div>
        {webAuthnSupported ? (
          <>
            <div>
              <label htmlFor="username">Username:</label>
              <input
                type="text"
                id="username"
                value={username}
                onChange={(e) => setUserName(e.target.value)}
              />
            </div>
            <button onClick={handleCreate}>Create a new passkey</button>
          </>
        ) : (
          <p>WebAuthn is not supported on this browser.</p>
        )}
      </div>
      <code>
        CredentialID: {credentialInfo.credentialId}
        <br />
        PublicKey: {credentialInfo.publicKey}
      </code>
    </div>
  );
}

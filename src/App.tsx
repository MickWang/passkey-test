import { useState, useEffect, useCallback } from "react";
import reactLogo from "./assets/react.svg";
import viteLogo from "/vite.svg";
import "./App.css";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { isoBase64URL, isoUint8Array } from "@simplewebauthn/server/helpers";
import GeneratePasskey from "./components/GeneratePasskey";
import Sign from "./components/Sign";
import VerifySignature from "./components/VerifySignature";
function hexStringToUint8Array(hexString: string) {
  // 移除前缀 "0x"（如果有）
  hexString = hexString.replace(/^0x/, "");

  // 确保十六进制字符串长度是偶数
  if (hexString.length % 2 !== 0) {
    throw new Error("Invalid hex string");
  }

  // 创建 Uint8Array
  const byteArray = new Uint8Array(hexString.length / 2);

  // 将每两个字符（一个字节）转换为十进制并存储在 Uint8Array 中
  for (let i = 0; i < hexString.length; i += 2) {
    byteArray[i / 2] = parseInt(hexString.substr(i, 2), 16);
  }

  return byteArray;
}

function arrayBufferToBase64Url(buffer) {
  const byteArray = new Uint8Array(buffer);
  let binaryString = "";
  for (let i = 0; i < byteArray.length; i++) {
    binaryString += String.fromCharCode(byteArray[i]);
  }
  const base64String = btoa(binaryString);
  // 将 base64 转换为 base64url
  return base64String
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function App() {
  return (
    <>
      <div>
        <GeneratePasskey />
        <Sign />
        <VerifySignature />
      </div>
    </>
  );
}

export default App;

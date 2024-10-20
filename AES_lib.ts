import { decodeBase64, encodeBase64 } from "@std/encoding";
const { subtle } = globalThis.crypto;

export async function generateAesKey(length = 256) {
  const key = await subtle.generateKey(
    {
      name: "AES-GCM",
      length,
    },
    true,
    ["encrypt", "decrypt"],
  );

  return key;
}

export async function exportKey(key: CryptoKey) {
  const keyraw = await subtle.exportKey("raw", key);
  const keyraw_base64 = encodeBase64(keyraw);
  return keyraw_base64;
}

export async function importKey(key: string) {
  const keyraw = decodeBase64(key);
  return await subtle.importKey("raw", keyraw, "AES-GCM", true, [
    "encrypt",
    "decrypt",
  ]);
}

export async function aesEncrypt(plaintext: string, key: CryptoKey) {
  const ec = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(16));

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    ec.encode(plaintext),
  );

  return {
    key,
    iv,
    ciphertext,
  };
}

export async function aesDecrypt(
  ciphertext: ArrayBuffer,
  key: CryptoKey,
  iv: ArrayBuffer,
) {
  const dec = new TextDecoder();
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    ciphertext,
  );

  return dec.decode(plaintext);
}

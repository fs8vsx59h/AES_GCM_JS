import { assertEquals } from "jsr:@std/assert";
import {
    aesDecrypt,
    aesEncrypt,
    exportKey,
    generateAesKey,
    importKey,
} from "./AES_lib.ts";

Deno.test("aesEncrypt", async () => {
    const plaintext = "Hello, world!";
    const key = await generateAesKey();
    const keyraw = await exportKey(key);
    const key_back = await importKey(keyraw);
    const { ciphertext: arrayBuffer, iv } = await aesEncrypt(plaintext, key);
    assertEquals(plaintext, await aesDecrypt(arrayBuffer, key_back, iv));
});

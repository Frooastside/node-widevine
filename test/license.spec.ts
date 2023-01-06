import { equal, ok } from "assert";
import { config } from "dotenv";
import { existsSync, readFileSync } from "fs";
import { describe } from "mocha";
import fetch from "node-fetch";
import { Session } from "../dist/index.js";

config();

describe("Bitmovin License Tests", () => {
  it("Should return a list of keys", async () => {
    //read cdm files located in the same directory
    const privateKey = existsSync("./device_private_key")
      ? readFileSync("./device_private_key")
      : Buffer.from(process.env.DEVICE_PRIVATE_KEY_BASE64 ?? "", "base64");
    const identifierBlob = existsSync("./device_client_id_blob")
      ? readFileSync("./device_client_id_blob")
      : Buffer.from(process.env.DEVICE_CLIENT_ID_BLOB_BASE64 ?? "", "base64");

    ok(privateKey.length > 0, "Private key file should be in the security folder or set using the environment variable 'DEVICE_PRIVATE_KEY_BASE64'");
    ok(
      identifierBlob.length > 0,
      "Identifier blob file should be in the security folder or set using the environment variable 'DEVICE_CLIENT_ID_BLOB_BASE64'"
    );

    //pssh found in the mpd manifest
    const pssh = Buffer.from(
      "AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA==",
      "base64"
    );
    //license url server
    const licenseUrl = "https://cwip-shaka-proxy.appspot.com/no_auth";

    const session = new Session({ privateKey, identifierBlob }, pssh);

    const response = await fetch(licenseUrl, {
      method: "POST",
      body: session.createLicenseRequest()
    });

    ok(response.ok);

    if (response.ok) {
      const keys = session.parseLicense(Buffer.from(await response.arrayBuffer()));
      ok(keys.length > 1, "List of keys is empty!");
      equal(keys[1].kid, "ccbf5fb4c2965be7aa130ffb3ba9fd73", "the provided key is not expected to be the 1. key!");
      equal(keys[1].key, "9cc0c92044cb1d69433f5f5839a159df", "1. key is not correct!");
      equal(keys[2].kid, "9bf0e9cf0d7b55aeb4b289a63bab8610", "the provided key is not expected to be the 2. key!");
      equal(keys[2].key, "90f52fd8ca48717b21d0c2fed7a12ae1", "2. key is not correct!");
      equal(keys[3].kid, "eb676abbcb345e96bbcf616630f1a3da", "the provided key is not expected to be the 3. key!");
      equal(keys[3].key, "100b6c20940f779a4589152b57d2dacb", "3. key is not correct!");
      equal(keys[4].kid, "0294b9599d755de2bbf0fdca3fa5eab7", "the provided key is not expected to be the 4. key!");
      equal(keys[4].key, "3bda2f40344c7def614227b9c0f03e26", "4. key is not correct!");
      equal(keys[5].kid, "639da80cf23b55f3b8cab3f64cfa5df6", "the provided key is not expected to be the 5. key!");
      equal(keys[5].key, "229f5f29b643e203004b30c4eaf348f4", "5. key is not correct!");
    }
  });
});

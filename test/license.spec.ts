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
      const successful = session.parseLicense(Buffer.from(await response.arrayBuffer())).length > 0;
      ok(successful, "Received a valid response");
    }
  });
});

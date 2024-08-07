import { ok } from "assert";
import { existsSync, readFileSync } from "fs";
import { describe } from "mocha";
import { LicenseType, SERVICE_CERTIFICATE_CHALLENGE, Session } from "../dist/index.js";
import "dotenv/config";

describe("Generic License Tests", () => {
  it("Should return a list of keys", async () => {
    //read cdm files located in the same directory
    const privateKey = existsSync("./security/device_private_key")
      ? readFileSync("./security/device_private_key")
      : Buffer.from(process.env.DEVICE_PRIVATE_KEY_BASE64 ?? "", "base64");
    const identifierBlob = existsSync("./security/device_client_id_blob")
      ? readFileSync("./security/device_client_id_blob")
      : Buffer.from(process.env.DEVICE_CLIENT_ID_BLOB_BASE64 ?? "", "base64");

    ok(privateKey.length > 0, "Private key file should be in the security folder or set using the environment variable 'DEVICE_PRIVATE_KEY_BASE64'");
    ok(
      identifierBlob.length > 0,
      "Identifier blob file should be in the security folder or set using the environment variable 'DEVICE_CLIENT_ID_BLOB_BASE64'"
    );

    //pssh found in the mpd manifest
    ok(process.env.PSSH);
    const pssh = Buffer.from(process.env.PSSH, "base64");

    //license url server
    ok(process.env.LICENSE_URL);
    const licenseUrl = process.env.LICENSE_URL;

    const session = new Session({ privateKey, identifierBlob }, pssh);

    const serviceCertificateResponse = await fetch(licenseUrl, {
      method: "POST",
      body: Buffer.from(SERVICE_CERTIFICATE_CHALLENGE)
    });

    const serviceCertificate = Buffer.from(await serviceCertificateResponse.arrayBuffer());
    await session.setServiceCertificateFromMessage(serviceCertificate);

    const response = await fetch(licenseUrl, {
      method: "POST",
      body: session.createLicenseRequest(LicenseType.STREAMING)
    });

    ok(response.ok);

    if (response.ok) {
      const successful = session.parseLicense(Buffer.from(await response.arrayBuffer())).length > 0;
      ok(successful, "Received a valid response");
    }
  }).timeout(10000);
}).timeout(10000);

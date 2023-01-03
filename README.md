# node-widevine

### Examples

Example using bitmovin demo

```typescript
import { Session } from "widevine";
import { readFileSync } from "fs";

//read cdm files located in the same directory
const privateKey = readFileSync("./device_private_key");
const identifierBlob = readFileSync("./device_client_id_blob");

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

if (response.ok) {
  const keys = session.parseLicense(Buffer.from(await response.arrayBuffer()));
  console.log(keys);
}
```

### Build

#### Code

Just run `pnpm build` to generate the js, map and type definition files from the Typescript source.

#### Protocol Buffers

If you want to compile the license_protocol.ts file yourself, you need to run `pnpm proto:compile`

Warning: You need to replace the import statement `import _m0 from "protobufjs/minimal";` in the license_protocol.ts file with `import _m0 from "protobufjs/minimal.js";` (add the .js extension) or else it will throw an error.

# node-widevine

- [Disclaimer](#disclaimer)
- [Installation](#installation)
- [Examples](#examples)
- [Build it yourself](#build)

## Disclaimer

1. This project requires a valid Google-provisioned Private Key and Client Identification blob which are not provided by this project.
2. Public test provisions are available and provided by Google to use for testing projects such as this one.
3. License Servers have the ability to block requests from any provision, and are likely already blocking test provisions on production endpoints.
4. This project does not condone piracy or any action against the terms of the DRM systems.
5. All efforts in this project have been the result of Reverse-Engineering, Publicly available research, and Trial & Error.

## Installation

I use pnpm and recommend in doing so too. If you don't want to modify the source code, it is fully compatible with every node package manager.

Install the package via

pnpm:

```bash
pnpm install node-widevine
```

npm:

```bash
npm install node-widevine
```

yarn:

```bash
yarn add node-widevine
```

## Examples

Example using bitmovin demo

```typescript
import { LicenseType, SERVICE_CERTIFICATE_CHALLENGE, Session } from 'widevine'
import { readFileSync } from 'fs'

//read cdm files located in the same directory
const privateKey = readFileSync('./device_private_key')
const identifierBlob = readFileSync('./device_client_id_blob')

//pssh found in the mpd manifest
const pssh = Buffer.from(
    'AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA==',
    'base64'
)
//license url server
const licenseUrl = 'https://cwip-shaka-proxy.appspot.com/no_auth'

const session = new Session({ privateKey, identifierBlob }, pssh)

const serviceCertificateResponse = await fetch(licenseUrl, {
    method: 'POST',
    body: Buffer.from(SERVICE_CERTIFICATE_CHALLENGE)
})

const serviceCertificate = Buffer.from(
    await serviceCertificateResponse.arrayBuffer()
)
await session.setServiceCertificateFromMessage(serviceCertificate)

const response = await fetch(licenseUrl, {
    method: 'POST',
    body: session.createLicenseRequest(LicenseType.STREAMING)
})

if (response.ok) {
    const successful =
        session.parseLicense(Buffer.from(await response.arrayBuffer())).length >
        0
    console.log(`successful? ${successful ? 'yes' : 'no'}`)
}
```

## Build

I use pnpm and if you don't want to change anything in the package.json, you have to install pnpm by using `npm -g install pnpm`

#### Code

Just run `pnpm build` to generate the js, map and type definition files from the Typescript source.

#### Protocol Buffers

If you want to compile the license_protocol.ts file yourself, you need to run `pnpm proto:compile`

Warning: You need to replace the import statement `import _m0 from "protobufjs/minimal";` in the license_protocol.ts file with `import _m0 from "protobufjs/minimal.js";` (add the .js extension) or else it will throw an error.

## License Stuff

This project is licensed under GPLv3-or-later because of `proto/license_protocol.proto` from [@rlaphoenix/pywidevine 1.6.0](https://github.com/rlaphoenix/pywidevine). It's license is in `THIRDPARTY.md`.

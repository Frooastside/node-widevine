# node-widevine

A lightweight NodeJS library for working with **Google Widevine**

- Loading and initializing Widevine device credentials (device_client_id_blob + device_private_key - WVD v1/v2)
- Creating Widevine license acquisition challenges (SignedMessage / LicenseRequest)
- Parsing and decrypting Widevine license responses (License / KeyContainer)
- Handling service certificates and encrypted client identification
- Managing Widevine sessions for streaming or offline license types

---

- [Disclaimer](#disclaimer)
- [Installation](#installation)
- [Usage](#usage)
- [Usage with WVD](#usage-with-wvd-files)
- [Build it yourself](#build)

## Disclaimer

1. This project requires a valid Google-provisioned Private Key and Client Identification blob which are not provided by this project.
2. Public test provisions are available and provided by Google to use for testing projects such as this one.
3. License Servers have the ability to block requests from any provision, and are likely already blocking test provisions on production endpoints.
4. This project does not condone piracy or any action against the terms of the DRM systems.
5. All efforts in this project have been the result of Reverse-Engineering, Publicly available research, and Trial & Error.

## Installation

npm:

```bash
npm install widevine
```

pnpm:

```bash
pnpm install widevine
```

bun:

```bun
bun add widevine
```

yarn:

```bash
yarn add widevine
```

## Usage

```typescript
import { readFileSync } from 'fs'
import { LicenseType, Widevine } from 'widevine'

// Read cdm files
const identifierBlob = readFileSync('./device_client_id_blob')
const privateKey = readFileSync('./device_private_key')

// Initialize Widevine client
const device = Widevine.init(identifierBlob, privateKey)

// Get Device info
console.log(device.info)

// PSSH found in the MPD manifest
const pssh = Buffer.from('AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA==', 'base64')

// Generate Session
const session = device.createSession(pssh, LicenseType.STREAMING)

// License Server URL
const licenseUrl = 'https://cwip-shaka-proxy.appspot.com/no_auth'

// Service Certificate Request
const serviceCertificateResponse = await fetch(licenseUrl, {
    method: 'POST',
    body: session.getServiceCertificateChallenge()
})

const serviceCertificate = Buffer.from(await serviceCertificateResponse.arrayBuffer())

// Set Service Certificate
session.setServiceCertificateFromMessage(serviceCertificate)

// License Request
const response = await fetch(licenseUrl, {
    method: 'POST',
    body: session.generateChallenge()
})

// Check if request was successful
if (response.ok) {
    // Parse license
    const successful = session.parseLicense(Buffer.from(await response.arrayBuffer())).length > 0
    console.log(`successful? ${successful ? 'yes' : 'no'}`)
} else {
    console.error('Request failed!')
    console.log(await response.text())
}
```

## Usage with WVD files

```typescript
import { readFileSync } from 'fs'
import { LicenseType, Widevine } from 'widevine'

// Read WVD file
const wvd = readFileSync('./device.wvd')

// Initialize Widevine client
const device = Widevine.initWVD(wvd)

// Get Device info
console.log(device.info)

// PSSH found in the MPD manifest
const pssh = Buffer.from('AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA==', 'base64')

// Generate Session
const session = device.createSession(pssh, LicenseType.STREAMING)

// License Server URL
const licenseUrl = 'https://cwip-shaka-proxy.appspot.com/no_auth'

// Service Certificate Request
const serviceCertificateResponse = await fetch(licenseUrl, {
    method: 'POST',
    body: session.getServiceCertificateChallenge()
})

const serviceCertificate = Buffer.from(await serviceCertificateResponse.arrayBuffer())

// Set Service Certificate
session.setServiceCertificateFromMessage(serviceCertificate)

// License Request
const response = await fetch(licenseUrl, {
    method: 'POST',
    body: session.generateChallenge()
})

// Check if request was successful
if (response.ok) {
    // Parse license
    const successful = session.parseLicense(Buffer.from(await response.arrayBuffer())).length > 0
    console.log(`successful? ${successful ? 'yes' : 'no'}`)
} else {
    console.error('Request failed!')
    console.log(await response.text())
}
```

## Build

#### Code

Just run `bun run build` to generate the js, map and type definition files from the Typescript source.

#### Protocol Buffers

If you want to compile the license_protocol_pb.ts file yourself, you need to run `bun run proto:compile`

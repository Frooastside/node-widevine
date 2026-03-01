import { LicenseType, Widevine } from '../dist/index.cjs'
import { readFileSync } from 'fs'
import { performance } from 'perf_hooks'

const identifierBlob = readFileSync('./device_client_id_blob')
const privateKey = readFileSync('./device_private_key')

const pssh = Buffer.from('AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA==', 'base64')

const licenseUrl = 'https://cwip-shaka-proxy.appspot.com/no_auth'

// ----------------------------
// DEVICE INIT
// ----------------------------
let t0 = performance.now()
const device = Widevine.init(identifierBlob, privateKey)
let t1 = performance.now()

console.log(device.info)
console.log(`Device init: ${(t1 - t0).toFixed(2)} ms`)

// ----------------------------
// SESSION CREATE
// ----------------------------
t0 = performance.now()
const session = device.createSession(pssh, LicenseType.STREAMING)
t1 = performance.now()
console.log(`Session create: ${(t1 - t0).toFixed(2)} ms`)

// ----------------------------
// SERVICE CERT REQUEST
// ----------------------------
t0 = performance.now()
const serviceCertificateResponse = await fetch(licenseUrl, {
    method: 'POST',
    body: session.getServiceCertificateChallenge()
})
const serviceCertificate = Buffer.from(await serviceCertificateResponse.arrayBuffer())
session.setServiceCertificateFromMessage(serviceCertificate)
t1 = performance.now()
console.log(`Service cert request: ${(t1 - t0).toFixed(2)} ms (FETCH)`)

// ----------------------------
// LICENSE REQUEST
// ----------------------------
t0 = performance.now()
const response = await fetch(licenseUrl, {
    method: 'POST',
    body: session.generateChallenge()
})
t1 = performance.now()
console.log(`License request: ${(t1 - t0).toFixed(2)} ms (FETCH)`)

if (response.ok) {
    // ----------------------------
    // LICENSE PARSE
    // ----------------------------
    const licenseBuffer = Buffer.from(await response.arrayBuffer())

    const parseStart = performance.now()
    const keys = session.parseLicense(licenseBuffer)
    const parseEnd = performance.now()

    console.log(`License parse: ${(parseEnd - parseStart).toFixed(2)} ms`)
    console.log(`Blob&Key Test Successful? ${keys.length > 0 ? 'YES' : 'NO'}`)
} else {
    console.error('Request failed!')
    console.log(await response.text())
}

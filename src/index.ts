import { fromBinary } from '@bufbuild/protobuf'
import { KeyObject, createPrivateKey } from 'crypto'
import * as protocol from './license_protocol_pb'
import PYWIDEVINE_DEVICE from './pywidevine/device'
import Session from './session'
import type { ContentDecryptionModule, KeyContainer, WidevineInfo } from './types'

export default class Widevine {
    private identifierBlob: protocol.ClientIdentification
    private devicePrivateKey: KeyObject
    /** Device metadata extracted from the client id blob */
    public info: WidevineInfo

    private constructor(identifierBlob: protocol.ClientIdentification, devicePrivateKey: KeyObject, info: WidevineInfo) {
        this.identifierBlob = identifierBlob
        this.devicePrivateKey = devicePrivateKey
        this.info = info
    }

    /**
     * Initializes a Widevine client with a client ID blob and its matching private key
     *
     * @param identifierBlob The Widevine device client ID blob
     * @param privateKey The private key associated with the device client ID blob
     * @returns A fully initialized Widevine instance
     * @throws If the device client ID blob cannot be parsed or if the private key does not match
     */
    static init(identifierBlob: Buffer, privateKey: Buffer) {
        // Parse Client Blob
        const deviceIdentifierBlob = fromBinary(protocol.ClientIdentificationSchema, identifierBlob)

        const devicePrivateKey = createPrivateKey({
            key: privateKey,
            format: 'pem'
        })

        // Create DRM Cert to get system id (parsing client blob token)
        const drmCertificate = fromBinary(protocol.DrmCertificateSchema, deviceIdentifierBlob.token)

        const info: WidevineInfo = {
            client_info: {},
            system_id: drmCertificate.systemId
        }
        for (const ci of deviceIdentifierBlob.clientInfo) {
            info.client_info[ci.name] = ci.value
        }

        return new Widevine(deviceIdentifierBlob, devicePrivateKey, info)
    }

    /**
     * Initializes a Widevine client with a Widevine WVD (V1/V2) file
     *
     * @param prd Buffer containing a Widevine WVD file
     * @returns A fully initialized Widevine instance
     * @throws If WVD parsing fails or if the private key does not match
     */
    static initWVD(wvd: Buffer) {
        // Parse WVD file
        const device = PYWIDEVINE_DEVICE.parse(wvd)

        // Parse Client Blob
        const deviceIdentifierBlob = fromBinary(protocol.ClientIdentificationSchema, device.device.client_id)

        // WVD contains the PK in DER format
        const devicePrivateKey = createPrivateKey({
            key: device.device.private_key,
            format: 'der',
            type: 'pkcs1'
        })

        // Create DRM Cert to get system id (parsing client blob token)
        const drmCertificate = fromBinary(protocol.DrmCertificateSchema, deviceIdentifierBlob.token)

        const info: WidevineInfo = {
            client_info: {},
            system_id: drmCertificate.systemId,
            device_version: device.device.version,
            security_level: device.device.security_level
        }
        for (const ci of deviceIdentifierBlob.clientInfo) {
            info.client_info[ci.name] = ci.value
        }

        return new Widevine(deviceIdentifierBlob, devicePrivateKey, info)
    }

    /**
     * Creates a new Widevine license session.
     *
     * A session encapsulates all state required to:
     *  - parse and validate the provided PSSH
     *  - generate a signed Widevine license challenge
     *  - process and decrypt a Widevine license response
     *
     * @param pssh The Widevine PSSH box
     * @param licenseType The type of license being requested (e.g., streaming, offline, automatic)
     * @param android Whether to use the Android request ID format (true) or the generic 16-byte format (false - default)
     * @returns A new Session instance bound to this Widevine client
     */
    public createSession(pssh: Buffer, licenseType: protocol.LicenseType, android: boolean = false) {
        return new Session(this.identifierBlob, this.devicePrivateKey, pssh, licenseType, android)
    }
}

export const LicenseType = protocol.LicenseType
export type { Session, ContentDecryptionModule, KeyContainer }

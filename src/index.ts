// Utils
import type { ContentDecryptionModule, KeyContainer } from './types'

// Packages
import forge from 'node-forge'
import { fromBinary } from '@bufbuild/protobuf'

// Protocol Buffers
import * as protocol from './license_protocol_pb'
import Session from './session'

export default class Widevine {
    private identifierBlob: protocol.ClientIdentification
    private devicePrivateKey: forge.pki.rsa.PrivateKey

    private constructor(
        identifierBlob: protocol.ClientIdentification,
        devicePrivateKey: forge.pki.rsa.PrivateKey
    ) {
        this.identifierBlob = identifierBlob
        this.devicePrivateKey = devicePrivateKey
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
        const deviceIdentifierBlob = fromBinary(
            protocol.ClientIdentificationSchema,
            identifierBlob
        )

        const devicePrivateKey = forge.pki.privateKeyFromPem(
            privateKey.toString('binary')
        )

        return new Widevine(deviceIdentifierBlob, devicePrivateKey)
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
    public createSession(
        pssh: Buffer,
        licenseType: protocol.LicenseType,
        android: boolean = false
    ) {
        return new Session(
            this.identifierBlob,
            this.devicePrivateKey,
            pssh,
            licenseType,
            android
        )
    }
}

export const LicenseType = protocol.LicenseType
export type { ContentDecryptionModule, KeyContainer }

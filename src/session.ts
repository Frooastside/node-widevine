import { create, fromBinary, toBinary } from '@bufbuild/protobuf'
import crypto, { KeyObject, randomBytes } from 'crypto'
import AES_CMAC from './cmac'
import { COMMON_SERVICE_CERTIFICATE, SERVICE_CERTIFICATE_CHALLENGE, WIDEVINE_ROOT_PUBLIC_KEY, WIDEVINE_SYSTEM_ID } from './consts'
import * as protocol from './license_protocol_pb'
import type { KeyContainer } from './types'

export default class Session {
    private identifierBlob: protocol.ClientIdentification
    private devicePrivateKey: KeyObject
    private pssh: Buffer
    private licenseType: protocol.LicenseType
    private android: boolean = false
    private rawLicenseRequest?: Buffer
    private serviceCertificate?: protocol.SignedDrmCertificate

    constructor(identifierBlob: protocol.ClientIdentification, devicePrivateKey: KeyObject, pssh: Buffer, licenseType: protocol.LicenseType, android: boolean = false) {
        this.identifierBlob = identifierBlob
        this.devicePrivateKey = devicePrivateKey
        this.pssh = pssh
        this.licenseType = licenseType
        this.android = android
    }

    // ============================================================================
    // Service Certificate handling
    // ============================================================================

    /**
     * Returns the predefined service certificate challenge used to request
     * a Widevine service certificate from a license server.
     *
     * @returns The static service certificate challenge buffer
     */
    public getServiceCertificateChallenge() {
        return Buffer.from(SERVICE_CERTIFICATE_CHALLENGE)
    }

    /**
     * Loads and activates the default built-in Widevine service certificate.
     *
     * This is equivalent to receiving a certificate from a server and applying
     * it via setServiceCertificate().
     *
     * @throws If the certificate cannot be parsed or processed
     */
    public setDefaultServiceCertificate() {
        this.setServiceCertificate(Buffer.from(COMMON_SERVICE_CERTIFICATE))
    }

    /**
     * Extracts and applies a service certificate from a SignedMessage structure.
     *
     * The method expects a SignedMessage containing a raw DRM certificate and
     * forwards it to setServiceCertificate() for further validation.
     *
     * @param rawSignedMessage A SignedMessage buffer containing a service certificate
     * @throws If the message does not contain an embedded certificate payload
     */
    public setServiceCertificateFromMessage(rawSignedMessage: Buffer) {
        const signedMessage: protocol.SignedMessage = fromBinary(protocol.SignedMessageSchema, rawSignedMessage)
        if (!signedMessage.msg) {
            throw new Error('The service certificate message does not contain a message')
        }
        this.setServiceCertificate(Buffer.from(signedMessage.msg))
    }

    /**
     * Validates and sets a Widevine service certificate for the session.
     *
     * @param serviceCertificate A buffer containing a serialized SignedDrmCertificate
     * @throws If the certificate is malformed or not signed by the Widevine root
     */
    public setServiceCertificate(serviceCertificate: Buffer) {
        const signedServiceCertificate: protocol.SignedDrmCertificate = fromBinary(protocol.SignedDrmCertificateSchema, serviceCertificate)
        if (!this.verifyServiceCertificate(signedServiceCertificate)) {
            throw new Error('Service certificate is not signed by the Widevine root certificate')
        }
        this.serviceCertificate = signedServiceCertificate
    }

    // ============================================================================
    // License/Challenge handling
    // ============================================================================

    /**
     * Generates a Widevine license challenge for the current session.
     *
     * This method:
     *  - validates the PSSH and ensures it contains the Widevine system ID
     *  - constructs a LicenseRequest protobuf using the session parameters
     *  - optionally encrypts the ClientIdentification using the active service certificate
     *  - signs the request using the device private key (RSA-PSS)
     *  - wraps the request and signature into a SignedMessage
     *
     * Once a challenge has been generated, the session becomes immutable and
     * cannot be reused for a second request.
     *
     * @returns A SignedMessage buffer representing the Widevine license challenge
     * @throws If the PSSH is invalid, the Widevine system ID is missing, or the session was already consumed
     */
    public generateChallenge(): Buffer<ArrayBuffer> {
        if (this.rawLicenseRequest) throw new Error('Session already consumed, open up a new one')
        if (!this.pssh.subarray(12, 28).equals(Buffer.from(WIDEVINE_SYSTEM_ID))) throw new Error('The pssh is not an actuall pssh')

        const pssh = this.parsePSSH(this.pssh)
        if (!pssh) throw new Error('Pssh is invalid')

        const licenseRequest: protocol.LicenseRequest = create(protocol.LicenseRequestSchema, {
            type: protocol.LicenseRequest_RequestType.NEW,
            contentId: create(protocol.LicenseRequest_ContentIdentificationSchema, {
                contentIdVariant: {
                    case: 'widevinePsshData',
                    value: create(protocol.LicenseRequest_ContentIdentification_WidevinePsshDataSchema, {
                        psshData: [this.pssh.subarray(32)],
                        licenseType: this.licenseType,
                        requestId: this.android ? Buffer.from(`${randomBytes(8).toString('hex')}${'01'}${'00000000000000'}`) : randomBytes(16)
                    })
                }
            }),
            requestTime: BigInt(Date.now()) / BigInt(1000),
            protocolVersion: protocol.ProtocolVersion.VERSION_2_1,
            keyControlNonce: Math.floor(Math.random() * 2 ** 31)
        })

        if (this.serviceCertificate) {
            const encryptedClientIdentification = this.encryptClientIdentification(this.identifierBlob, this.serviceCertificate)
            licenseRequest.encryptedClientId = encryptedClientIdentification
        } else {
            licenseRequest.clientId = this.identifierBlob
        }

        this.rawLicenseRequest = Buffer.from(toBinary(protocol.LicenseRequestSchema, licenseRequest))

        const signature = crypto.sign('sha1', this.rawLicenseRequest, {
            key: this.devicePrivateKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: 20
        })

        const signedLicenseRequest: protocol.SignedMessage = create(protocol.SignedMessageSchema, {
            type: protocol.SignedMessage_MessageType.LICENSE_REQUEST,
            msg: this.rawLicenseRequest,
            signature: signature
        })

        return Buffer.from(toBinary(protocol.SignedMessageSchema, signedLicenseRequest))
    }

    /**
     * Parses and decrypts a Widevine license response.
     *
     * This method:
     *  - parses and validates the SignedMessage returned by the license server
     *  - decrypts the sessionKey using the device private key (RSA-OAEP)
     *  - derives the content encryption key (encKey) and HMAC key using AES-CMAC
     *  - authenticates the license message via HMAC-SHA256
     *  - decrypts all key containers (KIDs + content keys) contained in the license
     *
     * Returns the decrypted key containers, each containing:
     *  - kid: the key ID as a hex string
     *  - key: the 16-byte content key as a hex string
     *
     * @param rawLicense The SignedMessage buffer returned by the Widevine license server
     * @param options (optional) Custom parser settings
     * @returns An array of decrypted key containers extracted from the license
     * @throws If the license is malformed, signatures do not match, or no valid keys are present
     */
    public parseLicense(
        rawLicense: Buffer,
        options?: {
            includeHeader?: boolean
        }
    ) {
        if (!this.rawLicenseRequest) {
            throw new Error('Please request a license challenge first')
        }

        const signedLicense = fromBinary(protocol.SignedMessageSchema, rawLicense)
        if (!signedLicense.sessionKey) {
            throw new Error('The license does not contain a session key')
        }
        if (!signedLicense.msg) {
            throw new Error('The license does not contain a message')
        }
        if (!signedLicense.signature) {
            throw new Error('The license does not contain a signature')
        }

        const sessionKey = crypto.privateDecrypt(
            {
                key: this.devicePrivateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha1'
            },
            Buffer.from(signedLicense.sessionKey)
        )

        const cmac = new AES_CMAC(sessionKey)

        const encKeyBase = Buffer.concat([Buffer.from('ENCRYPTION'), Buffer.from('\x00', 'ascii'), this.rawLicenseRequest, Buffer.from('\x00\x00\x00\x80', 'ascii')])
        const authKeyBase = Buffer.concat([Buffer.from('AUTHENTICATION'), Buffer.from('\x00', 'ascii'), this.rawLicenseRequest, Buffer.from('\x00\x00\x02\x00', 'ascii')])

        const encKey = cmac.calculate(Buffer.concat([Buffer.from('\x01'), encKeyBase]))
        const serverKey = Buffer.concat([cmac.calculate(Buffer.concat([Buffer.from('\x01'), authKeyBase])), cmac.calculate(Buffer.concat([Buffer.from('\x02'), authKeyBase]))])

        const calculatedSignature = crypto.createHmac('sha256', serverKey).update(Buffer.from(signedLicense.msg)).digest()

        if (!calculatedSignature.equals(signedLicense.signature)) {
            throw new Error('Signatures do not match')
        }

        const license = fromBinary(protocol.LicenseSchema, signedLicense.msg)

        // Filter out header
        if (!options?.includeHeader) {
            license.key = license.key.filter((k) => k.key.length === 32)
        }

        const keyContainers = license.key.map((keyContainer) => {
            if (keyContainer.type && keyContainer.key && keyContainer.iv) {
                const keyId = keyContainer.id && keyContainer.id.length > 0 ? Buffer.from(keyContainer.id).toString('hex') : '00000000000000000000000000000000'

                const decipher = crypto.createDecipheriv('aes-128-cbc', encKey, Buffer.from(keyContainer.iv))

                const decryptedKey = Buffer.concat([decipher.update(Buffer.from(keyContainer.key)), decipher.final()])
                const key: KeyContainer = {
                    kid: keyId,
                    key: decryptedKey.toString('hex')
                }

                return key
            }
        })
        if (keyContainers.filter((container) => !!container).length < 1) {
            throw new Error('There was not a single valid key in the response')
        }

        return keyContainers
    }

    private encryptClientIdentification(
        clientIdentification: protocol.ClientIdentification,
        signedServiceCertificate: protocol.SignedDrmCertificate
    ): protocol.EncryptedClientIdentification {
        if (!signedServiceCertificate.drmCertificate) {
            throw new Error('The service certificate does not contain an actual certificate')
        }

        const serviceCertificate = fromBinary(protocol.DrmCertificateSchema, signedServiceCertificate.drmCertificate)
        if (!serviceCertificate.publicKey) {
            throw new Error('The service certificate does not contain a public key')
        }

        const key = randomBytes(16)
        const iv = randomBytes(16)

        const plaintext = Buffer.from(toBinary(protocol.ClientIdentificationSchema, clientIdentification))

        const cipher = crypto.createCipheriv('aes-128-cbc', key, iv)

        const rawEncryptedClientIdentification = Buffer.concat([cipher.update(plaintext), cipher.final()])
        const publicKey = crypto.createPublicKey({
            key: Buffer.from(serviceCertificate.publicKey),
            format: 'der',
            type: 'pkcs1'
        })
        const encryptedKey = crypto.publicEncrypt(
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha1'
            },
            key
        )

        return create(protocol.EncryptedClientIdentificationSchema, {
            encryptedClientId: rawEncryptedClientIdentification,
            encryptedClientIdIv: iv,
            encryptedPrivacyKey: encryptedKey,
            providerId: serviceCertificate.providerId,
            serviceCertificateSerialNumber: serviceCertificate.serialNumber
        })
    }

    private verifyServiceCertificate(signedServiceCertificate: protocol.SignedDrmCertificate): boolean {
        if (!signedServiceCertificate.drmCertificate) {
            throw new Error('The service certificate does not contain an actual certificate')
        }
        if (!signedServiceCertificate.signature) {
            throw new Error('The service certificate does not contain a signature')
        }

        const publicKey = crypto.createPublicKey({
            key: Buffer.from(WIDEVINE_ROOT_PUBLIC_KEY),
            format: 'der',
            type: 'pkcs1'
        })

        return crypto.verify(
            'sha1',
            Buffer.from(signedServiceCertificate.drmCertificate),
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: 20
            },
            Buffer.from(signedServiceCertificate.signature)
        )
    }

    // ============================================================================
    // PSSH handling
    // ============================================================================

    private parsePSSH(pssh: Buffer): protocol.WidevinePsshData | null {
        try {
            return fromBinary(protocol.WidevinePsshDataSchema, pssh.subarray(32))
        } catch {
            return null
        }
    }
}

// Utils
import {
    COMMON_SERVICE_CERTIFICATE,
    SERVICE_CERTIFICATE_CHALLENGE,
    WIDEVINE_ROOT_PUBLIC_KEY,
    WIDEVINE_SYSTEM_ID
} from './consts'
import type { KeyContainer } from './types'
import AES_CMAC from './cmac'

// Packages
import forge from 'node-forge'
import { create, fromBinary, toBinary } from '@bufbuild/protobuf'

// Protocol Buffers
import * as protocol from './license_protocol_pb'

export default class Session {
    private identifierBlob: protocol.ClientIdentification
    private devicePrivateKey: forge.pki.rsa.PrivateKey
    private pssh: Buffer
    private licenseType: protocol.LicenseType
    private android: boolean = false
    private rawLicenseRequest?: Buffer
    private serviceCertificate?: protocol.SignedDrmCertificate

    constructor(
        identifierBlob: protocol.ClientIdentification,
        devicePrivateKey: forge.pki.rsa.PrivateKey,
        pssh: Buffer,
        licenseType: protocol.LicenseType,
        android: boolean = false
    ) {
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
        return SERVICE_CERTIFICATE_CHALLENGE
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
        const signedMessage: protocol.SignedMessage = fromBinary(
            protocol.SignedMessageSchema,
            rawSignedMessage
        )
        if (!signedMessage.msg) {
            throw new Error(
                'The service certificate message does not contain a message'
            )
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
        const signedServiceCertificate: protocol.SignedDrmCertificate =
            fromBinary(protocol.SignedDrmCertificateSchema, serviceCertificate)
        if (!this.verifyServiceCertificate(signedServiceCertificate)) {
            throw new Error(
                'Service certificate is not signed by the Widevine root certificate'
            )
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
        if (this.rawLicenseRequest)
            throw new Error('Session already consumed, open up a new one')
        if (!this.pssh.subarray(12, 28).equals(Buffer.from(WIDEVINE_SYSTEM_ID)))
            throw new Error('The pssh is not an actuall pssh')

        const pssh = this.parsePSSH(this.pssh)
        if (!pssh) throw new Error('Pssh is invalid')

        const licenseRequest: protocol.LicenseRequest = create(
            protocol.LicenseRequestSchema,
            {
                type: protocol.LicenseRequest_RequestType.NEW,
                contentId: create(
                    protocol.LicenseRequest_ContentIdentificationSchema,
                    {
                        contentIdVariant: {
                            case: 'widevinePsshData',
                            value: create(
                                protocol.LicenseRequest_ContentIdentification_WidevinePsshDataSchema,
                                {
                                    psshData: [this.pssh.subarray(32)],
                                    licenseType: this.licenseType,
                                    requestId: this.android
                                        ? Buffer.from(
                                              `${forge.util.bytesToHex(forge.random.getBytesSync(8))}${'01'}${'00000000000000'}`
                                          )
                                        : Buffer.from(
                                              forge.random.getBytesSync(16),
                                              'binary'
                                          )
                                }
                            )
                        }
                    }
                ),
                requestTime: BigInt(Date.now()) / BigInt(1000),
                protocolVersion: protocol.ProtocolVersion.VERSION_2_1,
                keyControlNonce: Math.floor(Math.random() * 2 ** 31)
            }
        )

        if (this.serviceCertificate) {
            const encryptedClientIdentification =
                this.encryptClientIdentification(
                    this.identifierBlob,
                    this.serviceCertificate
                )
            licenseRequest.encryptedClientId = encryptedClientIdentification
        } else {
            licenseRequest.clientId = this.identifierBlob
        }

        this.rawLicenseRequest = Buffer.from(
            toBinary(protocol.LicenseRequestSchema, licenseRequest)
        )

        const pss: forge.pss.PSS = forge.pss.create({
            md: forge.md.sha1.create(),
            mgf: forge.mgf.mgf1.create(forge.md.sha1.create()),
            saltLength: 20
        })
        const md = forge.md.sha1.create()
        md.update(this.rawLicenseRequest.toString('binary'), 'raw')
        const signature = Buffer.from(
            this.devicePrivateKey.sign(md, pss),
            'binary'
        )

        const signedLicenseRequest: protocol.SignedMessage = create(
            protocol.SignedMessageSchema,
            {
                type: protocol.SignedMessage_MessageType.LICENSE_REQUEST,
                msg: this.rawLicenseRequest,
                signature: signature
            }
        )

        return Buffer.from(
            toBinary(protocol.SignedMessageSchema, signedLicenseRequest)
        )
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

        const signedLicense = fromBinary(
            protocol.SignedMessageSchema,
            rawLicense
        )
        if (!signedLicense.sessionKey) {
            throw new Error('The license does not contain a session key')
        }
        if (!signedLicense.msg) {
            throw new Error('The license does not contain a message')
        }
        if (!signedLicense.signature) {
            throw new Error('The license does not contain a signature')
        }

        const sessionKey = this.devicePrivateKey.decrypt(
            Buffer.from(signedLicense.sessionKey).toString('binary'),
            'RSA-OAEP',
            {
                md: forge.md.sha1.create()
            }
        )

        const cmac = new AES_CMAC(Buffer.from(sessionKey, 'binary'))

        const encKeyBase = Buffer.concat([
            Buffer.from('ENCRYPTION'),
            Buffer.from('\x00', 'ascii'),
            this.rawLicenseRequest,
            Buffer.from('\x00\x00\x00\x80', 'ascii')
        ])
        const authKeyBase = Buffer.concat([
            Buffer.from('AUTHENTICATION'),
            Buffer.from('\x00', 'ascii'),
            this.rawLicenseRequest,
            Buffer.from('\x00\x00\x02\x00', 'ascii')
        ])

        const encKey = cmac.calculate(
            Buffer.concat([Buffer.from('\x01'), encKeyBase])
        )
        const serverKey = Buffer.concat([
            cmac.calculate(Buffer.concat([Buffer.from('\x01'), authKeyBase])),
            cmac.calculate(Buffer.concat([Buffer.from('\x02'), authKeyBase]))
        ])

        const hmac = forge.hmac.create()
        hmac.start(forge.md.sha256.create(), serverKey.toString('binary'))
        hmac.update(Buffer.from(signedLicense.msg).toString('binary'))
        const calculatedSignature = Buffer.from(hmac.digest().data, 'binary')

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
                const keyId =
                    keyContainer.id && keyContainer.id.length > 0
                        ? Buffer.from(keyContainer.id).toString('hex')
                        : '00000000000000000000000000000000'

                const decipher = forge.cipher.createDecipher(
                    'AES-CBC',
                    encKey.toString('binary')
                )
                decipher.start({
                    iv: Buffer.from(keyContainer.iv).toString('binary')
                })
                decipher.update(
                    forge.util.createBuffer(Buffer.from(keyContainer.key))
                )
                decipher.finish()

                const decryptedKey = Buffer.from(decipher.output.data, 'binary')
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
            throw new Error(
                'The service certificate does not contain an actual certificate'
            )
        }

        const serviceCertificate = fromBinary(
            protocol.DrmCertificateSchema,
            signedServiceCertificate.drmCertificate
        )
        if (!serviceCertificate.publicKey) {
            throw new Error(
                'The service certificate does not contain a public key'
            )
        }

        const key = forge.random.getBytesSync(16)
        const iv = forge.random.getBytesSync(16)

        const cipher = forge.cipher.createCipher('AES-CBC', key)
        cipher.start({ iv: iv })
        cipher.update(
            forge.util.createBuffer(
                toBinary(
                    protocol.ClientIdentificationSchema,
                    clientIdentification
                )
            )
        )
        cipher.finish()

        const rawEncryptedClientIdentification = Buffer.from(
            cipher.output.data,
            'binary'
        )
        const publicKey = forge.pki.publicKeyFromAsn1(
            forge.asn1.fromDer(
                Buffer.from(serviceCertificate.publicKey).toString('binary')
            )
        )
        const encryptedKey = publicKey.encrypt(key, 'RSA-OAEP', {
            md: forge.md.sha1.create()
        })

        return create(protocol.EncryptedClientIdentificationSchema, {
            encryptedClientId: rawEncryptedClientIdentification,
            encryptedClientIdIv: Buffer.from(iv, 'binary'),
            encryptedPrivacyKey: Buffer.from(encryptedKey, 'binary'),
            providerId: serviceCertificate.providerId,
            serviceCertificateSerialNumber: serviceCertificate.serialNumber
        })
    }

    private verifyServiceCertificate(
        signedServiceCertificate: protocol.SignedDrmCertificate
    ): boolean {
        if (!signedServiceCertificate.drmCertificate) {
            throw new Error(
                'The service certificate does not contain an actual certificate'
            )
        }
        if (!signedServiceCertificate.signature) {
            throw new Error(
                'The service certificate does not contain a signature'
            )
        }

        const publicKey = forge.pki.publicKeyFromAsn1(
            forge.asn1.fromDer(
                Buffer.from(WIDEVINE_ROOT_PUBLIC_KEY).toString('binary')
            )
        )
        const pss: forge.pss.PSS = forge.pss.create({
            md: forge.md.sha1.create(),
            mgf: forge.mgf.mgf1.create(forge.md.sha1.create()),
            saltLength: 20
        })

        const sha1 = forge.md.sha1.create()
        sha1.update(
            Buffer.from(signedServiceCertificate.drmCertificate).toString(
                'binary'
            ),
            'raw'
        )

        return publicKey.verify(
            sha1.digest().bytes(),
            Buffer.from(signedServiceCertificate.signature).toString('binary'),
            pss
        )
    }

    // ============================================================================
    // PSSH handling
    // ============================================================================

    private parsePSSH(pssh: Buffer): protocol.WidevinePsshData | null {
        try {
            return fromBinary(
                protocol.WidevinePsshDataSchema,
                pssh.subarray(32)
            )
        } catch {
            return null
        }
    }
}

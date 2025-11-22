export type KeyContainer = {
    kid: string
    key: string
}

export type ContentDecryptionModule = {
    privateKey: Buffer
    identifierBlob: Buffer
}

export type KeyContainer = {
    kid: string
    key: string
}

export type ContentDecryptionModule = {
    privateKey: Buffer
    identifierBlob: Buffer
}

export type WidevineInfo = {
    client_info: Record<string, any>
    system_id: number
    device_version?: number
    security_level?: number
}

export interface PyWidevineDevice {
    version: number
    security_level: number
    client_id: Buffer<ArrayBuffer>
    private_key: Buffer<ArrayBuffer>
}

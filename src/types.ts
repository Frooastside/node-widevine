export type KeyContainer = {
    kid: string
    key: string
}

export type ContentDecryptionModule = {
    privateKey: Buffer
    identifierBlob: Buffer
}

export interface KeyBoxData {
    device_id: Buffer<ArrayBuffer>
    device_key: Buffer<ArrayBuffer>
    data: Buffer<ArrayBuffer>
    parsed_data: {
        flags: number
        system_id: number
        provisioning_id: Buffer<ArrayBuffer>
        encrypted_data: Buffer<ArrayBuffer>
    }
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

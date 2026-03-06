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
    device_type: DeviceType
    device_version?: number
    security_level?: number
}

export enum DeviceType {
    CHROME = 1,
    ANDROID = 2
}

export interface PyWidevineDevice {
    version: number
    device_type: DeviceType
    security_level: number
    client_id: Buffer<ArrayBuffer>
    private_key: Buffer<ArrayBuffer>
}

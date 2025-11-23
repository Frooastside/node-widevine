import { PyWidevineDevice } from '../types'

export default class PYWIDEVINE_DEVICE {
    public device: PyWidevineDevice

    private constructor(device: PyWidevineDevice) {
        this.device = device
    }

    static parse(buf: Buffer, offset = 0) {
        // Check if constant is valid
        const constant = buf.toString('ascii', offset, offset + 3)
        if (constant !== 'WVD')
            throw new Error(`Invalid signature, not a WVD file: ${constant}`)
        offset += 3
        // Check device version
        const version = buf.readInt8(offset) as 1 | 2
        offset += 1
        if (version > 2 || version < 1)
            throw new Error(
                `Invalid version, not a WVD file: version ${version}`
            )
        // Check device type
        // const type = buf.readInt8(offset) as 1 | 2
        offset += 1
        // Check device security level
        const security_level = buf.readInt8(offset) as 1 | 2 | 3
        offset += 1
        if (security_level > 3 || security_level < 1)
            throw new Error(
                `Invalid security_level, not a WVD file: security_level ${security_level}`
            )

        // Device Flags
        // const flags = buf.readInt8(offset)
        offset += 1
        // Private Key Length
        const private_key_len = buf.readInt16BE(offset)
        offset += 2
        // Private Key
        const private_key = buf.subarray(
            offset,
            offset + private_key_len
        ) as Buffer<ArrayBuffer>
        offset += private_key_len
        // Client ID Blob Length
        const client_id_len = buf.readInt16BE(offset)
        offset += 2
        // Client ID Blob
        const client_id = buf.subarray(
            offset,
            offset + client_id_len
        ) as Buffer<ArrayBuffer>

        return new PYWIDEVINE_DEVICE({
            version: version,
            security_level: security_level,
            client_id: client_id,
            private_key: private_key
        })
    }
}

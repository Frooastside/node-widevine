import { KeyBoxData } from '../types'
import { crc32Mpeg2 } from '../utils/crc32mpeg2'

export default class KeyBox {
    private data: KeyBoxData

    private constructor(data: KeyBoxData) {
        this.data = data
    }

    static parse(buf: Buffer, offset = 0) {
        // Needs to be 128 or 132 bytes
        if (buf.length !== 128 && buf.length !== 132)
            throw new Error(
                `Invalid KeyBox length: ${buf.length}. Only 128 and 132 bytes are supported.`
            )
        // Check if magic is valid
        const constant = buf.toString('ascii', 120, 124)
        if (constant !== 'kbox')
            throw new Error(`Invalid signature, not a KeyBox: ${constant}`)
        // C character string identifying the device
        const device_id = buf.subarray(
            offset,
            offset + 32
        ) as Buffer<ArrayBuffer>
        offset += 32
        // 128 bit AES key assigned to device
        const device_key = buf.subarray(
            offset,
            offset + 16
        ) as Buffer<ArrayBuffer>
        offset += 16
        // Key Data
        const data = buf.subarray(offset, offset + 72) as Buffer<ArrayBuffer>
        offset += 72
        // Magic
        // const magic = buf.subarray(offset, offset + 4) as Buffer<ArrayBuffer>
        offset += 4
        // Crc
        const crc = buf.readUint32BE(offset)

        // KeyBox Integrity check (Crc)
        const integrity_test = KeyBox.validateKeyBox(crc, buf)
        if (!integrity_test) throw new Error('KeyBox integrity check failed.')

        return new KeyBox({
            device_id: device_id,
            device_key: device_key,
            data: data
        })
    }

    private static validateKeyBox(crc_expected: number, buf: Buffer) {
        const crc = crc32Mpeg2(buf, 124)

        if (crc !== crc_expected) return false
        return true
    }
}

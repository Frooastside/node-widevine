export function crc32Mpeg2(data: Uint8Array, length: number): number {
    const poly = 0x04c11db7
    let crc = 0xffffffff

    for (let i = 0; i < length; i++) {
        crc ^= data[i] << 24
        for (let bit = 0; bit < 8; bit++) {
            if (crc & 0x80000000) {
                crc = (crc << 1) ^ poly
            } else {
                crc <<= 1
            }
        }
    }

    return crc >>> 0
}

import crypto from 'crypto'

export default class AES_CMAC {
    private readonly BLOCK_SIZE = 16
    private readonly Rb = Buffer.from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87
    ])
    private readonly ZERO = Buffer.alloc(16)

    private key: Buffer
    private x: Buffer
    private y: Buffer

    constructor(key: Buffer) {
        if (![16, 24, 32].includes(key.length)) {
            throw new Error('Key size must be 128, 192, or 256 bits.')
        }
        this.key = key
        const { first, second } = this.generateSubkeys()
        this.x = first
        this.y = second
    }

    calculate(message: Buffer): Buffer {
        const blocks = Math.ceil(message.length / 16) || 1
        let x: Buffer = this.ZERO
        let i = 0

        for (; i < blocks - 1; i++) {
            const off = i * 16
            x = this.aes(this.xor(x, message.subarray(off, off + 16)))
        }

        const last = this.getLastBlock(message)
        return this.aes(this.xor(x, last))
    }

    private generateSubkeys() {
        const L = this.aes(this.ZERO)
        const K1 = this.leftShift(L)
        if (L[0] & 0x80) this.xorInPlace(K1, this.Rb)
        const K2 = this.leftShift(K1)
        if (K1[0] & 0x80) this.xorInPlace(K2, this.Rb)
        return { first: K1, second: K2 }
    }

    private aes(block: Buffer): Buffer {
        const cipher = crypto.createCipheriv(
            `aes-${this.key.length * 8}-cbc`,
            this.key,
            this.ZERO
        )
        const r = cipher.update(block).subarray(0, 16)
        cipher.final()
        return r
    }

    private getLastBlock(message: Buffer): Buffer {
        const blocks = Math.ceil(message.length / 16) || 1
        const complete = message.length > 0 && message.length % 16 === 0
        const key = complete ? this.x : this.y

        const out = Buffer.alloc(16)
        const from = (blocks - 1) * 16
        const slice = message.subarray(from, from + 16)
        out.set(slice)
        if (!complete) out[slice.length] = 0x80

        return this.xor(out, key)
    }

    private leftShift(b: Buffer): Buffer {
        const out = Buffer.alloc(b.length)
        let carry = 0
        for (let i = b.length - 1; i >= 0; i--) {
            const v = b[i]
            out[i] = ((v << 1) & 0xff) | carry
            carry = v >>> 7
        }
        return out
    }

    private xor(a: Buffer, b: Buffer): Buffer {
        const out = Buffer.alloc(16)
        for (let i = 0; i < 16; i++) out[i] = a[i] ^ b[i]
        return out
    }

    private xorInPlace(a: Buffer, b: Buffer) {
        for (let i = 0; i < 16; i++) a[i] ^= b[i]
    }
}

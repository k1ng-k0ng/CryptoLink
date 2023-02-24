const pc1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
];
const pc2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
];
const keyShift = [
    1, 1, 2, 2,
    2, 2, 2, 2,
    1, 2, 2, 2,
    2, 2, 2, 1
];

/**
 * DesKey 建構函式
 * 
 * @param {Uint8Array} origKey 原始的金鑰(64bit)
 */
function DesKey(origKey) {
    this.round = 0;
    this.buf = new Uint8Array(6);
    let c = 0, d = 0;
    for (let i = 0; i < 28; ++i) {
        let k = pc1[i] - 1;
        let b = origKey[k >>> 3] >>> 7 - (k & 7) & 1;
        c |= b << 27 - i;
        k = pc1[28 + i] - 1;
        b = origKey[k >>> 3] >>> 7 - (k & 7) & 1;
        d |= b << 27 - i;
    }
    this.c = c;
    this.d = d;
}

/**
 * 產生下一輪的衍生金鑰
 * 
 * @returns 衍生金鑰(48bit)
 */
DesKey.prototype.getNext = function () {
    let s = keyShift[this.round++];
    let c = this.c << s & 0x0fffffff | this.c >>> 28 - s;
    let d = this.d << s & 0x0fffffff | this.d >>> 28 - s;
    this.buf.fill(0);
    for (let i = 0; i < 56; ++i) {
        let k = pc2[i] - 1;
        if (k < 28) {
            this.buf[i >>> 3] |= (c >>> 27 - k & 1) << (7 - i & 7);
        } else {
            this.buf[i >>> 3] |= (d >>> 55 - k & 1) << (7 - i & 7);
        }
    }
    this.c = c;
    this.d = d;
    return this.buf;
}

export { DesKey };
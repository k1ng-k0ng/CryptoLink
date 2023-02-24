/**
 * OFB 塊鏈結模式物件
 * 一開始設定好「加密演算法」、「填充演算法」、「區塊大小」後
 * 即可用 encrypt 與 decrypt 加密或解密訊息
 */

/**
 * 建構函式
 * 
 * @param {Object} config 設定
 *                        cipherAlg: 加密演算法
 *                        paddingAlg: 填充演算法
 *                        blockSize: 明文切分的區塊大小(而不是加密演算法的區塊大小)
 */
function OFB(config) {
    const param = {
        cipherAlg: 'cipherAlg',
        paddingAlg: 'paddingAlg',
        sz: 'blockSize' // 1: OFB-8, 8: OFB-64
    };
    for (let k in param) {
        let paramName = param[k];
        if (config[paramName] === undefined) {
            throw `OFB construct error`;
        }
        this[k] = config[paramName];
    }
    this.modename = 'OFB';
}

/**
 * 加密
 * 
 * @param {Uint8Array} msg 明文(不限長度)
 * @param {Uint8Array} key 金鑰(長度由加密演算法決定)
 * @param {Uint8Array} iv 初始向量(長度由加密演算法決定)
 * @returns {Uint8Array} 加密後的資料
 */
OFB.prototype.encrypt = function (msg, key, iv) {
    let buf = this.paddingAlg.pad(msg, this.sz);
    return this.run(buf, key, iv);
}

/**
 * 解密
 * 
 * @param {Uint8Array} cipher 密文
 * @param {Uint8Array} key 金鑰(長度由加密演算法決定)
 * @param {Uint8Array} iv 初始向量(長度由加密演算法決定)
 * @returns {Uint8Array} 解密後的資料
 */
OFB.prototype.decrypt = function (cipher, key, iv) {
    let msg = this.run(cipher, key, iv);
    return this.paddingAlg.unpad(msg);
}

/**
 * 實際執行 OFB
 * 
 * @param {Uint8Array} buf 密文或明文
 * @param {Uint8Array} key 金鑰(長度由加密演算法決定)
 * @param {Uint8Array} iv 初始向量(長度由加密演算法決定) 
 * @returns 
 */
OFB.prototype.run = function (buf, key, iv) {
    let len = iv.length;
    let I = new Uint8Array(len << 1);
    let I1 = new Uint8Array(I.buffer, 0, len);
    let I2 = new Uint8Array(I.buffer, len, len);
    let sz = this.sz;
    let n = buf.length;
    I1.set(iv);
    for (let i = 0; i + sz - 1 < n; i += sz) {
        this.cipherAlg.cipher(I1, key, I2);
        let P = new Uint8Array(buf.buffer, buf.byteOffset + i, sz);
        for (let j = 0; j < sz; ++j) {
            P[j] ^= I2[j];
        }
        I.copyWithin(0, sz, sz + len);
    }
    return buf;
}

export { OFB };
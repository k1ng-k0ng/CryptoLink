/**
 * CFB 塊鏈結模式物件
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
function CFB(config) {
    const param = {
        cipherAlg: 'cipherAlg',
        paddingAlg: 'paddingAlg',
        sz: 'blockSize' // 1: CFB-8, 8: CFB-64
    };
    for (let k in param) {
        let paramName = param[k];
        if (config[paramName] === undefined) {
            throw `CFB construct error`;
        }
        this[k] = config[paramName];
    }
    this.modename='CFB';
}

/**
 * 加密
 * 
 * @param {Uint8Array} msg 明文(不限長度)
 * @param {Uint8Array} key 金鑰(長度由加密演算法決定)
 * @param {Uint8Array} iv 初始向量(長度由加密演算法決定)
 * @returns {Uint8Array} 加密後的資料
 */
CFB.prototype.encrypt = function (msg, key, iv) {
    let I=new Uint8Array(iv);
    let EI=new Uint8Array(iv.length);
    let sz=this.sz;
    let buf=this.paddingAlg.pad(msg, sz);
    let n=buf.length;
    for(let i=0;i+sz-1<n;i+=sz) {
        let P=new Uint8Array(buf.buffer, buf.byteOffset+i, sz);
        this.cipherAlg.cipher(I, key, EI);
        for(let j=0;j<sz;++j) { //Pi直接變成 Ci
            P[j]^=EI[j]; 
        }
        // I = ((I << s) + ci) mod blocksize
        I.copyWithin(0, sz);
        I.set(P, iv.length-sz);
    }
    return buf;
}

/**
 * 解密
 * 
 * @param {Uint8Array} cipher 密文
 * @param {Uint8Array} key 金鑰(長度由加密演算法決定)
 * @param {Uint8Array} iv 初始向量(長度由加密演算法決定)
 * @returns {Uint8Array} 解密後的資料
 */
CFB.prototype.decrypt = function (cipher, key, iv) {
    let I=new Uint8Array(iv);
    let EI=new Uint8Array(iv.length);
    let sz=this.sz;
    let buf=new Uint8Array(cipher);
    let n=buf.length;
    for(let i=0;i+sz-1<n;i+=sz) {
        let C=new Uint8Array(buf.buffer, buf.byteOffset+i, sz);
        this.cipherAlg.cipher(I, key, EI);
        // I = ((I << s) + ci) mod blocksize
        I.copyWithin(0, sz);
        I.set(C, iv.length-sz);
        for(let j=0;j<sz;++j) { //Ci直接變成 Pi
            C[j]^=EI[j]; 
        }
    }
    return this.paddingAlg.unpad(buf);
}

export {CFB};
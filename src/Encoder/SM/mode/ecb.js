/**
 * ECB 塊鏈結模式物件
 */

/**
 * 建構函式
 * 
 * @param {Object} config 設定
 *                        cipherAlg: 加密演算法
 *                        paddingAlg: 填充演算法
 *                        blockSize: 明文切分的區塊大小(而不是加密演算法的區塊大小)
 */
function ECB(config) {
    const param = {
        cipherAlg: 'cipherAlg',
        paddingAlg: 'paddingAlg',
        sz: 'blockSize'
    };
    for (let k in param) {
        let paramName = param[k];
        if (config[paramName] === undefined) {
            throw `ECB construct error`;
        }
        this[k] = config[paramName];
    }
    this.modename='ECB';
}

/**
 * 合併陣列內的 Uint8Array
 * 
 * @param {Array} arr Uint8Array 陣列
 * @returns {Uint8Array} 合併後的 Uint8Array
 */
ECB.prototype.mergeData=function(arr) {
    let sz=arr.reduce((s,x)=>{
        return s+x.length;
    }, 0);
    let result=new Uint8Array(sz);
    let pos=0;
    for(let i=0, n=arr.length; i<n;++i) {
        result.set(arr[i], pos);
        pos+=arr[i].length;
    }
    return result;
}

/**
 * 加密
 * 
 * @param {Uint8Array} msg 明文(不限長度)
 * @param {Uint8Array} key 金鑰(長度由加密演算法決定)
 * @param {Uint8Array} iv 初始向量(長度由加密演算法決定)
 * @returns {Uint8Array} 加密後的資料
 */
ECB.prototype.encrypt = function (msg, key) {
    let sz = this.sz;
    let paddedMsg = this.paddingAlg.pad(msg, sz);
    let n = paddedMsg.length;
    let ouputBlocks=[];
    for (let i = 0; i + sz < n + 1; i += sz) {
        let block = paddedMsg.slice(i, i + sz);
        ouputBlocks.push(
            this.cipherAlg.cipher(block, key)
        );
    }
    return this.mergeData(ouputBlocks);
}

/**
 * 解密
 * 
 * @param {Uint8Array} cipher 密文
 * @param {Uint8Array} key 金鑰(長度由加密演算法決定)
 * @param {Uint8Array} iv 初始向量(長度由加密演算法決定)
 * @returns {Uint8Array} 解密後的資料
 */
ECB.prototype.decrypt = function (cipher, key) {
    let sz = this.sz;
    let n = cipher.length;
    let ouputBlocks=[];
    for (let i = 0; i + sz < n + 1; i += sz) {
        let block = cipher.slice(i, i + sz);
        ouputBlocks.push(
            this.cipherAlg.decipher(block, key)
        );
    }
    return this.paddingAlg.unpad(this.mergeData(ouputBlocks));
}

export {ECB};
/**
 * CBC 塊鏈結模式物件
 * 一開始設定好「加密演算法」、「填充演算法」、「區塊大小」後
 * 即可用 encrypt 與 decrypt 加密或解密訊息
 */

/**
 * 建構函式
 * 
 * @param {Object} config 設定
 *                        cipherAlg: 加密演算法
 *                        paddingAlg: 填充演算法
 *                        blockSize: 明文切分的區塊大小(大小，而不是加密演算法的區塊大小)
 */
function CBC(config) {
    const param = {
        cipherAlg: 'cipherAlg',
        paddingAlg: 'paddingAlg',
        sz: 'blockSize'
    };
    for (let k in param) {
        let paramName = param[k];
        if (config[paramName] === undefined) {
            throw `CBC construct error`;
        }
        this[k] = config[paramName];
    }
    this.modename='CBC';
}

/**
 * 合併陣列內的 Uint8Array
 * 
 * @param {Array} arr Uint8Array 陣列
 * @returns {Uint8Array} 合併後的 Uint8Array
 */
CBC.prototype.mergeData=function(arr) {
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
CBC.prototype.encrypt = function (msg, key, iv) {
    let sz = this.sz;
    let paddedMsg = this.paddingAlg.pad(msg, sz);
    let lastBlock = iv;
    let n = paddedMsg.length;
    let ouputBlocks=[];
    for (let i = 0; i + sz < n + 1; i += sz) {
        let block = paddedMsg.slice(i, i + sz);
        for (let j = 0; j < sz; ++j) {
            block[j] ^= lastBlock[j];
        }
        lastBlock=this.cipherAlg.cipher(block, key);
        ouputBlocks.push(lastBlock);
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
CBC.prototype.decrypt = function (cipher, key, iv) {
    let lastBlock = iv;
    let sz = this.sz;
    let n = cipher.length;
    let ouputBlocks=[];
    for (let i = 0; i + sz < n + 1; i += sz) {
        let block = cipher.slice(i, i + sz);
        let data = this.cipherAlg.decipher(block, key);
        for (let j = 0; j < sz; ++j) {
            data[j] ^= lastBlock[j];
        }
        lastBlock=block;
        ouputBlocks.push(data);
    }
    return this.paddingAlg.unpad(this.mergeData(ouputBlocks));
}

export {CBC};
import * as Des from './des.js';

const UINT8_BLOCK = 8;
const getChainBlock = (arr, baseIndex = 0) => {
    let block = arr.slice(0+baseIndex, 8+baseIndex);
    return block;
}

// PKCS7
const padding = (originalBuffer) => {
    if (originalBuffer === null) {
        return null;
    }
    let paddingLength = UINT8_BLOCK - originalBuffer.length % UINT8_BLOCK;
    let paddedBuffer = new Array(originalBuffer.length + paddingLength);

    originalBuffer.forEach((val, index) => paddedBuffer[index] = val);
    paddedBuffer.fill(paddingLength, originalBuffer.length);
    return paddedBuffer;
}

const dePadding = (paddedBuffer) => {
    if (paddedBuffer === null) {
        return null;
    }
    let paddingLength = paddedBuffer[paddedBuffer.length - 1];
    let originalBuffer = paddedBuffer.slice(0, paddedBuffer.length - paddingLength);
    return originalBuffer;
}

/**
 * 将字符串转为Unicode数组
 * @example "1234" => [49, 50, 51, 52];
 * @param {String} str 要转换的字符串
 * @returns {Number[]} 转换后的数组
 */
const stringToArray = (str) => {
    if (!/string/gi.test(Object.prototype.toString.call(str))) {
        str = JSON.stringify(str);
    }
    return unescape(encodeURIComponent(str)).split("").map(val => val.charCodeAt());
}


/**
 * 把 3des 金鑰(64 or 128 or 192 bit)拆成 des 金鑰(64 bit)陣列
 * 
 * @param {ArrayBuffer} key 
 * @returns {Array} 金鑰(64 bit)陣列，應有 1 ~ 3 個元素
 */
function splitKeys(key) {
    let keys = [];
    for (let i = 0; i < 24 && i + 7 < key.length; i += 8) {
        keys.push(key.slice(i, i + 8));
    }
    return keys;
}

/**
 * 加密
 * 
 * @param {Uint8Array} msg 原始訊息(64bit)
 * @param {Uint8Array} key 金鑰(64, 128, 192 bit)
 * @param {Uint8Array|undefined} dest 如果有指定，會用來儲存加密後的結果(64bit)並回傳
 * @returns 加密後的結果(64bit)，如果沒指定 dest，會建立一個新的空間
 */
function _cipher(msg, key, dest) {
    let keys = splitKeys(key);
    let idx = 0;
    if(dest) {
        Des._cipher(msg, keys[(idx++) % keys.length], dest);
    } else {
        dest = Des._cipher(msg, keys[(idx++) % keys.length]);
    }
    Des._decipher(dest, keys[(idx++) % keys.length], dest);
    Des._cipher(dest, keys[(idx++) % keys.length], dest);
    return dest;
}

/**
 * 解密
 * 
 * @param {Uint8Array} cipher 加密的訊息(64bit)
 * @param {Uint8Array} key 金鑰(64, 128, 192 bit)
 * @param {Uint8Array|undefined} dest 如果有指定，會用來儲存解密後的結果(64bit)並回傳
 * @returns 解密後的結果(64bit)，如果沒指定 dest，會建立一個新的空間
 */
function _decipher(cipher, key, dest) {
    let keys = splitKeys(key);
    if (keys.length > 2) {
        keys.reverse();
    }
    let idx = 0;
    let ret = new Uint8Array(8);
    if(dest) {
        Des._decipher(cipher, keys[(idx++) % keys.length], dest);
    } else {
        dest = Des._decipher(cipher, keys[(idx++) % keys.length]);
    }
    Des._cipher(dest, keys[(idx++) % keys.length], dest);
    Des._decipher(dest, keys[(idx++) % keys.length], dest);
    // ret = Des.cipher(dest, keys[(idx++) % keys.length], dest);
    // ret = Des.decipher(dest, keys[(idx++) % keys.length], dest);
    // ret = Des.decipher(ret, keys[(idx++) % keys.length], ret);
    // ret = Des._cipher(ret, keys[(idx++) % keys.length]);
    // ret = Des._decipher(ret, keys[(idx++) % keys.length]);
    return dest;
}

function cipher(msg, key, dest) {
    let plainByteArray = msg
    let padded = padding(plainByteArray);
    let blockTimes = padded.length / UINT8_BLOCK;
    let outArray = [];
    for (let i = 0; i < blockTimes; i++) {
        let roundIndex = i * UINT8_BLOCK;
        let block = getChainBlock(padded, roundIndex);
        let cipherBlock = new Uint8Array(8)
        cipherBlock = _cipher(block, key);
        for (let l = 0; l < UINT8_BLOCK; l++) {
            outArray[roundIndex + l] = cipherBlock[l];
        }
    }    
    return outArray;
}

function decipher(cipher, key, dest) {
    let cipherByteArray = cipher;
    let blockTimes = cipherByteArray.length / UINT8_BLOCK;
    let outArray = [];
    for (let i = 0; i < blockTimes; i++) {
        // extract the 16 bytes block data for this round to encrypt
        let roundIndex = i * UINT8_BLOCK;
        // make Uint8Array to Uint32Array block
        let block = getChainBlock(cipherByteArray, roundIndex);
        // reverse the round keys to decrypt
        let plainBlock = new Uint8Array(8)
        plainBlock = _decipher(block, key);
        for (let l = 0; l < UINT8_BLOCK; l++) {
            outArray[roundIndex + l] = plainBlock[l];
        }
    }

    // depadding the decrypted data
    let depaddedPlaintext = outArray; //dePadding(outArray);
    // transform data to utf8 string
    return stringToArray(decodeURIComponent(escape(String.fromCharCode(...depaddedPlaintext))));
}

export { cipher, decipher };
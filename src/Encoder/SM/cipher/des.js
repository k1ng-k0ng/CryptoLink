import { DesKey } from './deskey.js';

const initPermArr = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
];
const initPermInvArr = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]
const eTable = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
];
const pTable = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
];
const sBoxs = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    ]
];

/**
 * 透過 map 做位元映射
 * 來源與輸出位元數視 map 而定
 * 輸入與輸出的位元數可以不一樣
 * 
 * @param {Uint8Array} src 來源
 * @param {Uint8Array} dest 輸出
 * @param {Uint8Array} map 映射
 */
function permutate(src, dest, map) {
    let n = map.length;
    dest.fill(0);
    for (let i = 0; i < n; ++i) {
        let k = map[i] - 1;
        let b = src[k >>> 3] >>> 7 - (k & 7) & 1;
        dest[i >>> 3] |= b << 7 - (i & 7);
    }
}

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
    let paddingLength = 0;
    if(originalBuffer.length%UINT8_BLOCK === 0){
        paddingLength = 0;
    }else{
        paddingLength = UINT8_BLOCK - originalBuffer.length % UINT8_BLOCK;
    }    

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
    if(paddingLength==0){

        for (var i = paddedBuffer.length; i > 0; --i) {
            if (paddedBuffer[i] === 0){
                paddingLength = paddedBuffer.length - i
            }
        }
    }
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
 * 透過 map 做位元映射
 * 輸出限定是 64 bit
 * 高位與低位分別儲存在 L 跟 R
 * 
 * @param {Uint8Array} src 來源
 * @param {Uint8Array} L 輸出(高位32bit)
 * @param {Uint8Array} R 輸出(低位32bit)
 * @param {Uint8Array} map 映射
 */
function permutateToLR(src, L, R, map) {
    for (let i = 0; i < 32; ++i) {
        let k = map[i] - 1;
        let b = src[k >>> 3] >>> 7 - (k & 7) & 1;
        L[i >>> 3] |= b << 7 - (i & 7);

        k = initPermArr[32 + i] - 1;
        b = src[k >>> 3] >>> 7 - (k & 7) & 1;
        R[i >>> 3] |= b << 7 - (i & 7);
    }
}

/**
 * 透過 map 做位元映射
 * 來源限定是 64 bit
 * 高位與低位分別儲存在 L 跟 R
 * 
 * @param {Uint8Array} dest 輸出
 * @param {Uint8Array} L 來源(高位32bit)
 * @param {Uint8Array} R 來源(低位32bit)
 * @param {Uint8Array} map 映射
 */
function permutateByLR(dest, L, R, map) {
    for (let i = 0; i < 64; ++i) {
        let k = map[i] - 1;
        let b = k < 32 ? (L[k >>> 3] >>> 7 - (k & 7) & 1) : (R[k - 32 >>> 3] >>> 7 - (k - 32 & 7) & 1);
        dest[i >>> 3] |= b << 7 - (i & 7);
    }
}

/**
 * 執行 xbox 的運算
 * 
 * @param {Uint8Array} src 來源
 * @param {Uint8Array} dest 輸出
 */
function sbox(src, dest) {
    dest.fill(0);
    for (let i = 0; i < 8; ++i) {
        //取六位到 x
        let ss = (i >>> 2) * 3, x;
        switch (i & 3) {
            case 0:
                x = src[ss] >>> 2;
                break;
            case 1:
                x = src[ss] << 4 & 0x30 | src[ss + 1] >>> 4;
                break;
            case 2:
                x = src[ss + 1] << 2 & 0x3c | src[ss + 2] >>> 6;
                break;
            case 3:
                x = src[ss + 2] & 0x3f;
                break;
        }
        x = sBoxs[i][(x >>> 4 & 2 | x & 1) * 16 + (x >>> 1 & 15)];
        if (i & 1) {
            dest[i >>> 1] |= x;
        } else {
            dest[i >>> 1] |= x << 4;
        }
    }
}

/**
 * F(R, K) 函數的運算
 * 
 * @param {Uint8Array} R R
 * @param {Uint8Array} K K
 * @param {Uint8Array} O 輸出，儲存 F(R, K) 的運算結果
 * @param {Uint8Array} T 計算過程暫存用空間
 */
function computeF(R, K, O, T) {
    // O = E(R)
    permutate(R, O, eTable);
    // O ^= K
    for (let j = 0; j < 6; ++j) {
        O[j] ^= K[j];
    }
    // T = sbox(O)
    sbox(O, T);
    // O = P(T)
    permutate(T, O, pTable);
}

/**
 * 加密
 * 
 * @param {Uint8Array} msg 原始訊息(64bit)
 * @param {Uint8Array} key 金鑰(64bit)
 * @param {Uint8Array|undefined} dest 如果有指定，會用來儲存加密後的結果(64bit)並回傳
 * @returns 加密後的結果(64bit)，如果沒指定 dest，會建立一個新的空間
 */
function _cipher(msg, key, dest) {
    key = new DesKey(key);
    let buffers = [
        new Uint8Array(6),
        new Uint8Array(6),
        new Uint8Array(6),
        new Uint8Array(6)
    ];
    let L = buffers[0],
        R = buffers[1], O, T, K;
    //把 msg 轉換為 L0 跟 R0
    permutateToLR(msg, L, R, initPermArr);
    //加密迴圈
    for (let i = 0; i < 16; ++i) {
        L = buffers[i & 3];
        R = buffers[i + 1 & 3];
        O = buffers[i + 2 & 3];
        T = buffers[i + 3 & 3];
        //T = f(R, K)
        computeF(R, key.getNext(), O, T);
        //O = O XOR L
        for (let j = 0; j < 4; ++j) {
            O[j] ^= L[j];
        }
    }
    L = buffers[16 & 3];
    R = buffers[17 & 3];
    //IP_inverse(R16L16)
    if (!dest) {
        dest = new Uint8Array(8);
    } else {
        dest.fill(0);
    }
    permutateByLR(dest, R, L, initPermInvArr);
    return dest;
}

/**
 * 解密
 * 
 * @param {Uint8Array} cipher 加密的訊息(64bit)
 * @param {Uint8Array} key 金鑰(64bit)
 * @param {Uint8Array|undefined} dest 如果有指定，會用來儲存解密後的結果(64bit)並回傳
 * @returns 解密後的結果(64bit)，如果沒指定 dest，會建立一個新的空間
 */
function _decipher(cipher, key, dest) {
    //key expension
    key = new DesKey(key);
    let keys = [];
    for (let i = 0; i < 16; ++i) {
        keys.push(key.getNext().slice());
    }
    //
    let buffers = [
        new Uint8Array(6),
        new Uint8Array(6),
        new Uint8Array(6),
        new Uint8Array(6)
    ];
    let L = buffers[0],
        R = buffers[1], O, T, K;
    //把 cipher 轉換為 L16 跟 R16
    permutateToLR(cipher, R, L, initPermArr);
    for (let i = 16; i > 0; --i) {
        L = buffers[i & 3];
        R = buffers[i + 1 & 3];
        T = buffers[i + 2 & 3];
        O = buffers[i + 3 & 3];
        //算出 f(R{n-1}) 值，注意 L{n}=R{n-1}
        computeF(L, keys[i - 1], O, T);
        //L{n-1}=R{n}^f, O^=R
        for (let j = 0; j < 4; ++j) {
            O[j] ^= R[j];
        }
    }
    L = buffers[0];
    R = buffers[1];
    if (!dest) {
        dest = new Uint8Array(8);
    } else {
        dest.fill(0);
    }
    permutateByLR(dest, L, R, initPermInvArr);
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
        let cipherBlock = _cipher(block, key);
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
        let plainBlock = _decipher(block, key);
        for (let l = 0; l < UINT8_BLOCK; l++) {
            outArray[roundIndex + l] = plainBlock[l];
        }
    }

    // depadding the decrypted data
    let depaddedPlaintext = dePadding(outArray);
    console.log(depaddedPlaintext)
    // transform data to utf8 string
    return stringToArray(decodeURIComponent(escape(String.fromCharCode(...depaddedPlaintext))));
}

export { cipher, decipher, _cipher, _decipher };
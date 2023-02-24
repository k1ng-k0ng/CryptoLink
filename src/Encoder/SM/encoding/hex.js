//[定義] 十六進位字串：由 0~9 a~f(大小寫都可) 組成的字串，長度為 2 的倍數。

/**
 * 把十六進位字串轉換成 Uint8Array
 * 
 * @param {String} str 十六進位字串
 * @returns {Uint8Array} Uint8Array
 */
function enc(str) {
    if (str.length & 1) {
        throw 'Hex String 長度必須為偶數';
    }
    return new Uint8Array(str.match(/.{2}/g).map(s => parseInt(s, 16)));
}

/**
 * 把 Uint8Array 解讀為十六進位字串
 * 
 * @param {Uint8Array} buffer Uint8Array
 * @returns {String} 十六進位字串
 */
function dec(buffer) {
    return buffer.reduce((s, x) => {
        s += x < 16 ? '0' + x.toString(16) : x.toString(16);
        return s;
    }, '');
}

export { enc, dec }
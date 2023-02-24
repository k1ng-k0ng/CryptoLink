//[定義] 二進位字串：由 0 與 1 組成的字串，長度為 8 的倍數。

/**
 * 把二進位字串轉換成 Uint8Array
 * 
 * @param {String} str 二進位字串
 * @returns {Uint8Array} Uint8Array
 */
function enc(str) {
    if (str.length & 1) {
        throw 'Bin String 長度必須為 8 的倍數';
    }
    return new Uint8Array(str.match(/.{8}/g).map(s => parseInt(s, 2)));
}

/**
 * 把 Uint8Array 解讀為二進位字串
 * 
 * @param {Uint8Array} buffer Uint8Array
 * @returns {String} 二進位字串
 */
function dec(buffer) {
    return buffer.reduce((s, x) => {
        s += ('0000000' + x.toString(2)).slice(-8);
        return s;
    }, '');
}

export { enc, dec }
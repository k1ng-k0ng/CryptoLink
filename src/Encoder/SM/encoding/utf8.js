/**
 * 把字串以 utf8 的方式編碼，轉換成 Uint8Array
 * 
 * @param {String} str 字串
 * @returns {Uint8Array} Uint8Array
 */
function enc(str) {
    return (new TextEncoder()).encode(str);
}

/**
 * 把 Uint8Array 以 utf8 的方式解碼為字串
 * 
 * @param {Uint8Array} buffer Uint8Array
 * @returns {String} 字串
 */
function dec(buffer) {
    let n = buffer.indexOf(0);
    return (new TextDecoder()).decode(n < 0 ? buffer : buffer.slice(0, n));
}

export { enc, dec }
/**
 * 以 pacs#7 填充資料到指定位元組數的整數倍
 * 
 * @param {Uint8Array} buffer 要被填充的資料
 * @param {Integer} blockSize 區塊大小，會被填充到這個值的整數倍
 * @returns {Uint8Array} 填充後的區塊
 */
function pad(buffer, blockSize) {
    let n = ((buffer.byteLength + blockSize) / blockSize | 0) * blockSize;
    let m = n - buffer.byteLength;
    let tmp = new Uint8Array(n);
    tmp.set(buffer, 0);
    tmp.fill(m, buffer.byteLength);
    return tmp;
}

/**
 * 去除 pacs#7 填充，以還原成原始資料
 * 
 * @param {Uint8Array} buffer 被填充後的資料
 * @returns {Uint8Array} 原始資料
 */
function unpad(buffer) {
    let n = buffer[buffer.byteLength - 1];
    return buffer.slice(0, buffer.byteLength - n);
}

export { pad, unpad };
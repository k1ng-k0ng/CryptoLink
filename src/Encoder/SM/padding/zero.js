/**
 * 以 zero 填充資料到指定位元組數的整數倍
 * 
 * @param {Uint8Array} buffer 要被填充的資料
 * @param {Integer} blockSize 區塊大小，會被填充到這個值的整數倍
 * @returns {Uint8Array} 填充後的區塊
 */
function pad(buffer, blockSize) {
    //剛好 blockSize 的整數倍就直接回傳
    if (buffer.byteLength % blockSize === 0) {
        return buffer;
    }
    //否則回傳填充後的 Uint8Array
    let n = ((buffer.byteLength + blockSize - 1) / blockSize | 0) * blockSize;
    let tmp = new Uint8Array(n);
    tmp.set(buffer, 0);
    return tmp;
}

/**
 * 由於 zero padding 本身的缺陷
 * 無法從填充後的資料判段哪些部分是多出來的
 * 所以這邊只直接回傳輸入的內容
 * 
 * @param {Uint8Array} buffer 被填充後的資料
 * @returns {Uint8Array} 同 buffer
 */
function unpad(buffer) {
    //zero padding 無法判斷原始資料長度
    return buffer;
}

export { pad, unpad };
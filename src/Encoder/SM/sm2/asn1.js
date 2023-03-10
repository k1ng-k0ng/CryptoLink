const { BigInteger } = require('jsbn');

function bigIntToMinTwosComplementsHex(bigIntegerValue) {
    let h = bigIntegerValue.toString(16);
    if (h.substr(0, 1) !== '-') {
        if (h.length % 2 === 1) {
            h = '0' + h;
        } else if (!h.match(/^[0-7]/)) {
            h = '00' + h;
        }
    } else {
        let hPos = h.substr(1);
        let xorLen = hPos.length;
        if (xorLen % 2 === 1) {
            xorLen += 1;
        } else if (!h.match(/^[0-7]/)) {
            xorLen += 2;
        }
        let hMask = '';
        for (let i = 0; i < xorLen; i++) {
            hMask += 'f';
        }
        let biMask = new BigInteger(hMask, 16);
        let biNeg = biMask.xor(bigIntegerValue).add(BigInteger.ONE);
        h = biNeg.toString(16).replace(/^-/, '');
    }
    return h;
}
 
/**
 * base class for ASN.1 DER encoder object
 */
class ASN1Object {
    constructor() {
        this.isModified = true;
        this.hTLV = null;
        this.hT = '00';
        this.hL = '00';
        this.hV = '';
    }
 
    /**
     * get hexadecimal ASN.1 TLV length(L) bytes from TLV value(V)
     */
    getLengthHexFromValue() {
        let n = this.hV.length / 2;
        let hN = n.toString(16);
        if (hN.length % 2 == 1) {
            hN = '0' + hN;
        }
        if (n < 128) {
            return hN;
        } else {
            let hNlen = hN.length / 2;
            let head = 128 + hNlen;
            return head.toString(16) + hN;
        }
    }
 
    /**
     * get hexadecimal string of ASN.1 TLV bytes
     */
    getEncodedHex() {
        if (this.hTLV == null || this.isModified) {
            this.hV = this.getFreshValueHex();
            this.hL = this.getLengthHexFromValue();
            this.hTLV = this.hT + this.hL + this.hV;
            this.isModified = false;
        }
        return this.hTLV;
    }
 
    getFreshValueHex() {
        return '';
    }
};
 
/**
 * class for ASN.1 DER Integer
 */
class DERInteger extends ASN1Object {
    constructor(options) {
        super();

        this.hT = '02';
        if (options && options.bigint) {
            this.hTLV = null;
            this.isModified = true;
            this.hV = bigIntToMinTwosComplementsHex(options.bigint);
        }
    }
 
    getFreshValueHex() {
        return this.hV;
    }
}

/**
 * class for ASN.1 DER Sequence
 */
class DERSequence extends ASN1Object {

    constructor(options) {
        super();
     
        this.hT = '30';
        this.asn1Array = [];
        if (options && options.array) {
            this.asn1Array = options.array;
        }
    }

    getFreshValueHex() {
        let h = '';
        for (let i = 0; i < this.asn1Array.length; i++) {
            let asn1Obj = this.asn1Array[i];
            h += asn1Obj.getEncodedHex();
        }
        this.hV = h;
        return this.hV;
    }
}

/**
 * get byte length for ASN.1 L(length) bytes
 */
function getByteLengthOfL(s, pos) {
    if (s.substring(pos + 2, pos + 3) !== '8') return 1;
    let i = parseInt(s.substring(pos + 3, pos + 4));
    if (i === 0) return -1; // length octet '80' indefinite length
    if (0 < i && i < 10) return i + 1;  // including '8?' octet;
    return -2; // malformed format
}

/**
 * get hexadecimal string for ASN.1 L(length) bytes
 */
function getHexOfL(s, pos) {
    let len = getByteLengthOfL(s, pos);
    if (len < 1) return '';
    return s.substring(pos + 2, pos + 2 + len * 2);
}

/**
 * get integer value of ASN.1 length for ASN.1 data
 */
function getIntOfL(s, pos) {
    let hLength = getHexOfL(s, pos);
    if (hLength === '') return -1;
    let bi;
    if (parseInt(hLength.substring(0, 1)) < 8) {
        bi = new BigInteger(hLength, 16);
    } else {
        bi = new BigInteger(hLength.substring(2), 16);
    }
    return bi.intValue();
}

/**
 * get ASN.1 value starting string position for ASN.1 object refered by index 'idx'.
 */
function getStartPosOfV(s, pos) {
    let lLen = getByteLengthOfL(s, pos);
    if (lLen < 0) return l_len;
    return pos + (lLen + 1) * 2;
}

/**
 * get hexadecimal string of ASN.1 V(value)
 */
function getHexOfV(s, pos) {
    let pos1 = getStartPosOfV(s, pos);
    let len = getIntOfL(s, pos);
    return s.substring(pos1, pos1 + len * 2);
}

/**
 * get next sibling starting index for ASN.1 object string
 */
function getPosOfNextSibling(s, pos) {
    let pos1 = getStartPosOfV(s, pos);
    let len = getIntOfL(s, pos);
    return pos1 + len * 2;
}

/**
 * get array of indexes of child ASN.1 objects
 */
function getPosArrayOfChildren(h, pos) {
    let a = [];
    let p0 = getStartPosOfV(h, pos);
    a.push(p0);

    let len = getIntOfL(h, pos);
    let p = p0;
    let k = 0;
    while (1) {
        var pNext = getPosOfNextSibling(h, p);
        if (pNext === null || (pNext - p0  >= (len * 2))) break;
        if (k >= 200) break;
        
        a.push(pNext);
        p = pNext;
        
        k++;
    }

    return a;
}

module.exports = {
    /**
     * ASN.1 DER??????
     */
    encodeDer(r, s) {
        let derR = new DERInteger({ bigint: r });
        let derS = new DERInteger({ bigint: s });
        let derSeq = new DERSequence({ array: [derR, derS] });

        return derSeq.getEncodedHex();
    },

    /**
     * ?????? ASN.1 DER
     */
    decodeDer(input) {
        // 1. Items of ASN.1 Sequence Check
        let a = getPosArrayOfChildren(input, 0);
        
        // 2. Integer check
        let iTLV1 = a[0];
        let iTLV2 = a[1];

        // 3. getting value
        let hR = getHexOfV(input, iTLV1);
        let hS = getHexOfV(input, iTLV2);

        let r = new BigInteger(hR, 16);
        let s = new BigInteger(hS, 16);
        
        return { r, s };
    }
};

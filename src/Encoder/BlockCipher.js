
import EnvUtil from '../EnvUtil'
import Encoder from '../Encoder'
import InvalidInputError from '../Error/InvalidInput'
import nodeCrypto from 'crypto'

// import path from 'path'
import {encrypt_ecb, decrypt_ecb, encrypt_cbc, decrypt_cbc} from './SM/SM4'
import sm3 from './SM/SM3'
// import SM2Cipher from './SM/sm2/sm2'

import * as Ciphers from './SM/cipher/ciphers.js';


const meta = {
  name: 'block-cipher',
  title: 'Block Cipher',
  category: 'Modern cryptography',
  type: 'encoder'
}

const algorithms = [
  {
    name: 'aes-128',
    label: 'AES-128',
    blockSize: 16,
    keySize: 16,
    browserAlgorithm: 'aes',
    nodeAlgorithm: 'aes-128'
  },
  {
    name: 'aes-192',
    label: 'AES-192',
    blockSize: 16,
    keySize: 24,
    // Not widely supported in browsers
    browserAlgorithm: false,
    nodeAlgorithm: 'aes-192'
  },
  {
    name: 'aes-256',
    label: 'AES-256',
    blockSize: 16,
    keySize: 32,
    browserAlgorithm: 'aes',
    nodeAlgorithm: 'aes-256'
  },
  {
    name: 'sm4',
    label: 'SM4-128',
    blockSize: 16,
    keySize: 16,
    browserAlgorithm: 'sm4',
    nodeAlgorithm: 'sm4-128'
  },
  {
    name: 'des',
    label: 'DES',
    blockSize: 16,
    keySize: 16,
    browserAlgorithm: 'des',
    nodeAlgorithm: 'des'
  },
  {
    name: '3des',
    label: '3DES',
    blockSize: 16,
    keySize: 24,
    browserAlgorithm: '3des',
    nodeAlgorithm: '3des'
  }
]

const modes = [
  {
    name: 'cbc',
    label: 'CBC (Cipher Block Chaining)',
    hasIV: true,
    browserMode: true,
    nodeMode: true
  },
  {
    name: 'ctr',
    label: 'CTR (Counter)',
    hasIV: true,
    browserMode: true,
    nodeMode: true
  },
  {
    name: 'ecb',
    label: 'ECB (Electronic Code Book)',
    hasIV: false,
    browserMode: true,
    nodeMode: true
  }
]

const paddings = [
  {
    name: 'pkcs7',
    label: 'PKCS7',
    browserMode: true,
    nodeMode: true
  },
  {
    name: 'none',
    label: 'none',
    browserMode: true,
    nodeMode: true
  },
  {
    name: 'pkcs5',
    label: 'PKCS5',
    browserMode: true,
    nodeMode: true
  },  
  {
    name: 'zero',
    label: 'Zero',
    browserMode: true,
    nodeMode: true
  },
  {
    name: 'iso10126',
    label: 'ISO10126',
    browserMode: true,
    nodeMode: true
  },
  {
    name: 'ansix923',
    label: 'Ansix923',
    browserMode: true,
    nodeMode: true
  }
]

function stringToBytes(str){
  return hexToBytes(stringToHex(str));
}

// Convert a ASCII string to a hex string
function stringToHex(str) {
  return str.split("").map(function(c) {
      return ("0" + c.charCodeAt(0).toString(16)).slice(-2);
  }).join("");
}

function hexToBytes(hex) {
  for (var bytes = [], c = 0; c < hex.length; c += 2)
      bytes.push(parseInt(hex.substr(c, 2), 16));
  return bytes;
}

function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

function importPrivateKey(pem) {
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
  const binaryDerString = window.atob(pemContents);
  const binaryDer = str2ab(binaryDerString);

  return window.crypto.subtle.importKey(
      "spki",
      binaryDer,
      {
          name: "RSA-OAEP",
          hash: 'SHA-1'
      },
      true,
      ["encrypt"]
  );
}



function encryptMessage(publicKey) {
  let enc = new TextEncoder();
  const data =  enc.encode('admin@123456');
  return window.crypto.subtle.encrypt({
          name: "RSA-OAEP",
          hash: 'SHA-1'
      },
      publicKey,
      data);
}


/**
 * Encoder brick for block cipher encryption and decryption
 */
export default class BlockCipherEncoder extends Encoder {
  /**
   * Returns brick meta.
   * @return {object}
   */
  static getMeta () {
    return meta
  }

  /**
   * Constructor
   */
  constructor () {
    super()

    const algorithms = BlockCipherEncoder.getAlgorithms()
    const defaultAlgorithm = algorithms[0]
    const modes = BlockCipherEncoder.getModes()
    const paddingAvailable = BlockCipherEncoder.isPaddingAvailable()
    const paddings = BlockCipherEncoder.getPaddings()
    const defaultPadding = paddings[0]

    this.addSettings([
      {
        name: 'algorithm',
        type: 'enum',
        value: defaultAlgorithm.name,
        elements: algorithms.map(algorithm => algorithm.name),
        labels: algorithms.map(algorithm => algorithm.label),
        randomizable: false,
        width: 6
      },
      {
        name: 'paddings',
        type: 'enum',
        value: defaultPadding.name,
        elements: paddings.map(padding => padding.name),
        labels: paddings.map(padding => padding.label),
        randomizable: false,
        width: 6,
      },      
      {
        name: 'padding',
        type: 'boolean',
        value: false,
        randomizable: false,
        width: paddingAvailable ? 4 : 12,
        visible: paddingAvailable
      },
      {
        name: 'mode',
        type: 'enum',
        value: 'cbc',
        elements: modes.map(mode => mode.name),
        labels: modes.map(mode => mode.label),
        randomizable: false
      },
      {
        name: 'key',
        type: 'bytes',
        value: new Uint8Array([
          0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
          0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c ]
        ),
        minSize: 4,
        maxSize: defaultAlgorithm.keySize
      },
      {
        name: 'iv',
        label: 'IV',
        type: 'bytes',
        value: new Uint8Array([
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F ]
        ),
        minSize: 0,
        maxSize: defaultAlgorithm.blockSize
      }
    ])
  }

  /**
   * Triggered when a setting field has changed.
   * @protected
   * @param {Field} setting Sender setting field
   * @param {mixed} value New field value
   */
  settingValueDidChange (setting, value) {
    switch (setting.getName()) {
      case 'algorithm':
        const { keySize } = BlockCipherEncoder.getAlgorithm(value)
        
        const name = this.getSettingValue('algorithm')
        if(name === '3des' || name === 'des'){
          this.getSetting('iv')
          .setVisible(false)
        }else{
          this.getSetting('iv')
          .setVisible(true)
        }
       
        if(name === 'aes-128' || name === 'aes-256'){
          this.setSettingValue('mode', 'cbc')
        }else{
          this.setSettingValue('mode', 'ecb')
        }
        
        // FIXME : it can not refresh the text box
        // if(name === '3des'){
        //   this.setSettingValue('key', new Uint8Array([
        //     0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        //     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        //     0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6]
        //   ))
        // }else{
        //   this.setSettingValue('key', new Uint8Array([
        //     0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        //     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c ]
        //   ))
        // }

        this.getSetting('key')
          .setMinSize(keySize)
          .setMaxSize(keySize)

          break

      case 'mode':
        const algorithm = this.getSettingValue('algorithm')
        const { blockSize } = BlockCipherEncoder.getAlgorithm(algorithm)
        const { hasIV } = BlockCipherEncoder.getMode(value)

        this.getSetting('iv')
          .setVisible(hasIV)
          .setMinSize(blockSize)
          .setMaxSize(blockSize)
        break
    }
  }

  /**
   * Performs encode or decode on given content.
   * @protected
   * @param {Chain} content
   * @param {boolean} isEncode True for encoding, false for decoding
   * @return {number[]|string|Uint8Array|Chain|Promise} Resulting content
   */
  async performTranslate (content, isEncode) {
    const message = content.getBytes()
    const { algorithm, mode, key, padding, iv } = this.getSettingValues()

    try {
      // Try to encrypt or decrypt
      return await this.createCipher(
        algorithm, mode, key, iv, padding, isEncode, message)
    } catch (err) {
      // Catch invalid input errors
      if (!isEncode) {
        throw new InvalidInputError(
          `${algorithm} decryption failed, ` +
          `this may be due to malformed content`)
      } else {
        throw new InvalidInputError(`${algorithm} encryption failed`)
      }
    }
  }

  /**
   * Creates message cipher using given algorithm.
   * @protected
   * @param {string} name Algorithm name
   * @param {Uint8Array} message Message bytes
   * @return {Promise}
   */
  async createCipher (name, mode, key, iv, padding, isEncode, message) {
    const algorithm = BlockCipherEncoder.getAlgorithm(name)

    const { hasIV } = BlockCipherEncoder.getMode(mode)
    if (!hasIV) {
      iv = new Uint8Array([])
    }
    switch (name) {
      case 'des':{
        console.log('des');
        const cipherName = algorithm.nodeAlgorithm + '-' + mode
          // Create message cipher using Node Crypto async

          return new Promise((resolve, reject) => {
            const cipher = isEncode
              ? Ciphers.Des.cipher(message, key.slice(0,8))
              : Ciphers.Des.decipher(message, key.slice(0,8)) 

            resolve(new Uint8Array(cipher))
          })

      }
      case '3des':{
        const cipherName = algorithm.nodeAlgorithm + '-' + mode
          // Create message cipher using Node Crypto async
        console.log('3des');
          return new Promise((resolve, reject) => {
            const cipher3 = isEncode
              ? Ciphers.TripleDes.cipher(message, key)
              : Ciphers.TripleDes.decipher(message, key) 

            resolve(new Uint8Array(cipher3))
          })

      }
      case 'sm4':{
        const cipherName = algorithm.nodeAlgorithm + '-' + mode
        console.log('genkey');
      //   const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('rsa', {
      //     modulusLength: 1024,
      //     publicKeyEncoding: {
      //         type: 'pkcs1',
      //         format: 'pem'
      //     },
      //     privateKeyEncoding: {
      //         type: 'pkcs1',
      //         format: 'pem',
      //         // cipher: 'aes-256-cbc',
      //         // passphrase: 'top secret'
      //     }
      // });
      // const publicKey = fs.readFileSync('../../../../../rsa_public_key.pem').toString('ascii');
      // const privateKey = fs.readFileSync('./rsa_private_key.pem').toString('ascii');
      const publicKey = "-----BEGIN PUBLIC KEY-----\
      MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/rzb20kypDANTLSMU30PeoWwP\
      ZVltVZC3tm6Nh5jlqmldB4hez02ojg+qOfSxvi1SNvlij3rNSKhMnJOofvBlj8/H\
      nSNX25EBlhC0/8vSkiHuePxGG04oCXvsWTNMJ2W9U54rno0IM2KDrFP5UZDxR8ft\
      jGOK3tJnuJO2TUQhawIDAQAB\
      -----END PUBLIC KEY-----";
      const data = 'data to crypt';
      console.log('rsa enc', stringToBytes(data));
      // // 公钥加密
      // const encryptData = nodeCrypto.publicEncrypt(publicKey, stringToBytes(data));
      // console.log('encode', encryptData);
      // console.log('rsa dec');
      // // 私钥解密
      // const decryptData = nodeCrypto.privateDecrypt(privateKey, Buffer.from(encryptData.toString('base64'), 'base64'));
      // console.log('decode', decryptData.toString());
      // const key = await importPrivateKey(pemEncodedKey);
      // // const password = await encryptMessage(key);
      // const password = window.crypto.subtle.encrypt({
      //   name: "RSA-OAEP"
      // },
      // key,
      // message);
      // const _password = window.btoa(String.fromCharCode(new Uint8Array(password)));
      // console.log(_password)      
      // data = DES().CalDES("3030303030303030","3030303030303030","E");

      // console.log(result);

      if (EnvUtil.isNode()) {
      }
      else{
        const pemEncodedKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxiuhgssxHclogWzB7OGy
vkIB+HGUO4hODykrz3c0/SBLJZc78mq7VaL3EnicGpoXFJkao3I+1C7MD5Jpa27b
Sc22veI0frbd/nbiSutvwAnf3rpVJEQtFTMz3v4OpSRcjOhIxKsL6iZ0JTt5++gk
sqeyrMtk5myAgho9JTnK7fPCrT7AZb/VaGc9NlWL2+9nTypLr2pew53o24nhWS5w
IgJM4X0M08YB3meXR/Q/CamgtI7+DEdubTfNwc9YCTuH6q3P7oqP/1X5Al+UHnoY
OITJJfFRBQ4zrzJU8lMQm3hy3ZSdsiP1vVqfoqQ2pu5IoL3OSgQEGVSp/OndwVz7
AQIDAQAB
-----END PUBLIC KEY-----`;
const key = await importPrivateKey(pemEncodedKey);
        // let result = window.crypto.subtle.encrypt({
        //     name: "RSA-OAEP",
        //     hash: 'SHA-1'
        // },
        // key,
        // message);
        // if (result.oncomplete !== undefined) {
        //   // Wrap IE11 CryptoOperation object in a promise
        //   result = new Promise((resolve, reject) => {
        //     result.oncomplete = resolve.bind(this, result.result)
        //     result.onerror = reject
        //   })
        // }
        
        // return result.then(buffer => new Uint8Array(buffer))
  }

        if(mode === "ecb"){
            // return new Promise(resolve => resolve(
            //   isEncode
            //   ? encrypt_ecb(message, key)
            //   : decrypt_ecb(message, key)
              
            // ))

            // Create message cipher using Node Crypto async
            return new Promise((resolve, reject) => {
              const cipher = isEncode
                ? encrypt_ecb(message, key)
                : decrypt_ecb(message, key) 

              // cipher.setAutoPadding(padding)
              // const resultBuffer = Buffer.concat([
              //   cipher
              // ])
              console.log(cipher);

              resolve(new Uint8Array(cipher))
            })
        }
        if(mode === "cbc"){
            // return new Promise(resolve => resolve(
            //   isEncode
            //   ? encrypt_cbc(message, key, iv)
            //   : decrypt_cbc(message, key, iv)
              
            // ))

            return new Promise((resolve, reject) => {
              const cipher = isEncode
                ? encrypt_cbc(message, key, iv)
                : decrypt_cbc(message, key, iv)

              // cipher.setAutoPadding(padding)
              // const resultBuffer = Buffer.concat([
              //   cipher
              // ])

              resolve(new Uint8Array(cipher))
            })

        }
   
      }
    }
    if (EnvUtil.isNode()) {
      const cipherName = algorithm.nodeAlgorithm + '-' + mode

      // Node v8.x - convert Uint8Array to Buffer - not needed for v10
      iv = global.Buffer.from(iv)
      message = global.Buffer.from(message)

      // Create message cipher using Node Crypto async
      return new Promise((resolve, reject) => {
        const cipher = isEncode
          ? nodeCrypto.createCipheriv(cipherName, key, iv)
          : nodeCrypto.createDecipheriv(cipherName, key, iv)

        cipher.setAutoPadding(padding)

        const resultBuffer = Buffer.concat([
          cipher.update(message),
          cipher.final()
        ])

        resolve(new Uint8Array(resultBuffer))
      })
    } else {
      const cipherName = algorithm.browserAlgorithm + '-' + mode

      // Get crypto subtle instance
      const crypto = window.crypto || window.msCrypto
      const cryptoSubtle = crypto.subtle || crypto.webkitSubtle

      // Create key instance
      const cryptoKey = await cryptoSubtle.importKey(
        'raw', key, { name: cipherName }, false, ['encrypt', 'decrypt'])

      // Create message cipher using Web Crypto API
      const algo = {
        name: cipherName,
        iv,
        counter: iv,
        length: algorithm.blockSize
      }

      let result = isEncode
        ? cryptoSubtle.encrypt(algo, cryptoKey, message)
        : cryptoSubtle.decrypt(algo, cryptoKey, message)

      // IE11 exception
      if (result.oncomplete !== undefined) {
        // Wrap IE11 CryptoOperation object in a promise
        result = new Promise((resolve, reject) => {
          result.oncomplete = resolve.bind(this, result.result)
          result.onerror = reject
        })
      }

      return result.then(buffer => new Uint8Array(buffer))
    }
  }

  /**
   * Returns wether padding is available in the current environment.
   * @protected
   * @return {boolean}
   */
  static isPaddingAvailable () {
    return EnvUtil.isNode()    
  }

  /**
   * Returns algorithm for given name.
   * @protected
   * @param {string} name Algorithm name
   * @return {?object} Algorithm object or null, if not found.
   */
  static getAlgorithm (name) {
    return algorithms.find(algorithm => algorithm.name === name)
  }

  /**
   * Returns algorithm objects available in the current environment.
   * @protected
   * @return {object[]}
   */
  static getAlgorithms () {
    const isNode = EnvUtil.isNode()
    return algorithms.filter(algorithm =>
      (algorithm.browserAlgorithm && !isNode) ||
      (algorithm.nodeAlgorithm && isNode)
    )
  }

  /**
   * Returns mode for given name.
   * @protected
   * @param {string} name Mode name
   * @return {?object} Mode object or null, if not found.
   */
  static getMode (name) {
    return modes.find(mode => mode.name === name)
  }

  /**
   * Returns mode objects available in the current environment.
   * @protected
   * @return {object[]}
   */
  static getModes () {
    const isNode = EnvUtil.isNode()
    return modes.filter(mode =>
      (mode.browserMode && !isNode) ||
      (mode.nodeMode && isNode)
    )
  }

  static getPadding (name) {
    return paddings.find(padding => padding.name === name)
  }

  /**
   * Returns mode objects available in the current environment.
   * @protected
   * @return {object[]}
   */
  static getPaddings () {
    const isNode = true; //EnvUtil.isNode()
    return paddings.filter(padding =>
      (padding.browserMode && isNode) ||
      (padding.nodeMode && isNode)
    )
  }

}

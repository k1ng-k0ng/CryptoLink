// PEM encoded X.509 key
const publicKey = `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/rzb20kypDANTLSMU30PeoWwP
ZVltVZC3tm6Nh5jlqmldB4hez02ojg+qOfSxvi1SNvlij3rNSKhMnJOofvBlj8/H
nSNX25EBlhC0/8vSkiHuePxGG04oCXvsWTNMJ2W9U54rno0IM2KDrFP5UZDxR8ft
jGOK3tJnuJO2TUQhawIDAQAB
-----END PUBLIC KEY-----`;
// PEM encoded PKCS#8 key
const privateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC/rzb20kypDANTLSMU30PeoWwPZVltVZC3tm6Nh5jlqmldB4he
z02ojg+qOfSxvi1SNvlij3rNSKhMnJOofvBlj8/HnSNX25EBlhC0/8vSkiHuePxG
G04oCXvsWTNMJ2W9U54rno0IM2KDrFP5UZDxR8ftjGOK3tJnuJO2TUQhawIDAQAB
AoGADpPMokir+88mEZVFLbks+Clehm02t9HiB5agIbNGNXEYQjLodA1f4omrN07h
BQNpfu8fWBeBR0tXQTxHHnFI5s6vNs8Y8jZu22hNJlI5B3Q2b4P1IgJfVzLK9qqv
958i++SOj3d0gpCeUXnDBZhyuK/FA82vKKDwj/j3Gm4zcgECQQDfkuXPcknDiZkK
5wXF3l7KDkEDMFLo3Rvzl0gklUJ1qxi4oKqMluDR/ynfAcL+DjXMzE0+sQjhHkau
/uiHxYlhAkEA23xKrGuLCzxSZb2vQi3hOgI6R/JE/pjTRQmMfj3D4n5+afciQDDP
l5Vf9i5+4UKSQs499MmbDUHZDIFQ/eYiSwJAWdYPHeJQnY/GvUjDWxTVhd9gZEWg
qw1d0+2wAXMwd1O+5UE6BrABuqALVR7CGY/gMmDNkSlV5g9iW6L2EMhhQQJAYRTt
Aq7e5a1c1Nu99YvNn5b0qHYkxmhaqqK6new8BKbmy4AgijwM1oOf2oheXszPXPVU
uj2ic464rqtUY7mzWQJBALRpxw3qroCNSw9OcgNpunSD+os9DVHTi32EQ4SW6lSR
ve6eLn43rqXO/C40priPf/7iQ6h1JJAD9usSt5FhGp4=
-----END RSA PRIVATE KEY-----`;

async function importPublicKeyAndEncrypt(str) {
    try {
      const pub = await importPublicKey(publicKey);
      console.log(pub);
      const encrypted = await encryptRSA(pub, new TextEncoder().encode(str));
      const encryptedBase64 = window.btoa(ab2str(encrypted));
      console.log(encryptedBase64.replace(/(.{64})/g, '$1\n'));
    } catch (error) {
      console.log(error);
    }
  }
  
  async function importPrivateKeyAndDecrypt(str) {
    try {
      const priv = await importPrivateKey(privateKey);
      const decrypted = await decryptRSA(priv, str2ab(window.atob(str)));
      console.log(decrypted);
    } catch (error) {
      console.log(error);
    }
  }
  
  async function importPublicKey(spkiPem) {
    return await window.crypto.subtle.importKey(
      'spki',
      getSpkiDer(spkiPem),
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      },
      true,
      ['encrypt']
    );
  }
  
  async function importPrivateKey(pkcs8Pem) {
    return await window.crypto.subtle.importKey(
      'pkcs8',
      getPkcs8DerDecode(pkcs8Pem),
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      },
      true,
      ['decrypt']
    );
  }
  
  async function encryptRSA(key, plaintext) {
    let encrypted = await window.crypto.subtle.encrypt(
      {
        name: 'RSA-OAEP',
      },
      key,
      plaintext
    );
    return encrypted;
  }
  
  async function decryptRSA(key, ciphertext) {
    let decrypted = await window.crypto.subtle.decrypt(
      {
        name: 'RSA-OAEP',
      },
      key,
      ciphertext
    );
    return new TextDecoder().decode(decrypted);
  }
  
  function getSpkiDer(spkiPem) {
    const pemHeader = '-----BEGIN PUBLIC KEY-----';
    const pemFooter = '-----END PUBLIC KEY-----';
    var pemContents = spkiPem.substring(
      pemHeader.length,
      spkiPem.length - pemFooter.length
    );
    var binaryDerString = window.atob(pemContents);
    return str2ab(binaryDerString);
  }
  
  function getPkcs8DerDecode(pkcs8Pem) {
    const pemHeader = '-----BEGIN PRIVATE KEY-----';
    const pemFooter = '-----END PRIVATE KEY-----';
    var pemContents = pkcs8Pem.substring(
      pemHeader.length,
      pkcs8Pem.length - pemFooter.length
    );
    var binaryDerString = window.atob(pemContents);
    return str2ab(binaryDerString);
  }
  
  function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }
  
  function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
  }

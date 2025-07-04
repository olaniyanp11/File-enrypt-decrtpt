// lib/cryptoHelpers.js
const crypto = require('crypto');
const fs     = require('fs');

/**
 * Decrypt a file that was encrypted with AES‑256‑CBC.
 * @param {string} inPath   – path to the .enc file
 * @param {string} outPath  – where to write the decrypted file
 * @param {Buffer} key      – 32‑byte AES key
 * @param {Buffer} iv       – 16‑byte IV
 * @returns {Promise<void>}
 */
function decryptAES(inPath, outPath, key, iv) {
  return new Promise((resolve, reject) => {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    const input  = fs.createReadStream(inPath);
    const output = fs.createWriteStream(outPath);

    input.pipe(decipher).pipe(output);

    output.on('finish', resolve);
    output.on('error',  reject);
    input .on('error',  reject);
  });
}

module.exports = { decryptAES };

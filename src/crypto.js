/**
 * This module provides easy, yet strong, facilities for encrypting and decrypting serializable objects. The
 * ease-of-use comes from the fact that this module is opinionated in its (strong) choice of cryptographic algorithms,
 * lengths, and iterations that cannot be overriden by its users.
 *
 * The module exports a `makeCryptoWith` function that takes a single argument, an `opts` object. This object requires
 * a property named `encryptionKey` which is a passphrase used by the encryption and decryption algorithms within
 * this module. The `makeCryptoWith` function returns an object containing two functions, `encrypt` and `decrypt`.
 *
 * Both the `encrypt` and `decrypt` functions are inverses of each other and return Promises. That is:
 *   someSerializableObj === await decrypt(await encrypt(someSerializableObj)).
 */

import crypto from 'crypto';

const IV_LENGTH_IN_BYTES = 12;
const SALT_LENGTH_IN_BYTES = 64;
const KEY_LENGTH_IN_BYTES = 32;
const KEY_ITERATIONS = 10000;
const KEY_DIGEST = 'sha512';
const CIPHER_ALGORITHM = 'aes-256-gcm';
const ENCRYPTION_RESULT_ENCODING = 'base64';

function _validateOpts({ encryptionKey }) {
  if (!encryptionKey) {
    throw new Error('encryptionKey is required');
  }
}

function _validateAAD(aad) {
  if(aad == null) {
    return;
  }

  if(typeof aad !== 'string') {
    throw new Error('AAD must be a string');
  }

  if(aad.length === 0) {
    throw new Error('AAD cannot be an empty string');
  }
}

function _generateSalt() {
  return crypto.randomBytes(SALT_LENGTH_IN_BYTES);
}

function _generateIV() {
  return crypto.randomBytes(IV_LENGTH_IN_BYTES);
}

function _generateKey(encryptionKey, salt) {
  if (!Buffer.isBuffer(salt)) {
    salt = new Buffer(salt, ENCRYPTION_RESULT_ENCODING);
  }

  return new Promise((resolve, reject) => {
    crypto.pbkdf2(encryptionKey, salt, KEY_ITERATIONS, KEY_LENGTH_IN_BYTES, KEY_DIGEST, (err, key) => {
      if (err) {
        reject(err);
        return;
      }

      if (!Buffer.isBuffer(key)) {
        key = new Buffer(key, 'binary');
      }

      resolve(key);
    });
  });
}

function _serialize(obj) {
  return new Promise((resolve, reject) => {
    const serializedObj = JSON.stringify(obj);
    if (serializedObj === undefined) {
      reject(new Error('Object to be encrypted must be serializable'));
      return;
    }
    resolve(serializedObj);
  });
}

/**
 * Implmenetation of encrypt() and decrypt() taken from https://gist.github.com/AndiDittrich/4629e7db04819244e843,
 * which was recommended by @jaymode
 */
export default function makeCryptoWith(opts) {

  _validateOpts(opts);
  const { encryptionKey } = opts;

  async function encrypt(input, aad) {
    _validateAAD(aad);
    const salt = _generateSalt();

    return Promise.all([
      _serialize(input),
      _generateIV(),
      _generateKey(encryptionKey, salt)
    ])
    .then(results => {
      const [ serializedInput, iv, key ] = results;
      const cipher = crypto.createCipheriv(CIPHER_ALGORITHM, key, iv);

      if(aad != null) {
        cipher.setAAD(Buffer.from(aad, 'utf8'));
      }

      const encrypted = Buffer.concat([cipher.update(serializedInput, 'utf8'), cipher.final()]);
      const tag = cipher.getAuthTag();

      return Buffer.concat([salt, iv, tag, encrypted]).toString(ENCRYPTION_RESULT_ENCODING);
    });
  }

  async function decrypt(output, aad) {
    _validateAAD(aad);
    const outputBytes = new Buffer(output, ENCRYPTION_RESULT_ENCODING);

    const salt = outputBytes.slice(0, SALT_LENGTH_IN_BYTES);
    const iv = outputBytes.slice(SALT_LENGTH_IN_BYTES, SALT_LENGTH_IN_BYTES + IV_LENGTH_IN_BYTES);
    const tag = outputBytes.slice(SALT_LENGTH_IN_BYTES + IV_LENGTH_IN_BYTES, SALT_LENGTH_IN_BYTES + IV_LENGTH_IN_BYTES + 16); // Auth tag is always 16 bytes long
    const text = outputBytes.slice(SALT_LENGTH_IN_BYTES + IV_LENGTH_IN_BYTES + 16);

    const key = await _generateKey(encryptionKey, salt);
    const decipher = crypto.createDecipheriv(CIPHER_ALGORITHM, key, iv);
    decipher.setAuthTag(tag);

    if(aad != null) {
      decipher.setAAD(Buffer.from(aad, 'utf8'));
    }

    const decrypted = decipher.update(text, 'binary', 'utf8') + decipher.final('utf8');
    return JSON.parse(decrypted);
  }

  return {
    encrypt,
    decrypt
  };
}

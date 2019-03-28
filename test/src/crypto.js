import expect from 'expect.js';
import sinon from 'sinon';
import makeCryptoWith from '../../lib/crypto';

describe('crypto', () => {
  let crypto;

  beforeEach(() => {
    const opts = {
      encryptionKey: 'no wifi on this plane :('
    };
    crypto = makeCryptoWith(opts);
  });

  describe('encrypt()', () => {
    it ('fails if given an object that is not serializable', async () => {

      try {
        const testObj = () => 'I am a function';
        await crypto.encrypt(testObj);
        throw new Error('Encryption should fail');
      } catch (err) {
        expect(err).to.be.an(Error);
        expect(err.message).to.match(/Object to be encrypted must be serializable/);
      }

    });
  });

  describe('encrypt() and decrypt()', () => {

    it ('can handle strings', async () => {
      const testObj = 'I am a string';

      const encrypted = await crypto.encrypt(testObj);
      const decrypted = await crypto.decrypt(encrypted);

      expect(decrypted).to.eql(testObj);
    });

    it ('can handle numbers', async () => {
      const testObj = 234391265392819463321;

      const encrypted = await crypto.encrypt(testObj);
      const decrypted = await crypto.decrypt(encrypted);

      expect(decrypted).to.eql(testObj);
    });

    it ('can handle booleans', async () => {
      const testObj = false;

      const encrypted = await crypto.encrypt(testObj);
      const decrypted = await crypto.decrypt(encrypted);

      expect(decrypted).to.eql(testObj);
    });

    it ('can handle arrays', async () => {
      const testObj = [ 173, 'foo', false, { bar: 'baz' } ];

      const encrypted = await crypto.encrypt(testObj);
      const decrypted = await crypto.decrypt(encrypted);

      expect(decrypted).to.eql(testObj);
    });

    it ('can handle objects', async () => {
      const testObj = {
        aNumber: 17,
        aString: 'baz',
        anArray: [ 19, 23 ],
        aBoolean: true
      };

      const encrypted = await crypto.encrypt(testObj);
      const decrypted = await crypto.decrypt(encrypted);

      expect(decrypted).to.eql(testObj);
    });

  });

  describe('decrypt()', () => {
    it ('fails when its input contains a modified salt', async () => {
      const testObj = 'I am a string';

      const encrypted = await crypto.encrypt(testObj);
      const encryptedBytes = new Buffer(encrypted);
      const encryptedBytesWithModifiedSalt = encryptedBytes.fill('s', 0, 64); // salt is 64 bytes long starting at byte 0

      try {
        await crypto.decrypt(encryptedBytesWithModifiedSalt);
        throw new Error('Encryption should fail');
      } catch (err) {
        expect(err).to.be.an(Error);
        expect(err.message).to.match(/Unsupported state or unable to authenticate data/);
      }
    });

    it ('fails when its input contains a modified IV', async () => {
      const testObj = 'I am a string';

      const encrypted = await crypto.encrypt(testObj);
      const encryptedBytes = new Buffer(encrypted);
      const encryptedBytesWithModifiedIV = encryptedBytes.fill('i', 64, 76); // iv is 12 bytes long, starting a byte 64

      try {
        await crypto.decrypt(encryptedBytesWithModifiedIV);
        throw new Error('Encryption should fail');
      } catch (err) {
        expect(err).to.be.an(Error);
        expect(err.message).to.match(/Unsupported state or unable to authenticate data/);
      }
    });

    it ('fails when its input contains a modified auth tag', async () => {
      const testObj = 'I am a string';

      const encrypted = await crypto.encrypt(testObj);
      const encryptedBytes = new Buffer(encrypted);
      const encryptedBytesWithModifiedAuthTag = encryptedBytes.fill('i', 76, 92); // auth tag is 16 bytes long, starting a byte 76

      try {
        await crypto.decrypt(encryptedBytesWithModifiedAuthTag);
        throw new Error('Encryption should fail');
      } catch (err) {
        expect(err).to.be.an(Error);
        expect(err.message).to.match(/Unsupported state or unable to authenticate data/);
      }
    });

    it ('fails when its input contains a modified encrypted value', async () => {
      const testObj = 'I am a string';

      const encrypted = await crypto.encrypt(testObj);
      const encryptedBytes = new Buffer(encrypted);
      const encryptedBytesWithModifiedEncryptedValue = encryptedBytes.fill('i', 92); // encrypted value starts at byte 92

      try {
        await crypto.decrypt(encryptedBytesWithModifiedEncryptedValue);
        throw new Error('Encryption should fail');
      } catch (err) {
        expect(err).to.be.an(Error);
        expect(err.message).to.match(/Unsupported state or unable to authenticate data/);
      }
    });
  });

  describe('backwards compatibility break test', () => {
    it ('correctly decrypts a encrypted string literal', async () => {
      const encrypted = 'GxM6gGXoR9z+/B4wBjI1dp0B8pcE1+nfyEqIKanp45Ec0QV1eGp6821Xc2IGAnGeYGq9RbdHxYe+yBG4uykPNH8NNdSiNoWKzjSyuYuvGYTgxeYwI3nMLo8y5WVxEWsO/Gn5VYDFG3xQYXg=';
      expect(await crypto.decrypt(encrypted)).to.be('I am a string');
    });
  });

  describe('Using AAD', () => {
    it('should decryptable with same AAD', async () => {
      const encrypted = await crypto.encrypt('Hello World!', 'some aad');

      const decrypted = await crypto.decrypt(encrypted, 'some aad');
      expect(decrypted).to.be.equal('Hello World!');
    });

    it('should not be decryptable without aad used in encryption', async () => {
      const encrypted = await crypto.encrypt('Hello World!', 'some aad');
      try {
        const decrypted = await crypto.decrypt(encrypted);
        throw new Error(`Decryption should fail but value was ${decrypted}`);
      }catch(err) {
        expect(err).to.be.an(Error);
        expect(err.message).to.match(/Unsupported state or unable to authenticate data/);
      }
    });
  });
});

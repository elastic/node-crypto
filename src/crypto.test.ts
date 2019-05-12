import makeCryptoWith, { Crypto } from './crypto';

describe('crypto', () => {
  let crypto: Crypto;

  beforeEach(() => {
    const opts = {
      encryptionKey: 'no wifi on this plane :(',
    };
    crypto = makeCryptoWith(opts);
  });

  describe('encrypt()', () => {
    it('fails if given an object that is not serializable', async () => {
      const testObj = () => 'I am a function';
      await expect(crypto.encrypt(testObj)).rejects.toThrow(
        /Object to be encrypted must be serializable/
      );
    });
  });

  describe('encrypt() and decrypt()', () => {
    it('can handle strings', async () => {
      const testObj = 'I am a string';

      const encrypted = await crypto.encrypt(testObj);
      const decrypted = await crypto.decrypt(encrypted);

      expect(decrypted).toEqual(testObj);
    });

    it('can handle numbers', async () => {
      const testObj = 234391265392819463321;

      const encrypted = await crypto.encrypt(testObj);
      const decrypted = await crypto.decrypt(encrypted);

      expect(decrypted).toEqual(testObj);
    });

    it('can handle booleans', async () => {
      const testObj = false;

      const encrypted = await crypto.encrypt(testObj);
      const decrypted = await crypto.decrypt(encrypted);

      expect(decrypted).toEqual(testObj);
    });

    it('can handle arrays', async () => {
      const testObj = [173, 'foo', false, { bar: 'baz' }];

      const encrypted = await crypto.encrypt(testObj);
      const decrypted = await crypto.decrypt(encrypted);

      expect(decrypted).toEqual(testObj);
    });

    it('can handle objects', async () => {
      const testObj = {
        aNumber: 17,
        aString: 'baz',
        anArray: [19, 23],
        aBoolean: true,
      };

      const encrypted = await crypto.encrypt(testObj);
      const decrypted = await crypto.decrypt(encrypted);

      expect(decrypted).toEqual(testObj);
    });
  });

  describe('decrypt()', () => {
    it('fails when its input contains a modified salt', async () => {
      const testObj = 'I am a string';

      const encrypted = await crypto.encrypt(testObj);
      const encryptedBytes = new Buffer(encrypted);
      const encryptedBytesWithModifiedSalt = encryptedBytes.fill('s', 0, 64); // salt is 64 bytes long starting at byte 0

      await expect(crypto.decrypt(encryptedBytesWithModifiedSalt)).rejects.toThrow(
        /Unsupported state or unable to authenticate data/
      );
    });

    it('fails when its input contains a modified IV', async () => {
      const testObj = 'I am a string';

      const encrypted = await crypto.encrypt(testObj);
      const encryptedBytes = new Buffer(encrypted);
      const encryptedBytesWithModifiedIV = encryptedBytes.fill('i', 64, 76); // iv is 12 bytes long, starting a byte 64

      await expect(crypto.decrypt(encryptedBytesWithModifiedIV)).rejects.toThrow(
        /Unsupported state or unable to authenticate data/
      );
    });

    it('fails when its input contains a modified auth tag', async () => {
      const testObj = 'I am a string';

      const encrypted = await crypto.encrypt(testObj);
      const encryptedBytes = new Buffer(encrypted);
      const encryptedBytesWithModifiedAuthTag = encryptedBytes.fill('i', 76, 92); // auth tag is 16 bytes long, starting a byte 76

      await expect(crypto.decrypt(encryptedBytesWithModifiedAuthTag)).rejects.toThrow(
        /Unsupported state or unable to authenticate data/
      );
    });

    it('fails when its input contains a modified encrypted value', async () => {
      const testObj = 'I am a string';

      const encrypted = await crypto.encrypt(testObj);
      const encryptedBytes = new Buffer(encrypted);
      const encryptedBytesWithModifiedEncryptedValue = encryptedBytes.fill('i', 92); // encrypted value starts at byte 92

      await expect(crypto.decrypt(encryptedBytesWithModifiedEncryptedValue)).rejects.toThrow(
        /Unsupported state or unable to authenticate data/
      );
    });
  });

  describe('backwards compatibility break test', () => {
    it('correctly decrypts a encrypted string literal', async () => {
      const encrypted =
        'GxM6gGXoR9z+/B4wBjI1dp0B8pcE1+nfyEqIKanp45Ec0QV1eGp6821Xc2IGAnGeYGq9RbdHxYe+yBG4uykPNH8NNdSiNoWKzjSyuYuvGYTgxeYwI3nMLo8y5WVxEWsO/Gn5VYDFG3xQYXg=';
      expect(await crypto.decrypt(encrypted)).toBe('I am a string');
    });
  });

  describe('Using AAD', () => {
    describe('type validation', () => {
      describe('for encrypt', () => {
        it('should throw an error if aad is empty string', async () => {
          await expect(crypto.encrypt('Hello World!', '')).rejects.toThrowError(
            /AAD cannot be an empty string/
          );
        });

        it('should be valid for string', async () => {
          const encrypted = await crypto.encrypt('Hello World!', 'should succeed');
          expect(encrypted).not.toBeUndefined();
          expect(encrypted).not.toEqual('Hello World!');
        });

        it('should throw an error if AAD is an Array', async () => {
          const aad = ['a', 'b'] as any;
          await expect(crypto.encrypt('Hello World!', aad)).rejects.toThrowError(
            /AAD must be a string/
          );
        });

        it('should throw an error if AAD is an Object', async () => {
          const aad = {} as any;
          await expect(crypto.encrypt('Hello World!', aad)).rejects.toThrowError(
            /AAD must be a string/
          );
        });

        it('should throw an error if AAD is an function', async () => {
          /* tslint:disable:no-empty */
          const aad = (() => {}) as any;
          await expect(crypto.encrypt('Hello World!', aad)).rejects.toThrowError(
            /AAD must be a string/
          );
        });
      });

      describe('for decrypt', () => {
        const encrypted =
          'ImI9iJzw8dc3g47sM0fdJTa1+N+h9EI12kzFt1dzewuKx4E3rO6d6lqH+VSYNAf1H3m9HX/SFb0ZeJBx06NtERF2j9rY+1PtrOkJQfQCqnVC1PdlguZAMTG38vEfKBMgrJiK2+fqBFH80A==';

        it('should throw an error if aad is empty string', async () => {
          await expect(crypto.decrypt(encrypted, '')).rejects.toThrowError(
            /AAD cannot be an empty string/
          );
        });

        it('should be valid for string', async () => {
          const decrypted = await crypto.decrypt(encrypted, 'should succeed');
          expect(decrypted).not.toBeUndefined();
          expect(decrypted).toEqual('Hello World!');
        });

        it('should throw an error if AAD is an Array', async () => {
          const aad = ['a', 'b'] as any;
          await expect(crypto.decrypt(encrypted, aad)).rejects.toThrowError(/AAD must be a string/);
        });

        it('should throw an error if AAD is an Object', async () => {
          const aad = {} as any;
          await expect(crypto.decrypt(encrypted, aad)).rejects.toThrowError(/AAD must be a string/);
        });

        it('should throw an error if AAD is an function', async () => {
          /* tslint:disable:no-empty */
          const aad = (() => {}) as any;
          await expect(crypto.decrypt(encrypted, aad)).rejects.toThrowError(/AAD must be a string/);
        });
      });
    });

    it('should be decryptable with same AAD', async () => {
      const encrypted = await crypto.encrypt('Hello World!', 'some aad');

      const decrypted = await crypto.decrypt(encrypted, 'some aad');
      expect(decrypted).toEqual('Hello World!');
    });

    it('should not be decryptable without aad used in encryption', async () => {
      const encrypted = await crypto.encrypt('Hello World!', 'some aad');
      await expect(crypto.decrypt(encrypted)).rejects.toThrowError(
        /Unsupported state or unable to authenticate data/
      );
    });

    it('should not be decryptable with the wrong aad', async () => {
      const encrypted = await crypto.encrypt('Hello World!', '123456789');
      await expect(crypto.decrypt(encrypted, '123456780')).rejects.toThrowError(
        /Unsupported state or unable to authenticate data/
      );
    });
  });
});

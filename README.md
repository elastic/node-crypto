# node-crypto

<p align="center">
  Easy (yet strong) encryption and decryption facilities for Node.js
</p>

<p align="center">
  <a href="https://badge.fury.io/js/%40elastic%2Fnode-crypto"><img src="https://badge.fury.io/js/%40elastic%2Fnode-crypto.svg" alt="npm version" height="18"></a>
  <a href="https://codecov.io/gh/elastic/node-crypto"><img src="https://codecov.io/gh/elastic/node-crypto/branch/master/graph/badge.svg" /></a>
  <a href="https://travis-ci.org/elastic/node-crypto"><img src="https://travis-ci.org/elastic/node-crypto.svg?branch=master"></a>
</p>

This node module that can be used for easily encrypting and decrypting serializable objects. The ease-of-use comes from the fact that this module is opinionated in its (strong) choice of cryptographic algorithms, lengths, and iterations that cannot be overriden by its users.

Currently, all versions of this library are able to decrypt secrets encrypted with previous versions. However, version 1.0.0 introduced the ability to use an optional AAD when encrypting/decrypting secrets.

## Maintainers Notes

If you change encryption parameters so that the encrypted result is different from what the current latest release of this library would produce, make sure to bump up the major version of the library before releasing it and ensure that you disclose this breaking change.

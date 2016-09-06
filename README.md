# node-crypto
Easy (yet strong) encryption and decryption facilities for Node.js

This node module that can be used for easily encrypting and decrypting serializable objects. The ease-of-use comes from the fact that this module is opinionated in its (strong) choice of cryptographic algorithms, lengths, and iterations that cannot be overriden by its users.

Note: strings encrypted with one major version of this library can only be decrypted by the same major version of the library.

## cose-to-jwk

[![Build Status](https://travis-ci.org/apowers313/cose-to-jwk.svg?branch=master)](https://travis-ci.org/apowers313/cose-to-jwk) [![Coverage Status](https://coveralls.io/repos/github/apowers313/cose-to-jwk/badge.svg?branch=master)](https://coveralls.io/github/apowers313/cose-to-jwk?branch=master)

This was created to convert [CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152) to [JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517). I specifically needed this for [WebAuthn](https://www.w3.org/TR/webauthn/) and I'm using it with [jwk-to-pem](https://www.npmjs.com/package/jwk-to-pem) to create PEM strings that work with [Node.js's Crypto library](https://nodejs.org/api/crypto.html).

## Example

``` js
const coseToJwk = require("cose-to-jwk");

// Buffer, ArrayBuffer, Uint8Array, etc. also accepted
const coseArray = [
    0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0xBB, 0x11, 0xCD, 0xDD, 0x6E, 0x9E,
    0x86, 0x9D, 0x15, 0x59, 0x72, 0x9A, 0x30, 0xD8, 0x9E, 0xD4, 0x9F, 0x36, 0x31, 0x52, 0x42, 0x15,
    0x96, 0x12, 0x71, 0xAB, 0xBB, 0xE2, 0x8D, 0x7B, 0x73, 0x1F, 0x22, 0x58, 0x20, 0xDB, 0xD6, 0x39,
    0x13, 0x2E, 0x2E, 0xE5, 0x61, 0x96, 0x5B, 0x83, 0x05, 0x30, 0xA6, 0xA0, 0x24, 0xF1, 0x09, 0x88,
    0x88, 0xF3, 0x13, 0x55, 0x05, 0x15, 0x92, 0x11, 0x84, 0xC8, 0x6A, 0xCA, 0xC3
];

var jwk = coseToJwk(coseArray);
```

Notes:
* This currently only supports ECDSA and RSA. GitHub pull requests or issues for other crypto suites are welcome.
* This doesn't do any other COSE things (signing, decrypting, etc.)
* This could probably use more testing (although it's not very sophisticated)
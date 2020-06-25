/// <reference path="../index.d.ts" />

import * as webcrypto from "webcrypto-core";

WebcryptoCore.SubtleCrypto;

let subtle = new webcrypto.SubtleCrypto();
subtle.digest("SHA-1", new Uint8Array(16))
    .then(digest =>
        console.log(new Uint8Array(digest))
    );
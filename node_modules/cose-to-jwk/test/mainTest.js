"use strict";

const coseToJwk = require("../cose-to-jwk");
const algToStr = coseToJwk.algToStr;
const algToHashStr = coseToJwk.algToHashStr;
const assert = require("chai").assert;

const coseArray = [
    0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0xBB, 0x11, 0xCD, 0xDD, 0x6E, 0x9E,
    0x86, 0x9D, 0x15, 0x59, 0x72, 0x9A, 0x30, 0xD8, 0x9E, 0xD4, 0x9F, 0x36, 0x31, 0x52, 0x42, 0x15,
    0x96, 0x12, 0x71, 0xAB, 0xBB, 0xE2, 0x8D, 0x7B, 0x73, 0x1F, 0x22, 0x58, 0x20, 0xDB, 0xD6, 0x39,
    0x13, 0x2E, 0x2E, 0xE5, 0x61, 0x96, 0x5B, 0x83, 0x05, 0x30, 0xA6, 0xA0, 0x24, 0xF1, 0x09, 0x88,
    0x88, 0xF3, 0x13, 0x55, 0x05, 0x15, 0x92, 0x11, 0x84, 0xC8, 0x6A, 0xCA, 0xC3
];

const xArray = [
    0xbb, 0x11, 0xcd, 0xdd, 0x6e, 0x9e, 0x86, 0x9d, 0x15, 0x59, 0x72, 0x9a, 0x30, 0xd8, 0x9e, 0xd4,
    0x9f, 0x36, 0x31, 0x52, 0x42, 0x15, 0x96, 0x12, 0x71, 0xab, 0xbb, 0xe2, 0x8d, 0x7b, 0x73, 0x1f
];

const yArray = [
    0xdb, 0xd6, 0x39, 0x13, 0x2e, 0x2e, 0xe5, 0x61, 0x96, 0x5b, 0x83, 0x05, 0x30, 0xa6, 0xa0, 0x24,
    0xf1, 0x09, 0x88, 0x88, 0xf3, 0x13, 0x55, 0x05, 0x15, 0x92, 0x11, 0x84, 0xc8, 0x6a, 0xca, 0xc3
];

const coseArray2 = [
    0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0x4A, 0x7F, 0xC2, 0xCB, 0xB2, 0xB6,
    0xE0, 0x3B, 0x5B, 0x17, 0x0C, 0x85, 0x66, 0x3E, 0xFB, 0x92, 0x3D, 0x08, 0xBC, 0x17, 0xAA, 0x92,
    0x61, 0x48, 0x3D, 0xDB, 0x4A, 0xEA, 0x03, 0x8E, 0x66, 0x5C, 0x22, 0x58, 0x20, 0xE6, 0xE9, 0x0D,
    0xA0, 0x5A, 0xD4, 0xEA, 0xD5, 0x56, 0xD8, 0x75, 0xA4, 0x8C, 0xB2, 0x46, 0xB1, 0xE6, 0x2D, 0x10,
    0x5F, 0x17, 0x35, 0x94, 0x3B, 0xA4, 0x94, 0x0E, 0xFD, 0xFD, 0xD5, 0x5D, 0x4B,
];

const xArray2 = [
    0x4A, 0x7F, 0xC2, 0xCB, 0xB2, 0xB6, 0xE0, 0x3B, 0x5B, 0x17, 0x0C, 0x85, 0x66, 0x3E, 0xFB, 0x92,
    0x3D, 0x08, 0xBC, 0x17, 0xAA, 0x92, 0x61, 0x48, 0x3D, 0xDB, 0x4A, 0xEA, 0x03, 0x8E, 0x66, 0x5C
];
const x2base64 = "Sn/Cy7K24DtbFwyFZj77kj0IvBeqkmFIPdtK6gOOZlw=";

const yArray2 = [
    0xE6, 0xE9, 0x0D, 0xA0, 0x5A, 0xD4, 0xEA, 0xD5, 0x56, 0xD8, 0x75, 0xA4, 0x8C, 0xB2, 0x46, 0xB1,
    0xE6, 0x2D, 0x10, 0x5F, 0x17, 0x35, 0x94, 0x3B, 0xA4, 0x94, 0x0E, 0xFD, 0xFD, 0xD5, 0x5D, 0x4B
];
const y2base64 = "5ukNoFrU6tVW2HWkjLJGseYtEF8XNZQ7pJQO/f3VXUs=";

const expectedX = Buffer.from(xArray);
const expectedY = Buffer.from(yArray);

const coseBuffer = Buffer.from(coseArray);
const coseUint8Array = new Uint8Array(coseBuffer);
const coseUint16Array = new Uint16Array(coseBuffer);
const coseArrayBuffer = coseUint8Array.buffer;

function bufComp(a, b) {
    var len = a.length;

    if (len !== b.length) {
        return false;
    }

    for (var i = 0; i < len; i++) {
        if (a.readUInt8(i) !== b.readUInt8(i)) {
            return false;
        }
    }

    return true;
}


describe("cose-to-jwk", function() {
    it("error checking");

    it("can convert ArrayBuffer", function() {
        var ret = coseToJwk(coseArrayBuffer);
        assert.instanceOf(ret, Object);
        assert.strictEqual(ret.kty, "EC");
        assert.strictEqual(ret.crv, "P-256");
        assert.strictEqual(ret.x, "uxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8=");
        assert.strictEqual(ret.y, "29Y5Ey4u5WGWW4MFMKagJPEJiIjzE1UFFZIRhMhqysM=");
    });

    it("can convert Uint8Array", function() {
        var ret = coseToJwk(coseUint8Array);
        assert.instanceOf(ret, Object);
        assert.strictEqual(ret.kty, "EC");
        assert.strictEqual(ret.crv, "P-256");
        assert.strictEqual(ret.x, "uxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8=");
        assert.strictEqual(ret.y, "29Y5Ey4u5WGWW4MFMKagJPEJiIjzE1UFFZIRhMhqysM=");
    });

    it.skip("can convert Uint16Array", function() {
        var ret = coseToJwk(coseUint16Array);
        assert.instanceOf(ret, Object);
        assert.strictEqual(ret.kty, "EC");
        assert.strictEqual(ret.crv, "P-256");
        assert.strictEqual(ret.x, "uxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8=");
        assert.strictEqual(ret.y, "29Y5Ey4u5WGWW4MFMKagJPEJiIjzE1UFFZIRhMhqysM=");
    });

    it("can convert Array", function() {
        var ret = coseToJwk(coseArray);
        assert.instanceOf(ret, Object);
        assert.strictEqual(ret.kty, "EC");
        assert.strictEqual(ret.crv, "P-256");
        assert.strictEqual(ret.x, "uxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8=");
        assert.strictEqual(ret.y, "29Y5Ey4u5WGWW4MFMKagJPEJiIjzE1UFFZIRhMhqysM=");
    });

    it("ECDSA", function() {
        var ret = coseToJwk(coseBuffer);
        assert.instanceOf(ret, Object);
        assert.strictEqual(ret.kty, "EC");
        assert.strictEqual(ret.crv, "P-256");
        assert.strictEqual(ret.x, "uxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8=");
        assert.strictEqual(ret.y, "29Y5Ey4u5WGWW4MFMKagJPEJiIjzE1UFFZIRhMhqysM=");

        var x = Buffer.from(ret.x, "base64");
        var y = Buffer.from(ret.y, "base64");

        assert(bufComp(x, expectedX), "ECDSA x bytes are correct");
        assert(bufComp(y, expectedY), "ECDSA y bytes are correct");
    });

    it("can convert Array2", function() {
        var ret = coseToJwk(coseArray2);
        assert.instanceOf(ret, Object);
        assert.strictEqual(ret.kty, "EC");
        assert.strictEqual(ret.crv, "P-256");
        assert.strictEqual(ret.x, x2base64);
        assert.strictEqual(ret.y, y2base64);

        var x = Buffer.from(ret.x, "base64");
        var y = Buffer.from(ret.y, "base64");
        const expectedX2 = Buffer.from(xArray2);
        const expectedY2 = Buffer.from(yArray2);

        assert(bufComp(x, expectedX2), "ECDSA x bytes are correct");
        assert(bufComp(y, expectedY2), "ECDSA y bytes are correct");
    });

    it("can convert RSASSA PKCS1 w/ SHA256", function() {
        var rsaSsaPkcs1 = new Uint8Array([
            0xA4, 0x01, 0x03, 0x03, 0x39, 0x01, 0x00, 0x20, 0x59, 0x01, 0x00, 0xC5, 0xDA, 0x6F, 0x4D, 0x93,
            0x57, 0xBD, 0xE2, 0x02, 0xF5, 0xC5, 0x58, 0xCD, 0x0A, 0x31, 0x56, 0xD2, 0x54, 0xF2, 0xE0, 0xAD,
            0x9A, 0xB5, 0x79, 0x31, 0xF9, 0x82, 0x6B, 0x74, 0x7D, 0xE1, 0xAC, 0x4F, 0x29, 0xD6, 0x07, 0x08,
            0x74, 0xDC, 0xE5, 0x79, 0x10, 0xE1, 0x98, 0x44, 0x49, 0x9D, 0x8E, 0x42, 0x47, 0x03, 0x39, 0xB1,
            0x70, 0xD0, 0x22, 0xB5, 0x01, 0xAB, 0x88, 0xE9, 0xC2, 0xF4, 0xED, 0x30, 0x2E, 0x47, 0x19, 0xC7,
            0x0D, 0xEB, 0xE8, 0x84, 0x24, 0x03, 0xED, 0x9B, 0xDF, 0xC2, 0x27, 0x30, 0xA6, 0x1A, 0x1B, 0x70,
            0xF6, 0x16, 0xC5, 0xF1, 0xB7, 0x00, 0xCA, 0xCF, 0x78, 0x46, 0x13, 0x7D, 0xC4, 0xB2, 0xD4, 0x69,
            0xA8, 0xE1, 0x5A, 0xAB, 0x4F, 0xAD, 0x86, 0x57, 0x08, 0x40, 0x22, 0xD2, 0x8F, 0x44, 0xD9, 0x07,
            0x53, 0x23, 0x12, 0x6B, 0x70, 0x07, 0xC9, 0x81, 0x93, 0x9F, 0xDF, 0x72, 0x4C, 0xAF, 0x4F, 0xBE,
            0x47, 0x50, 0x40, 0x43, 0x1A, 0x4E, 0xA0, 0x64, 0x43, 0x0B, 0xCB, 0x2C, 0xFA, 0xD7, 0xD0, 0x5B,
            0xDB, 0x9F, 0x64, 0xB5, 0xB0, 0xE0, 0x95, 0x2E, 0xCF, 0x86, 0x79, 0x27, 0x3D, 0x6C, 0x6D, 0xFA,
            0x81, 0x60, 0x1F, 0x14, 0x50, 0x33, 0x16, 0xA1, 0x3D, 0x07, 0x82, 0xC3, 0x1A, 0x3E, 0x6B, 0xDD,
            0xED, 0x3D, 0x7B, 0xC4, 0x6B, 0xC1, 0xFA, 0x9B, 0xEF, 0x0D, 0xFF, 0x83, 0xB7, 0xDE, 0xAF, 0x14,
            0x6B, 0x58, 0x2C, 0x46, 0x44, 0x82, 0x1A, 0x3C, 0x62, 0xED, 0xBA, 0xA6, 0xBE, 0x42, 0x2B, 0xF0,
            0x4E, 0x43, 0xED, 0xAF, 0x5F, 0xD3, 0x78, 0x30, 0x86, 0x15, 0x3D, 0x73, 0x61, 0xA2, 0x03, 0x06,
            0x1A, 0x62, 0x98, 0xAB, 0x26, 0xE1, 0x33, 0x7C, 0xA1, 0xC9, 0xED, 0x06, 0x74, 0x1A, 0x59, 0x05,
            0x47, 0x79, 0x88, 0xE7, 0x20, 0x30, 0x4E, 0xAE, 0x18, 0x9D, 0x7F, 0x21, 0x43, 0x01, 0x00, 0x01,
        ]).buffer;
        var ret = coseToJwk(rsaSsaPkcs1);
        assert.instanceOf(ret, Object);
        assert.strictEqual(ret.kty, "RSA");
        assert.strictEqual(ret.alg, "RSASSA-PKCS1-v1_5_w_SHA256");
        assert.strictEqual(ret.n, "xdpvTZNXveIC9cVYzQoxVtJU8uCtmrV5MfmCa3R94axPKdYHCHTc5XkQ4ZhESZ2OQkcDObFw0CK1AauI6cL07TAuRxnHDevohCQD7ZvfwicwphobcPYWxfG3AMrPeEYTfcSy1Gmo4VqrT62GVwhAItKPRNkHUyMSa3AHyYGTn99yTK9PvkdQQEMaTqBkQwvLLPrX0Fvbn2S1sOCVLs+GeSc9bG36gWAfFFAzFqE9B4LDGj5r3e09e8Rrwfqb7w3/g7ferxRrWCxGRIIaPGLtuqa+QivwTkPtr1/TeDCGFT1zYaIDBhpimKsm4TN8ocntBnQaWQVHeYjnIDBOrhidfw==");
        assert.strictEqual(ret.e, "AQAB");
    });
});

describe("algToStr", function() {
    it("error checking");

    it("ECDSA_w_SHA256", function() {
        var ret = algToStr(-7);
        assert.strictEqual(ret, "ECDSA_w_SHA256");
    });

    it("EdDSA", function() {
        var ret = algToStr(-8);
        assert.strictEqual(ret, "EdDSA");
    });

    it("ECDSA_w_SHA384", function() {
        var ret = algToStr(-35);
        assert.strictEqual(ret, "ECDSA_w_SHA384");
    });

    it("ECDSA_w_SHA512", function() {
        var ret = algToStr(-36);
        assert.strictEqual(ret, "ECDSA_w_SHA512");
    });

    it("RSASSA-PKCS1-v1_5_w_SHA256", function() {
        var ret = algToStr(-257);
        assert.strictEqual(ret, "RSASSA-PKCS1-v1_5_w_SHA256");
    });

    it("RSASSA-PKCS1-v1_5_w_SHA384", function() {
        var ret = algToStr(-258);
        assert.strictEqual(ret, "RSASSA-PKCS1-v1_5_w_SHA384");
    });

    it("RSASSA-PKCS1-v1_5_w_SHA512", function() {
        var ret = algToStr(-259);
        assert.strictEqual(ret, "RSASSA-PKCS1-v1_5_w_SHA512");
    });

    it("RSASSA-PKCS1-v1_5_w_SHA1", function() {
        var ret = algToStr(-65535);
        assert.strictEqual(ret, "RSASSA-PKCS1-v1_5_w_SHA1");
    });
});

describe("algToHashStr", function() {
    it("error checking");

    it("ECDSA_w_SHA256", function() {
        var ret = algToHashStr("ECDSA_w_SHA256");
        assert.strictEqual(ret, "SHA256");
    });

    it("ECDSA_w_SHA256 (-7)", function() {
        var ret = algToHashStr(-7);
        assert.strictEqual(ret, "SHA256");
    });

    it.skip("EdDSA", function() {
        var ret = algToHashStr(-8);
        assert.strictEqual(ret, "EdDSA");
    });

    it.skip("EdDSA (-8)", function() {
        var ret = algToHashStr(-8);
        assert.strictEqual(ret, "EdDSA");
    });

    it("ECDSA_w_SHA384", function() {
        var ret = algToHashStr("ECDSA_w_SHA384");
        assert.strictEqual(ret, "SHA384");
    });

    it("ECDSA_w_SHA384 (-35)", function() {
        var ret = algToHashStr(-35);
        assert.strictEqual(ret, "SHA384");
    });

    it("ECDSA_w_SHA512", function() {
        var ret = algToHashStr("ECDSA_w_SHA512");
        assert.strictEqual(ret, "SHA512");
    });

    it("ECDSA_w_SHA512 (-36)", function() {
        var ret = algToHashStr(-36);
        assert.strictEqual(ret, "SHA512");
    });

    it("RSASSA-PKCS1-v1_5_w_SHA256", function() {
        var ret = algToHashStr("RSASSA-PKCS1-v1_5_w_SHA256");
        assert.strictEqual(ret, "SHA256");
    });

    it("RSASSA-PKCS1-v1_5_w_SHA256 (-257)", function() {
        var ret = algToHashStr(-257);
        assert.strictEqual(ret, "SHA256");
    });

    it("RSASSA-PKCS1-v1_5_w_SHA384", function() {
        var ret = algToHashStr("RSASSA-PKCS1-v1_5_w_SHA384");
        assert.strictEqual(ret, "SHA384");
    });

    it("RSASSA-PKCS1-v1_5_w_SHA384 (-258)", function() {
        var ret = algToHashStr(-258);
        assert.strictEqual(ret, "SHA384");
    });

    it("RSASSA-PKCS1-v1_5_w_SHA512", function() {
        var ret = algToHashStr("RSASSA-PKCS1-v1_5_w_SHA512");
        assert.strictEqual(ret, "SHA512");
    });

    it("RSASSA-PKCS1-v1_5_w_SHA512 (-259)", function() {
        var ret = algToHashStr(-259);
        assert.strictEqual(ret, "SHA512");
    });

    it("RSASSA-PKCS1-v1_5_w_SHA1", function() {
        var ret = algToHashStr("RSASSA-PKCS1-v1_5_w_SHA1");
        assert.strictEqual(ret, "SHA1");
    });

    it("RSASSA-PKCS1-v1_5_w_SHA1 (-65535)", function() {
        var ret = algToHashStr(-65535);
        assert.strictEqual(ret, "SHA1");
    });
});

var webcrypto = require("../");
var assert = require("assert");

var helper = require("./helper");
var generate = helper.generate;
var encrypt = helper.encrypt;
var exportKey = helper.exportKey;
var importKey = helper.importKey;
var wrapKey = helper.wrapKey;
var unwrapKey = helper.unwrapKey;

describe("Subtle", function () {

    context("AES", function () {

        var algs = ["AES-CBC", "AES-CTR", "AES-GCM", "AES-ECB"];
        algs.forEach(function (alg) {

            it(alg + " generate 128", function (done) {
                generate({ name: alg, length: 128 }, ["encrypt", "decrypt", "wrapKey", "unwrapKey"], done, false);
            });
            it(alg + " generate 192", function (done) {
                generate({ name: alg, length: 192 }, ["encrypt", "decrypt", "wrapKey", "unwrapKey"], done, false);
            });
            it(alg + " generate 256", function (done) {
                generate({ name: alg, length: 256 }, ["encrypt", "decrypt", "wrapKey", "unwrapKey"], done, false);
            });
            it(alg + " generate wrong key usage", function (done) {
                generate({ name: alg, length: 128 }, ["sign", "verify"], done, true);
            });
            it(alg + " generate 111, wrong length", function (done) {
                generate({ name: alg, length: 111 }, ["encrypt", "decrypt", "wrapKey", "unwrapKey"], done, true);
            });
            it(alg + " generate with wrong key usage", function (done) {
                generate({ name: alg, length: 256 }, ["sign"], done, true);
            });
            it(alg + " generate with key usage = null", function (done) {
                generate({ name: alg, length: 256 }, null, done, true);
            });
            it(alg + " generate with empty key usage", function (done) {
                generate({ name: alg, length: 256 }, [], done, true);
            });
            it(alg + " export raw", function (done) {
                var key = { algorithm: { name: alg }, type: "secret", extractable: true };
                exportKey("raw", key, done, false);
            });
            it(alg + " export jwk", function (done) {
                var key = { algorithm: { name: alg }, type: "secret", extractable: true };
                exportKey("jwk", key, done, false);
            });
            it(alg + " export pkcs8, wrong format", function (done) {
                var key = { algorithm: { name: alg }, type: "secret", extractable: true };
                exportKey("pkcs8", key, done, true);
            });
            it(alg + " import jwk", function (done) {
                var _alg = { name: alg };
                importKey("jwk", new Uint8Array(3), _alg, ["encrypt"], done, false);
            });
            it(alg + " import raw", function (done) {
                var _alg = { name: alg };
                importKey("raw", new Uint8Array(3), _alg, ["encrypt"], done, false);
            });
            it(alg + " import pkcs8, wrong format", function (done) {
                var _alg = { name: alg };
                importKey("pkcs8", new Uint8Array(3), _alg, ["encrypt"], done, true);
            });
            it(alg + " import raw, wrong key usage", function (done) {
                var _alg = { name: alg };
                importKey("raw", new Uint8Array(3), _alg, ["sign"], done, true);
            });
        });

        context("AES-ECB", () => {
            it("encrypt", (done) => {
                var alg = { name: "AES-ECB" };
                var key = {
                    algorithm: { name: "AES-ECB" },
                    type: "secret",
                    usages: ["encrypt"]
                };
                encrypt("encrypt", alg, key, done, false);
            });
            it("decrypt", (done) => {
                var alg = { name: "AES-ECB" };
                var key = {
                    algorithm: { name: "AES-ECB" },
                    type: "secret",
                    usages: ["decrypt"]
                };
                encrypt("decrypt", alg, key, done, false);
            });
        });

        context("AES-CBC encrypt", () => {
            it("ArrayBufferView", function (done) {
                var alg = { name: "AES-CBC", iv: new Uint8Array(16) };
                var key = {
                    algorithm: { name: "AES-CBC" },
                    type: "secret",
                    usages: ["encrypt"]
                };
                encrypt("encrypt", alg, key, done, false);
            });
            it("ArrayBuffer", function (done) {
                var alg = { name: "AES-CBC", iv: new ArrayBuffer(16) };
                var key = {
                    algorithm: { name: "AES-CBC" },
                    type: "secret",
                    usages: ["encrypt"]
                };
                encrypt("encrypt", alg, key, done, false);
            });
            it("Wrong iv", function (done) {
                var alg = { name: "AES-CBC", iv: [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6] };
                var key = {
                    algorithm: { name: "AES-CBC" },
                    type: "secret",
                    usages: ["encrypt"]
                };
                encrypt("encrypt", alg, key, done, true);
            });
        })
        context("AES-CBC decrypt", () => {
            it("ArrayBufferView", function (done) {
                var alg = { name: "AES-CBC", iv: new Uint16Array(8) };
                var key = {
                    algorithm: { name: "AES-CBC" },
                    type: "secret",
                    usages: ["decrypt"]
                };
                encrypt("decrypt", alg, key, done, false);
            });
            it("ArrayBufferView", function (done) {
                var alg = { name: "AES-CBC", iv: new ArrayBuffer(16) };
                var key = {
                    algorithm: { name: "AES-CBC" },
                    type: "secret",
                    usages: ["decrypt"]
                };
                encrypt("decrypt", alg, key, done, false);
            });
            it("wrong key", function (done) {
                var alg = { name: "AES-CBC", iv: new Uint8Array(16) };
                var key = {
                    algorithm: { name: "AES-GCM" },
                    type: "secret",
                    usages: ["decrypt"]
                };
                encrypt("decrypt", alg, key, done, true);
            });
            it("wrong alg param, iv size 15", function (done) {
                var alg = { name: "AES-CBC", iv: new Uint8Array(15) };
                var key = {
                    algorithm: { name: "AES-CBC" },
                    type: "secret",
                    usages: ["decrypt"]
                };
                encrypt("decrypt", alg, key, done, true);
            });
            it("wrong key usage", function (done) {
                var alg = { name: "AES-CBC", iv: new Uint8Array(16) };
                var key = {
                    algorithm: { name: "AES-CBC" },
                    type: "secret",
                    usages: ["unwrapKey"]
                };
                encrypt("decrypt", alg, key, done, true);
            });
        });
        context("AES-CTR encrypt", () => {
            it("counter - ArrayBufferView", function (done) {
                var alg = { name: "AES-CTR", counter: new Uint8Array(16), length: 1 };
                var key = {
                    algorithm: { name: "AES-CTR" },
                    type: "secret",
                    usages: ["encrypt"]
                };
                encrypt("encrypt", alg, key, done, false);
            });
            it("counter - ArrayBuffer", function (done) {
                var alg = { name: "AES-CTR", counter: new ArrayBuffer(16), length: 1 };
                var key = {
                    algorithm: { name: "AES-CTR" },
                    type: "secret",
                    usages: ["encrypt"]
                };
                encrypt("encrypt", alg, key, done, false);
            });
            it("counter - wrong type", function (done) {
                var alg = { name: "AES-CTR", counter: "1234567890123456", length: 1 };
                var key = {
                    algorithm: { name: "AES-CTR" },
                    type: "secret",
                    usages: ["encrypt"]
                };
                encrypt("encrypt", alg, key, done, true);
            });
            it("counter - size is not 16", function (done) {
                var alg = { name: "AES-CTR", counter: new ArrayBuffer(15), length: 1 };
                var key = {
                    algorithm: { name: "AES-CTR" },
                    type: "secret",
                    usages: ["encrypt"]
                };
                encrypt("encrypt", alg, key, done, true);
            });
        })
        context("AES-CTR decrypt", () => {
            it("counter - ArrayBufferView", function (done) {
                var alg = { name: "AES-CTR", counter: new Uint8Array(16), length: 1 };
                var key = {
                    algorithm: { name: "AES-CTR" },
                    type: "secret",
                    usages: ["decrypt"]
                };
                encrypt("decrypt", alg, key, done, false);
            });
            it("counter - ArrayBuffer", function (done) {
                var alg = { name: "AES-CTR", counter: new ArrayBuffer(16), length: 1 };
                var key = {
                    algorithm: { name: "AES-CTR" },
                    type: "secret",
                    usages: ["decrypt"]
                };
                encrypt("decrypt", alg, key, done, false);
            });
            it("wrong alg param, length", function (done) {
                var alg = { name: "AES-CTR", counter: new Uint8Array(16), length: -1 };
                var key = {
                    algorithm: { name: "AES-CTR" },
                    type: "secret",
                    usages: ["decrypt"]
                };
                encrypt("decrypt", alg, key, done, true);
            });
        });

        it("AES-CTR wrapKey", function (done) {
            var alg = { name: "AES-CTR", counter: new Uint8Array(16), length: 1 };
            var key = {
                algorithm: { name: "AES-CTR" },
                type: "secret",
                usages: ["wrapKey"]
            };
            var wkey = {
                algorithm: { name: "RSA-OAEP", hash: "SHA-1", length: 16 },
                type: "secret",
                extractable: true,
                usages: ["encrypt"]
            };
            wrapKey("jwk", alg, wkey, key, done, false);
        });

        it("AES-CTR unwrapKey", function (done) {
            var alg = { name: "AES-CTR", counter: new Uint8Array(16), length: 1 };
            var kalg = { name: "RSA-OAEP", hash: "SHA-1" };
            var key = {
                algorithm: { name: "AES-CTR" },
                type: "secret",
                usages: ["unwrapKey"]
            };
            var wkey = new Uint8Array(19);
            unwrapKey("jwk", wkey, key, alg, kalg, true, ["encrypt"], done, false);
        });

        context("AES-CBC", () => {
            var AesCBC = webcrypto.AesCBC;

            context("checkAlgorithmParams", () => {

                it("correct", () => {
                    AesCBC.checkAlgorithmParams({ name: "AES-CBC", iv: new Uint8Array(16) });
                });

                it("empty iv", () => {
                    assert.throws(() => AesCBC.checkAlgorithmParams({ name: "AES-CBC" }), Error);
                });

                it("wrong iv length", () => {
                    assert.throws(() => AesCBC.checkAlgorithmParams({ name: "AES-CBC", iv: new Uint8Array(20) }), Error);
                });
                it("wrong iv data", () => {
                    assert.throws(() => AesCBC.checkAlgorithmParams({ name: "AES-CBC", iv: "wrong" }), Error);
                });

            })

        });

        context("AES-CTR", () => {
            var AesCTR = webcrypto.AesCTR;

            context("checkAlgorithmParams", () => {

                it("wrong counter data", () => {
                    assert.throws(() => AesCTR.checkAlgorithmParams({ name: "AES-CTR", counter: "wrong" }), Error);
                });

            })

        });

        context("AES-GCM", () => {
            var AesGCM = webcrypto.AesGCM;

            context("checkAlgorithmParams", () => {

                it("valid with tagLength", () => {
                    AesGCM.checkAlgorithmParams({ name: "AES-GCM", additionalData: new Uint8Array(4), iv: new Uint8Array(12), tagLength: 128 });
                });
                it("valid with additionalData and iv ArrayBuffer", () => {
                    AesGCM.checkAlgorithmParams({ name: "AES-GCM", additionalData: new ArrayBuffer(4), iv: new ArrayBuffer(12), tagLength: 128 });
                });
                it("valid without tagLength", () => {
                    AesGCM.checkAlgorithmParams({ name: "AES-GCM", additionalData: new Uint8Array(4), iv: new Uint8Array(12) });
                });

                it("valid without additionalData", () => {
                    AesGCM.checkAlgorithmParams({ name: "AES-GCM", iv: new Uint8Array(12) });
                });
                it("valid without iv", () => {
                    assert.throws(() => AesGCM.checkAlgorithmParams({ name: "AES-GCM" }), Error);
                });
                it("wrong type of iv", () => {
                    assert.throws(() => AesGCM.checkAlgorithmParams({ name: "AES-GCM", iv: [1, 2, 3, 4, 5, 6, 7, 8] }), Error);
                });
                it("wrong type of additionalData", () => {
                    assert.throws(() => AesGCM.checkAlgorithmParams({ name: "AES-GCM", iv: new Uint8Array(12), additionalData: [1, 2, 3, 4, 5, 6, 7, 8] }), Error);
                });
                it("wrong tagLength", () => {
                    assert.throws(() => AesGCM.checkAlgorithmParams({ name: "AES-GCM", iv: new Uint8Array(12), tagLength: 130 }), Error);
                });

            });

            ["encrypt", "decrypt"].forEach(type => {
                it(type, done => {
                    const alg = { name: "AES-GCM", additionalData: new Uint8Array(4), iv: new Uint8Array(12) }
                    const key = {
                        algorithm: alg,
                        type: "secret",
                        extractable: true,
                        usages: [type]
                    };
                    encrypt(type, alg, key, done, false);
                });
            });

        });

        context("AES-KW", () => {

            context("generate", () => {

                [
                    { length: 128, error: false },
                    { length: 192, error: false },
                    { length: 256, error: false },
                    { length: 129, error: true },
                ].forEach(params => {
                    it(`length: ${params.length}`, done => {
                        generate({ name: "AES-KW", length: params.length }, ["wrapKey", "unwrapKey"], done, params.error);
                    });
                });

            });

            context("exportKey", () => {

                // keyLength
                [128, 192, 256].forEach(keyLength => {
                    // format
                    ["jwk", "raw"].forEach(format => {
                        it(`length: ${keyLength} ${format}`, done => {
                            exportKey(
                                format,
                                { type: "secret", algorithm: { name: "AES-KW", length: keyLength }, extractable: true, usages: ["wrapKey", "unwrapKey"] },
                                done,
                                false
                            );
                        });
                    })
                });
            });

            context("importKey", () => {
                // keyLength
                [128, 192, 256].forEach(keyLength => {
                    // format
                    ["jwk", "raw"].forEach(format => {
                        it(`length: ${keyLength} ${format}`, done => {
                            importKey(format, new Uint8Array(3), { name: "AES-KW", length: keyLength }, ["wrapKey"], done, false);
                        });
                    })
                });
            });

            context("wrapKey", () => {

                // keyLength
                [128, 192, 256].forEach(keyLength => {
                    // format
                    ["jwk", "pkcs8"].forEach(format => {
                        it(`length: ${keyLength} ${format}`, done => {
                            wrapKey(
                                format,
                                { name: "AES-KW" },
                                { type: "private", algorithm: { name: "RSASSA-PKCS1-v1_5" }, extractable: true, usages: ["sign"] },
                                { type: "secret", algorithm: { name: "AES-KW", length: keyLength }, extractable: true, usages: ["wrapKey", "unwrapKey"] },
                                done,
                                false
                            );
                        });
                    });
                });

            });

            context("unwrapKey", () => {

                // keyLength
                [128, 192, 256].forEach(keyLength => {
                    // format
                    ["jwk", "pkcs8"].forEach(format => {
                        it(`length: ${keyLength} ${format}`, done => {
                            unwrapKey(
                                format,
                                new Uint8Array([1, 2, 3]),
                                { type: "secret", algorithm: { name: "AES-KW", length: keyLength }, extractable: true, usages: ["wrapKey", "unwrapKey"] },
                                { name: "AES-KW" },
                                { name: "RSASSA-PKCS1-v1_5" },
                                true,
                                ["sign"],
                                done,
                                false
                            );
                        });
                    });
                });

            });

        });

    })

})
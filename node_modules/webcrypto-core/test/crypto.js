var webcrypto = require("../");
var assert = require("assert");

describe("Webcrypto", () => {

    context("Prepare data", () => {

        context("Algorithm", () => {

            it("from string", () => {
                var alg = webcrypto.PrepareAlgorithm("AES-CBC");
                assert(JSON.stringify(alg), JSON.stringify({ name: "AES-CBC" }));
            });

            it("from object", () => {
                var alg = webcrypto.PrepareAlgorithm({ name: "AES-CBC" });
                assert(JSON.stringify(alg), JSON.stringify({ name: "AES-CBC" }));
            });

            it("from object with hashed algorithm as string", () => {
                var alg = webcrypto.PrepareAlgorithm({ name: "RSA-PSS", hash: "SHA-1" });
                assert(JSON.stringify(alg), JSON.stringify({ name: "RSA-PSS", hash: { name: "SHA-1" } }));
            });

            it("from object with hashed algorithm as object", () => {
                var alg = webcrypto.PrepareAlgorithm({ name: "RSA-PSS", hash: { name: "SHA-1" } });
                assert(JSON.stringify(alg), JSON.stringify({ name: "RSA-PSS", hash: { name: "SHA-1" } }));
            });

            it("from object without name", () => {
                assert.throws(() => webcrypto.PrepareAlgorithm({ wrong: "param" }), Error);
            });

        });

        context("Data", () => {

            function TestPrepareData(inData, byteLength) {
                const outData = webcrypto.PrepareData(inData);
                assert.equal(outData.byteLength, byteLength);
                assert.equal(ArrayBuffer.isView(outData), true);
                const bufInData = new Buffer(Buffer.isBuffer(inData) || inData instanceof ArrayBuffer ? inData : inData.buffer);
                const bufOutData = new Buffer(outData);
                assert.equal(Buffer.compare(bufInData, bufOutData), 0);
            }

            it("from Uint8Array", () => {
                const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
                TestPrepareData(data, 10);
            });

            it("from Uint16Array", () => {
                const data = new Uint16Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
                TestPrepareData(data, 20);
            });

            it("from Uint32Array", () => {
                const data = new Uint32Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
                TestPrepareData(data, 40);
            });

            it("from ArrayBuffer", () => {
                const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]).buffer;
                TestPrepareData(data, 10);
            });

            it("from Buffer", () => {
                const data = new Buffer([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
                TestPrepareData(data, 10);
            });

            context("from subarray ArrayBufferView", () => {

                it("Uint8Array", () => {
                    const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
                    const sub = data.subarray(0, 5);
                    assert.equal(webcrypto.PrepareData(sub).byteLength, 5);
                });

                it("Uint16Array", () => {
                    const data = new Uint16Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
                    const sub = data.subarray(0, 5);
                    assert.equal(webcrypto.PrepareData(sub).byteLength, 10);
                });

            });

            it("from wrong data", () => {
                assert.throws(() => webcrypto.PrepareData("12345"), Error);
            });

            it("empty data", () => {
                assert.throws(() => webcrypto.PrepareData(), Error);
            });
        });

    });

    context("BaseCrypto", () => {
        var BaseCrypto = webcrypto.BaseCrypto;

        context("ckeckAlgorithm", () => {
            var checkAlgorithm = BaseCrypto.checkAlgorithm;

            it("algorithm", () => {
                checkAlgorithm({ name: "AES-CBC" });
            });

            it("hashed algorithm", () => {
                checkAlgorithm({ name: "RSA-PSS", hash: "SHA-1" });
            });

            it("wrong value", () => {
                assert.throws(() => checkAlgorithm([]), Error);
            });

            it("wrong object", () => {
                assert.throws(() => checkAlgorithm({}), Error);
            });

            it("empty", () => {
                assert.throws(() => checkAlgorithm(), Error);
            });

        });

        context("checkKey", () => {
            var checkKey = BaseCrypto.checkKey;

            it("empty", () => {
                assert.throws(() => checkKey(), Error);
            });

            it("wrong alg", () => {
                assert.throws(() => checkKey({ algorithm: { name: "AES-CBC" } }, "WRONG-ALG"), Error);
            });

        });

        it("checkWrappedKey", () => {
            assert.throws(() => BaseCrypto.checkWrappedKey({ extractable: false }), Error);
        })

        context("checkFormat", () => {
            var checkFormat = BaseCrypto.checkFormat;

            ["private"].forEach(type =>
                it(`raw for ${type}`, () => {
                    assert.throws(() => checkFormat("raw", type), Error);
                })
            );

            ["private"].forEach(type =>
                it(`jwk for ${type}`, () => {
                    assert.throws(() => checkFormat("raw", type), Error);
                })
            );

            ["secret", "private"].forEach(type =>
                it(`spki for ${type}`, () => {
                    assert.throws(() => checkFormat("spki", type), Error);
                })
            );

            ["secret", "public"].forEach(type =>
                it(`pkcs8 for ${type}`, () => {
                    assert.throws(() => checkFormat("pkcs8", type), Error);
                })
            );

            it("wrong format", () => {
                assert.throws(() => checkFormat("wrong", "secret"), Error);
            });

        });

        context("Abstract methods", () => {

            ["generateKey", "digest", "sign", "verify", "encrypt", "decrypt",
                "exportKey", "importKey", "wrapKey", "unwrapKey",
                "deriveKey", "deriveBits"].forEach(method =>
                    it(`${method} not implemented`, done => {
                        BaseCrypto[method]()
                            .then(() => {
                                done(new Error("Must be error"))
                            })
                            .catch(e =>
                                done()
                            );
                    })
                );

        });

    });


});
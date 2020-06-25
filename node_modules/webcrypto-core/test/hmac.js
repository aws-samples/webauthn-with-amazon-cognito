var webcrypto = require("../");
var assert = require("assert");

var helper = require("./helper");
var generate = helper.generate;
var sign = helper.sign;
var verify = helper.verify;
var exportKey = helper.exportKey;
var importKey = helper.importKey;

describe("Subtle", function () {

    context("HMAC", function () {

        var algs = ["HMAC"];

        algs.forEach(function (alg) {

            context("generate", () => {
                [0, 128, 256, 512].forEach(length => {
                    it(`${alg} length:${length}`, function (done) {
                        generate({ name: alg, length: length }, ["sign", "verify"], done, !length);
                    });
                });
            }); // generate

            context("export", () => {
                it(alg + " raw", function (done) {
                    var key = { algorithm: { name: alg }, type: "secret", extractable: true };
                    exportKey("raw", key, done, false);
                });
                it(alg + " jwk", function (done) {
                    var key = { algorithm: { name: alg }, type: "secret", extractable: true };
                    exportKey("jwk", key, done, false);
                });
                it(alg + " pkcs8, wrong format", function (done) {
                    var key = { algorithm: { name: alg }, type: "secret", extractable: true };
                    exportKey("pkcs8", key, done, true);
                });
            }); // export

            context("import", () => {
                it(alg + " jwk", function (done) {
                    var _alg = { name: alg };
                    importKey("jwk", new Uint8Array(3), _alg, ["sign"], done, false);
                });
                it(alg + " raw", function (done) {
                    var _alg = { name: alg };
                    importKey("raw", new Uint8Array(3), _alg, ["sign"], done, false);
                });
                it(alg + " pkcs8, wrong format", function (done) {
                    var _alg = { name: alg };
                    importKey("pkcs8", new Uint8Array(3), _alg, ["sign"], done, true);
                });
                it(alg + " raw, wrong key usage", function (done) {
                    var _alg = { name: alg };
                    importKey("raw", new Uint8Array(3), _alg, ["encrypt"], done, true);
                });
            }); // import

            context("sign/verify", () => {
                ["sha-1", "sha-256", "sha-384", "sha-512"]
                    .forEach(function (hashAlg, index) {
                        it("sign " + hashAlg, function (done) {
                            var _key = {
                                type: "secret",
                                algorithm: {
                                    name: "hmac",
                                    hash: {
                                        name: hashAlg
                                    }
                                },
                                usages: ["sign"]
                            };
                            var _alg = {
                                name: "hmac",
                            }
                            sign(_alg, _key, done, index === 4);
                        });

                        it("verify " + hashAlg, function (done) {
                            var _key = {
                                type: "secret",
                                algorithm: {
                                    name: "hmac",
                                    hash: {
                                        name: hashAlg
                                    }
                                },
                                usages: ["verify"]
                            };
                            var _alg = {
                                name: "hmac"
                            }
                            verify(_alg, _key, done, index === 4);
                        });

                    });

                it("sign wrong key type", function (done) {
                    var _key = {
                        type: "private",
                        algorithm: {
                            name: "hmac",
                            hash: {
                                name: "sha-1"
                            }
                        },
                        usages: ["sign"]
                    };
                    var _alg = {
                        name: "hmac",
                    }
                    sign(_alg, _key, done, true);
                });
                it("sign wrong key usage", function (done) {
                    var _key = {
                        type: "secret",
                        algorithm: {
                            name: "hmac",
                            hash: {
                                name: "sha-1"
                            }
                        },
                        usages: ["verify"]
                    };
                    var _alg = {
                        name: "hmac",
                    }
                    sign(_alg, _key, done, true);
                });
                it("verify wrong key type", function (done) {
                    var _key = {
                        type: "public",
                        algorithm: {
                            name: "hmac",
                            hash: {
                                name: "sha-1"
                            }
                        },
                        usages: ["verify"]
                    };
                    var _alg = {
                        name: "hmac",
                    }
                    verify(_alg, _key, done, true);
                });
                it("verify wrong key usage", function (done) {
                    var _key = {
                        type: "secret",
                        algorithm: {
                            name: "hmac",
                            hash: {
                                name: "sha-1"
                            }
                        },
                        usages: ["sign"]
                    };
                    var _alg = {
                        name: "hmac",
                    }
                    verify(_alg, _key, done, true);
                });
            });
        });
    });
});
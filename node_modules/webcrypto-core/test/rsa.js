var helper = require("./helper");
var assert = require("assert");
var subtle = helper.subtle;
var sign = helper.sign;
var verify = helper.verify;
var generate = helper.generate;
var importKey = helper.importKey;
var exportKey = helper.exportKey;
var encrypt = helper.encrypt;
var wrapKey = helper.wrapKey;
var unwrapKey = helper.unwrapKey;

describe("Subtle", function () {
    context("RSA", function (done) {

        context("generateKey", function (done) {

            it("with wrong publicExponent type ArrayBuffer", function (done) {
                generate({
                    name: "rsassa-pkcs1-v1_5",
                    hash: "SHA-256",
                    modulusLength: 1024,
                    publicExponent: new ArrayBuffer(3),
                }, ["sign"], done, true);
            });
            it("without hash param", function (done) {
                generate({
                    name: "rsassa-pkcs1-v1_5",
                    modulusLength: 1024,
                    publicExponent: new Uint8Array([3]),
                }, ["sign"], done, true);
            });
            it("RSA generate RSASSA 1024 [3] sign", function (done) {
                generate({
                    name: "rsassa-pkcs1-v1_5",
                    modulusLength: 1024,
                    publicExponent: new Uint8Array([3]),
                    hash: { name: "sha-1" }
                }, ["sign"], done, false);
            });
            it("RSA generate RSASSA 2048 [1, 0, 1] verify", function (done) {
                generate({
                    name: "rsassa-pkcs1-v1_5",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: { name: "sha-1" }
                }, ["verify"], done, false);
            });
            it("RSA generate RSASSA 4048 [1, 0, 1] sign,verify(upper case)", function (done) {
                generate({
                    name: "rsassa-pkcs1-v1_5",
                    modulusLength: 4096,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: { name: "sha-256" }
                }, ["VERIFY", "SiGn"], done, false);
            });
            it("RSA generate RSASSA empty modulusLength", function (done) {
                generate({
                    name: "rsassa-pkcs1-v1_5",
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: { name: "sha-256" }
                }, ["verify", "sign"], done, true);
            });
            context("RSA generate RSASSA wrong modulusLength", function () {
                it("not multiple 8", function (done) {
                    generate({
                        name: "rsassa-pkcs1-v1_5",
                        modulusLength: 257,
                        publicExponent: new Uint8Array([1, 0, 1]),
                        hash: { name: "sha-256" }
                    }, ["verify", "verify"], done, true);
                });
                it("less than 256", function (done) {
                    generate({
                        name: "rsassa-pkcs1-v1_5",
                        modulusLength: 128,
                        publicExponent: new Uint8Array([1, 0, 1]),
                        hash: { name: "sha-256" }
                    }, ["verify", "verify"], done, true);
                });
                it("more than 16384", function (done) {
                    generate({
                        name: "rsassa-pkcs1-v1_5",
                        modulusLength: 16392,
                        publicExponent: new Uint8Array([1, 0, 1]),
                        hash: { name: "sha-256" }
                    }, ["verify", "verify"], done, true);
                });
            })
            it("RSA generate RSASSA empty publicExponent", function (done) {
                generate({
                    name: "rsassa-pkcs1-v1_5",
                    modulusLength: 1024,
                    hash: { name: "sha-256" }
                }, ["verify", "sign"], done, true);
            });
            it("RSA generate RSASSA wrong publicExponent", function (done) {
                generate({
                    name: "rsassa-pkcs1-v1_5",
                    modulusLength: 1024,
                    publicExponent: new Uint8Array([1, 1, 1]),
                    hash: { name: "sha-256" }
                }, ["verify", "sign"], done, true);
            });
            it("RSA generate RSASSA empty hash", function (done) {
                generate({
                    name: "rsassa-pkcs1-v1_5",
                    modulusLength: 1024,
                    publicExponent: new Uint8Array([1, 0, 1])
                }, ["verify", "sign"], done, true);
            });
            it("RSA generate RSASSA wrong keyUsage", function (done) {
                generate({
                    name: "rsassa-pkcs1-v1_5",
                    modulusLength: 1024,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: { name: "sha-256" }
                }, ["verify", "sign", "encrypt"], done, true);
            });
            it("RSA generate PSS sign,verify", function (done) {
                generate({
                    name: "rsa-pss",
                    modulusLength: 1024,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: { name: "sha-256" }
                }, ["verify", "sign"], done, false);
            });
            it("RSA generate OAEP decrypt,encrypt,wrapKey,unwrapKey", function (done) {
                generate({
                    name: "rsa-oaep",
                    modulusLength: 1024,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: { name: "sha-256" }
                }, ["decrypt", "encrypt", "wrapKey", "unwrapKey"], done, false);
            });

        });

        context("sign/verify", function () {
            it("RsaSSA", done => {
                var key = {
                    algorithm: {
                        name: "RSASSA-PKCS1-v1_5",
                        hash: { name: "sha-1" }
                    },
                    usages: ["sign"],
                    type: "private"
                };
                sign({ name: "RSASSA-PKCS1-v1_5" }, key, done, false);
            });
            it("RsaSSA verify", done => {
                var key = {
                    algorithm: {
                        name: "RSASSA-PKCS1-v1_5",
                        hash: { name: "sha-1" }
                    },
                    usages: ["verify"],
                    type: "public"
                };
                verify({ name: "RSASSA-PKCS1-v1_5" }, key, done, false);
            });
            it("RsaSSA wrong type", function (done) {
                var key = {
                    algorithm: {
                        name: "RSASSA-PKCS1-v1_5",
                        hash: { name: "sha-1" }
                    },
                    usages: ["sign"],
                    type: "public"
                };
                sign({ name: "RSASSA-PKCS1-v1_5" }, key, done, true);
            });
            it("RsaSSA wrong usage", function (done) {
                var key = {
                    algorithm: {
                        name: "RSASSA-PKCS1-v1_5",
                        hash: { name: "sha-1" }
                    },
                    usages: ["verify"],
                    type: "private"
                };
                sign({ name: "RSASSA-PKCS1-v1_5" }, key, done, true);
            });
            it("RsaSSA wrong key alg", function (done) {
                var key = {
                    algorithm: {
                        name: "RSA-PSS",
                        hash: { name: "sha-1" }
                    },
                    usages: ["sign"],
                    type: "private"
                };
                sign({ name: "RSASSA-PKCS1-v1_5" }, key, done, true);
            });
            it("RsaPSS sign", function (done) {
                var key = {
                    algorithm: {
                        name: "RSA-PSS",
                        hash: { name: "sha-1" }
                    },
                    usages: ["sign"],
                    type: "private"
                };
                sign({ name: "RSA-PSS", saltLength: 8 }, key, done, false);
            });
            it("RsaPSS verify", function (done) {
                var key = {
                    algorithm: {
                        name: "RSA-PSS",
                        hash: { name: "sha-1" }
                    },
                    usages: ["verify"],
                    type: "public"
                };
                verify({ name: "RSA-PSS", saltLength: 8 }, key, done, false);
            });
            it("RsaPSS empty salt length", function (done) {
                var key = {
                    algorithm: {
                        name: "RSA-PSS",
                        hash: { name: "sha-1" }
                    },
                    usages: ["sign"],
                    type: "private"
                };
                sign({ name: "RSA-PSS" }, key, done, true);
            });
            it("RsaPSS wrong salt length", function (done) {
                var key = {
                    algorithm: {
                        name: "RSA-PSS",
                        hash: { name: "sha-1" }
                    },
                    usages: ["sign"],
                    type: "private"
                };
                sign({ name: "RSA-PSS", saltLength: -1 }, key, done, true);
            });
        })

        context("encrypt/decrypt", function () {

            it("OAEP encrypt", function (done) {
                var key = {
                    algorithm: {
                        name: "RSA-OAEP",
                        hash: { name: "sha-1" }
                    },
                    usages: ["encrypt"],
                    type: "public"
                };
                var alg = {
                    name: "RSA-OAEP",
                    label: new Uint8Array([1, 2, 3, 4, 5, 6])
                }
                encrypt("encrypt", alg, key, done, false);
            });
            it("OAEP encrypt label ArrayBuffer", function (done) {
                var key = {
                    algorithm: {
                        name: "RSA-OAEP",
                        hash: { name: "sha-1" }
                    },
                    usages: ["encrypt"],
                    type: "public"
                };
                var alg = {
                    name: "RSA-OAEP",
                    label: new ArrayBuffer(6)
                }
                encrypt("encrypt", alg, key, done, false);
            });
            it("OAEP encrypt label wrong type", function (done) {
                var key = {
                    algorithm: {
                        name: "RSA-OAEP",
                        hash: { name: "sha-1" }
                    },
                    usages: ["encrypt"],
                    type: "public"
                };
                var alg = {
                    name: "RSA-OAEP",
                    label: "label"
                }
                encrypt("encrypt", alg, key, done, true);
            });
            it("OAEP decrypt", function (done) {
                var key = {
                    algorithm: {
                        name: "RSA-OAEP",
                        hash: { name: "sha-1" }
                    },
                    usages: ["decrypt"],
                    type: "private"
                };
                var alg = {
                    name: "RSA-OAEP",
                    label: new Uint8Array([1, 2, 3, 4, 5, 6])
                }
                encrypt("decrypt", alg, key, done, false);
            });
            it("OAEP decrypt without label param", function (done) {
                var key = {
                    algorithm: {
                        name: "RSA-OAEP",
                        hash: { name: "sha-1" }
                    },
                    usages: ["decrypt"],
                    type: "private"
                };
                var alg = {
                    name: "RSA-OAEP"
                }
                encrypt("decrypt", alg, key, done, false);
            });
            it("OAEP encrypt wrong key alg", function (done) {
                var key = {
                    algorithm: {
                        name: "RSA-PSS",
                        hash: { name: "sha-1" }
                    },
                    usages: ["decrypt"],
                    type: "private"
                };
                var alg = {
                    name: "RSA-OAEP"
                }
                encrypt("decrypt", alg, key, done, true);
            });
            it("OAEP encrypt wrong key usage", function (done) {
                var key = {
                    algorithm: {
                        name: "RSA-OAEP",
                        hash: { name: "sha-1" }
                    },
                    usages: ["decrypt"],
                    type: "public"
                };
                var alg = {
                    name: "RSA-OAEP"
                }
                encrypt("encrypt", alg, key, done, true);
            });

        })

        context("wrap/unwrap", function () {

            it("OAEP wrap AES raw", function (done) {
                var wkey = {
                    algorithm: { name: "rsa-oaep" },
                    type: "public",
                    usages: ["wrapKey"]
                }
                var key = {
                    algorithm: { name: "aes-cbc" },
                    type: "secret",
                    extractable: true
                }
                var alg = {
                    name: 'rsa-oaep'
                }
                wrapKey("raw", alg, key, wkey, done, false);
            });
            it("OAEP wrap AES jwk", function (done) {
                var wkey = {
                    algorithm: { name: "rsa-oaep" },
                    type: "public",
                    usages: ["wrapKey"]
                }
                var key = {
                    algorithm: { name: "aes-cbc" },
                    type: "secret",
                    extractable: true
                }
                var alg = {
                    name: 'rsa-oaep'
                }
                wrapKey("jwk", alg, key, wkey, done, false);
            });
            it("OAEP wrap AES wrong format pkcs8", function (done) {
                var wkey = {
                    algorithm: { name: "rsa-oaep" },
                    type: "public",
                    usages: ["wrapKey"]
                }
                var key = {
                    algorithm: { name: "aes-cbc" },
                    type: "secret",
                    extractable: true
                }
                var alg = {
                    name: 'rsa-oaep'
                }
                wrapKey("pkcs8", alg, key, wkey, done, true);
            });
            it("OAEP wrap AES wrong wrap key alg", function (done) {
                var wkey = {
                    algorithm: { name: "rsa-pss" },
                    type: "public",
                    usages: ["wrapKey"]
                }
                var key = {
                    algorithm: { name: "aes-cbc" },
                    type: "secret",
                    extractable: true
                }
                var alg = {
                    name: 'rsa-oaep'
                }
                wrapKey("raw", alg, key, wkey, done, true);
            });
            it("OAEP unwrap AES", function (done) {
                var wkey = {
                    algorithm: { name: "rsa-oaep" },
                    type: "private",
                    usages: ["unwrapKey"]
                }
                var alg = {
                    name: "aes-cbc"
                }
                var walg = {
                    name: 'rsa-oaep'
                }
                unwrapKey("raw", new ArrayBuffer(3), wkey, walg, alg, true, ["sign"], done, false);
            });

        })

        context("import/export", function () {

            ["RSASSA-PKCS1-v1_5", "RSA-PSS", "RSA-OAEP"].forEach((alg) => {

                context(alg, function () {
                    it("export jwk publicKey", function (done) {
                        var key = {
                            algorithm: {
                                name: alg
                            },
                            type: "public",
                            extractable: true
                        }
                        exportKey("jwk", key, done, false);
                    });
                    it("export pkcs8 publicKey", function (done) {
                        var key = {
                            algorithm: {
                                name: alg
                            },
                            type: "public",
                            extractable: true
                        }
                        exportKey("pkcs8", key, done, true);
                    });
                    it("export spki publicKey", function (done) {
                        var key = {
                            algorithm: {
                                name: alg
                            },
                            type: "public",
                            extractable: true
                        }
                        exportKey("spki", key, done, false);
                    });
                    it("export pkcs8 privateKey", function (done) {
                        var key = {
                            algorithm: {
                                name: alg
                            },
                            type: "private",
                            extractable: true
                        }
                        exportKey("pkcs8", key, done, false);
                    });
                    it("export pkcs8 privateKey not extractable", function (done) {
                        var key = {
                            algorithm: {
                                name: alg
                            },
                            type: "private",
                            extractable: false
                        }
                        exportKey("pkcs8", key, done, true);
                    });
                })

            });

            it("import RSA without hash param", function (done) {
                var alg = {
                    name: "RSASSA-PKCS1-v1_5",
                }
                importKey("pkcs8", new Uint8Array([1]), alg, ["sign"], done, true);
            });
            it("import pkcs8 RSASSA-PKCS1-v1_5", function (done) {
                var alg = {
                    name: "RSASSA-PKCS1-v1_5",
                    hash: {
                        name: "sha-1"
                    }
                }
                importKey("pkcs8", new Uint8Array([1]), alg, ["sign"], done, false);
            });
            it("import pkcs8 PSS", function (done) {
                var alg = {
                    name: "RSA-pss",
                    hash: {
                        name: "sha-1"
                    }
                }
                importKey("pkcs8", new Uint8Array([1]), alg, ["sign"], done, false);
            });
            it("import pkcs8 OAEP", function (done) {
                var alg = {
                    name: "RSA-oaep",
                    hash: {
                        name: "sha-256"
                    }
                }
                importKey("pkcs8", new Uint8Array([1]), alg, ["encrypt"], done, false);
            });
            it("import spki RSASSA-PKCS1-v1_5", function (done) {
                var alg = {
                    name: "RSASSA-PKCS1-v1_5",
                    hash: {
                        name: "sha-1"
                    }
                }
                importKey("spki", new Uint8Array([1]), alg, ["sign"], done, false);
            });
            it("import raw RSASSA-PKCS1-v1_5, wrong format", function (done) {
                var alg = {
                    name: "RSASSA-PKCS1-v1_5",
                    hash: {
                        name: "sha-1"
                    }
                }
                importKey("raw", new Uint8Array([1]), alg, ["sign"], done, true);
            });
            it("import pkcs8 RSASSA-PKCS1-v1_5, wrong key usage", function (done) {
                var alg = {
                    name: "RSASSA-PKCS1-v1_5",
                    hash: {
                        name: "sha-1"
                    }
                }
                importKey("pkcs8", new Uint8Array([1]), alg, ["encrypt"], done, true);
            });
            it("import pkcs8 RSASSA-PKCS1-v1_5 wrong hash name", function (done) {
                var alg = {
                    name: "RSASSA-PKCS1-v1_5",
                    hash: {
                        name: "wrong name"
                    }
                }
                importKey("pkcs8", new Uint8Array([1]), alg, ["sign"], done, true);
            });

        });
    });
});


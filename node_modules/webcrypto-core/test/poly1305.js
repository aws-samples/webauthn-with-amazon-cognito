var webcrypto = require("../");
var assert = require("assert");

var helper = require("./helper");
var generate = helper.generate;
var sign = helper.sign;
var verify = helper.verify;
var exportKey = helper.exportKey;
var importKey = helper.importKey;

describe("Subtle", function () {

    context("Poly1305", function () {

        context("exportKey", function () {
            var alg = "Poly1305";
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
        })

        context("importKey", function () {
            var alg = "Poly1305";
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
        })

        context("sign/verify", function () {
            it("sign", function (done) {
                var _key = {
                    type: "secret",
                    algorithm: {
                        name: "EDDSA",
                    },
                    usages: ["sign"]
                };
                var _alg = {
                    name: "Poly1305",
                }
                sign(_alg, _key, done, false);
            });

            it("sign fails with bad useage", function (done) {
                var _key = {
                    type: "secret",
                    algorithm: {
                        name: "EDDSA",
                    },
                    usages: ["encrypt"]
                };
                var _alg = {
                    name: "Poly1305",
                }
                sign(_alg, _key, done, true);
            });

            it("sign fails with no key", function (done) {
                var _key = null;
                var _alg = {
                    name: "Poly1305",
                }
                sign(_alg, _key, done, true);
            });

            it("sign fails with bad algo", function (done) {
                var _key = {
                    type: "secret",
                    algorithm: {
                        name: "EDDSA",
                    },
                    usages: ["sign"]
                };
                var _alg = {
                    name: "ChaCha20",
                }
                sign(_alg, _key, done, true);
            });

            it("sign fails with bad algo length", function (done) {
                var _key = {
                    type: "secret",
                    algorithm: {
                        name: "EDDSA",
                    },
                    usages: ["sign"]
                };
                var _alg = {
                    name: "ChaCha20",
                    length: 254,
                }
                sign(_alg, _key, done, true);
            });

            it("verify", function (done) {
                var _key = {
                    type: "secret",
                    algorithm: {
                        name: "EDDSA",
                    },
                    usages: ["verify"]
                };
                var _alg = {
                    name: "Poly1305"
                }
                verify(_alg, _key, done, false);
            });

            it("verify fails with no key", function (done) {
                var _key = {};
                var _alg = {
                    name: "Poly1305"
                }
                verify(_alg, _key, done, true);
            });
        })
    })
})

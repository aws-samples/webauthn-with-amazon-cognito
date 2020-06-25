var webcrypto = require("../");
var assert = require("assert");

var helper = require("./helper");
var generate = helper.generate;
var importKey = helper.importKey;
var deriveKey = helper.deriveKey;
var deriveBits = helper.deriveBits;

context("PBKDF2", () => {

    context("importKey", () => {
        it("raw", done => {
            importKey("raw", new Uint8Array([1, 2, 3]), { name: "PBKDF2" }, ["deriveKey", "deriveBits"], done, false, false);
        });
        it("extractable true", done => {
            importKey("raw", new Uint8Array([1, 2, 3]), { name: "PBKDF2" }, ["deriveKey", "deriveBits"], done, true, true);
        });
        it("wrong format", done => {
            importKey("pkcs8", new Uint8Array([1, 2, 3]), { name: "PBKDF2" }, ["deriveKey", "deriveBits"], done, true, false);
        });
    });

    context("deriveBits", () => {

        it("empty algorithm param salt", done => {
            deriveBits(
                { name: "PBKDF2", iterations: 1000, hash: "SHA-1" },
                { type: "secret", algorithm: { name: "PBKDF2" }, extractable: true, usages: ["deriveBits"] },
                256,
                done,
                true
            );
        });

        it("wrong algorithm param salt", done => {
            deriveBits(
                { name: "PBKDF2", salt: "wrong param", iterations: 1000, hash: "SHA-1" },
                { type: "secret", algorithm: { name: "PBKDF2" }, extractable: true, usages: ["deriveBits"] },
                256,
                done,
                true
            );
        });

        it("empty algorithm param iterations", done => {
            deriveBits(
                { name: "PBKDF2", salt: new Uint8Array([1, 2, 3]), hash: "SHA-1" },
                { type: "secret", algorithm: { name: "PBKDF2" }, extractable: true, usages: ["deriveBits"] },
                256,
                done,
                true
            );
        });

        it("empty algorithm param hash", done => {
            deriveBits(
                { name: "PBKDF2", salt: new Uint8Array([1, 2, 3]), iterations: 1000 },
                { type: "secret", algorithm: { name: "PBKDF2" }, extractable: true, usages: ["deriveBits"] },
                256,
                done,
                true
            );
        });

        it("wrong algorithm param hash", done => {
            deriveBits(
                { name: "PBKDF2", salt: new Uint8Array([1, 2, 3]), iterations: 1000, hash: { name: "AES-CBC" } },
                { type: "secret", algorithm: { name: "PBKDF2" }, extractable: true, usages: ["deriveBits"] },
                256,
                done,
                true
            );
        });

        ["SHA-1", "SHA-256", "SHA-384", "SHA-512"]
            .forEach(hash =>
                it(hash, done => {
                    deriveBits(
                        { name: "PBKDF2", salt: new Uint8Array([1, 2, 3]), iterations: 1000, hash },
                        { type: "secret", algorithm: { name: "PBKDF2" }, extractable: true, usages: ["deriveBits"] },
                        256,
                        done,
                        false
                    );
                }));

        it("wrong key usage", done => {
            deriveBits(
                { name: "PBKDF2", salt: new Uint8Array([1, 2, 3]), iterations: 1000, hash: "SHA-1" },
                { type: "secret", algorithm: { name: "PBKDF2" }, extractable: true, usages: ["deriveKeys"] },
                256,
                done,
                true
            );
        });

        it("length = 0", done => {
            deriveBits(
                { name: "PBKDF2", salt: new Uint8Array([1, 2, 3]), iterations: 1000, hash: "SHA-1" },
                { type: "secret", algorithm: { name: "PBKDF2" }, extractable: true, usages: ["deriveBits"] },
                0,
                done,
                true
            );
        });

    });

    context("deriveKey", () => {

        // keyAlg
        ["AES-CBC", "AES-GCM", "AES-CTR", "AES-KW", "HMAC"]
            .forEach(keyAlg => {
                it(keyAlg, done => {
                    deriveKey(
                        { name: "PBKDF2", salt: new Uint8Array([1, 2, 3]), iterations: 1000, hash: "SHA-1" },
                        { type: "secret", algorithm: { name: "PBKDF2" }, extractable: true, usages: ["deriveKey"] },
                        { name: keyAlg, length: 128 },
                        ["wrapKey"],
                        done,
                        false
                    );
                });
            });

        it("wrong derived key length", done => {
            deriveKey(
                { name: "PBKDF2", salt: new Uint8Array([1, 2, 3]), iterations: 1000, hash: "SHA-1" },
                { type: "secret", algorithm: { name: "PBKDF2" }, extractable: true, usages: ["deriveKey"] },
                { name: "AES-CBC", length: 121 },
                ["wrapKey"],
                done,
                true
            );
        });
        it("wrong derived key algorithm", done => {
            deriveKey(
                { name: "PBKDF2", salt: new Uint8Array([1, 2, 3]), iterations: 1000, hash: "SHA-1" },
                { type: "secret", algorithm: { name: "PBKDF2" }, extractable: true, usages: ["deriveKey"] },
                { name: "RSA-PSS" },
                ["wrapKey"],
                done,
                true
            );
        });

    });

});
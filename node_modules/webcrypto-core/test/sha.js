var helper = require("./helper");
var assert = require("assert");
var subtle = helper.subtle;

describe("Subtle", function () {
    context("SHA", function (done) {

        function digest(alg, data, done, error) {
            var _error = true;
            subtle.digest(alg, data)
                .then(function (digest) {
                    assert.equal(digest, null);
                    _error = false
                })
                .catch(function (err) {
                    assert.equal(!!err, error, err.stack);
                })
                .then(function () {
                    assert.equal(_error, error, "Must be error");
                })
                .then(done, done);
        }

        var algs = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
        for (var i in algs) {
            var alg = algs[i];

            context(alg, function () {

                it(alg + " string alg name", function (done) {
                    digest(alg, new Uint8Array([0, 1, 2, 3]), done, false);
                });

                it(alg + " string alg name in lower case", function (done) {
                    digest(alg.toLowerCase(), new Uint8Array([0, 1, 2, 3]), done, false);
                });

                it(alg + " object alg", function (done) {
                    digest({ name: alg }, new Uint8Array([0, 1, 2, 3]), done, false);
                });

                it(alg + " invalid alg", function (done) {
                    digest("Wrong-Alg-Name", new Uint8Array([0, 1, 2, 3]), done, true);
                });

                it(alg + " valid data Uint8Array", function (done) {
                    digest({ name: alg }, new Uint8Array([0, 1, 2, 3]), done, false);
                });

                it(alg + " valid data Uint16Array", function (done) {
                    digest({ name: alg }, new Uint16Array([0, 1, 2, 3]), done, false);
                });

                it(alg + " valid data ArrayBuffer", function (done) {
                    digest({ name: alg }, new Uint16Array([0, 1, 2, 3].buffer), done, false);
                });

                it(alg + " valid data Buffer", function (done) {
                    digest({ name: alg }, new Buffer("Hello"), done, false);
                });

                it(alg + " invalid data", function (done) {
                    digest({ name: alg }, "Wron data", done, true);
                });

            });

        }

    });
});
"use strict";
var webcrypto = require("../");
var assert = require("assert");

var helper = require("./helper");
var generate = helper.generate;
var sign = helper.sign;
var verify = helper.verify;
var encrypt = helper.encrypt;
var exportKey = helper.exportKey;
var importKey = helper.importKey;

describe("Subtle", function () {

    it("generate wrong alg", done => {
        generate({ name: "Unknown" }, ["sign", "verify"], done, true);
    });

    it("sign wrong alg", done => {
        sign({ name: "Unknown" }, ["sign"], done, true);
    });

    it("verify wrong alg", done => {
        verify({ name: "Unknown" }, ["verify"], done, true);
    });

    it("encrypt wrong alg", done => {
        encrypt("encrypt", {name: "Unknown"}, {}, done, true);
    });

    it("decrypt wrong alg", done => {
        encrypt("decrypt", {name: "Unknown"}, {}, done, true);
    });

});
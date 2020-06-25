var helper = require("./helper");
var generate = helper.generate;
var encrypt = helper.encrypt;
var exportKey = helper.exportKey;
var importKey = helper.importKey;

describe("Subtle", function () {

  context("DES", function () {

      var algs = ["DES-CBC"];
      algs.forEach(function (alg) {

          it(alg + " generate", function (done) {
              generate({ name: alg, length: 64 }, ["encrypt", "decrypt", "wrapKey", "unwrapKey"], done, false);
          });
          it(alg + " generate wrong key usage", function (done) {
              generate({ name: alg, length: 64 }, ["sign", "verify"], done, true);
          });
          it(alg + " generate with key usage = null", function (done) {
              generate({ name: alg, length: 64 }, null, done, true);
          });
          it(alg + " generate with empty key usage", function (done) {
              generate({ name: alg, length: 64 }, [], done, true);
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

      context("DES-CBC encrypt", () => {
          it("ArrayBufferView", function (done) {
              var alg = { name: "DES-CBC", iv: new Uint8Array(8) };
              var key = {
                  algorithm: { name: "DES-CBC" },
                  type: "secret",
                  usages: ["encrypt"]
              };
              encrypt("encrypt", alg, key, done, false);
          });
          it("ArrayBuffer", function (done) {
              var alg = { name: "DES-CBC", iv: new ArrayBuffer(8) };
              var key = {
                  algorithm: { name: "DES-CBC" },
                  type: "secret",
                  usages: ["encrypt"]
              };
              encrypt("encrypt", alg, key, done, false);
          });
          it("Wrong iv", function (done) {
              var alg = { name: "DES-CBC", iv: [1, 2, 3, 4, 5, 6, 7, 8] };
              var key = {
                  algorithm: { name: "DES-CBC" },
                  type: "secret",
                  usages: ["encrypt"]
              };
              encrypt("encrypt", alg, key, done, true);
          });
      })
      context("DES-CBC decrypt", () => {
          it("Uint16Array", function (done) {
              var alg = { name: "DES-CBC", iv: new Uint16Array(4) };
              var key = {
                  algorithm: { name: "DES-CBC" },
                  type: "secret",
                  usages: ["decrypt"]
              };
              encrypt("decrypt", alg, key, done, false);
          });
          it("ArrayBuffer", function (done) {
              var alg = { name: "DES-CBC", iv: new ArrayBuffer(8) };
              var key = {
                  algorithm: { name: "DES-CBC" },
                  type: "secret",
                  usages: ["decrypt"]
              };
              encrypt("decrypt", alg, key, done, false);
          });
          it("wrong key", function (done) {
              var alg = { name: "DES-CBC", iv: new Uint8Array(8) };
              var key = {
                  algorithm: { name: "AES-GCM" },
                  type: "secret",
                  usages: ["decrypt"]
              };
              encrypt("decrypt", alg, key, done, true);
          });
          it("wrong alg param, iv size 15", function (done) {
              var alg = { name: "DES-CBC", iv: new Uint8Array(15) };
              var key = {
                  algorithm: { name: "DES-CBC" },
                  type: "secret",
                  usages: ["decrypt"]
              };
              encrypt("decrypt", alg, key, done, true);
          });
          it("wrong key usage", function (done) {
              var alg = { name: "DES-CBC", iv: new Uint8Array(8) };
              var key = {
                  algorithm: { name: "DES-CBC" },
                  type: "secret",
                  usages: ["unwrapKey"]
              };
              encrypt("decrypt", alg, key, done, true);
          });
      });

  });

});
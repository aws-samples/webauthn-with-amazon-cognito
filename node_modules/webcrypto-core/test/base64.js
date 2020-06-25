var Base64Url = require("../").Base64Url;
var assert = require("assert");

describe("Base64 URL", function(){

    function e2d(message) {
        var enc = Base64Url.encode(new Buffer(message));
        var dec = Base64Url.decode(enc);
        assert.equal(new Buffer(dec).toString(), message);
    }

    function d2e(message) {
        var dec = Base64Url.decode(message);
        var enc = Base64Url.encode(dec);
        assert.equal(enc, message);
    }

    it("encode/decode", function(){
        e2d("1234567890");
        d2e("qL8R4QIcQ-ZsRqOAbeRfcZhilN-MksRtDaErMA");
    });
});
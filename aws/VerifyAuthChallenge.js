var crypto = require("crypto");

exports.handler = async (event) => {
    console.log(event);
   
   //--------get private challenge data
    const challenge = event.request.privateChallengeParameters.challenge;
    const credId = event.request.privateChallengeParameters.credId;
    
    //--------publickey information
    var publicKeyCred = event.request.userAttributes["custom:publicKeyCred"];
    var publicKeyCredJSON = JSON.parse(Buffer.from(publicKeyCred, 'base64').toString('ascii'));
    
    //-------get challenge ansower
    const challengeAnswerJSON = JSON.parse(event.request.challengeAnswer);
    
    const verificationResult = await validateAssertionSignature(publicKeyCredJSON, challengeAnswerJSON);
    console.log("Verification Results:"+verificationResult);
    
    if (verificationResult) {
        event.response.answerCorrect = true;
    } else {
        event.response.answerCorrect = false;
    }
    return event;
};

async function validateAssertionSignature(publicKeyCredJSON, challengeAnswerJSON) {
    
    var expectedSignature = toArrayBuffer(challengeAnswerJSON.response.signature, "signature");
    var publicKey = publicKeyCredJSON.publicKey;
    var rawAuthnrData = toArrayBuffer(challengeAnswerJSON.response.authenticatorData, "authenticatorData");
    var rawClientData = toArrayBuffer(challengeAnswerJSON.response.clientDataJSON, "clientDataJSON");

    const hash = crypto.createHash("SHA256");
    hash.update(Buffer.from(new Uint8Array(rawClientData)));
    var clientDataHashBuf = hash.digest();
    var clientDataHash = new Uint8Array(clientDataHashBuf).buffer;

    const verify = crypto.createVerify("SHA256");
    verify.write(Buffer.from(new Uint8Array(rawAuthnrData)));
    verify.write(Buffer.from(new Uint8Array(clientDataHash)));
    verify.end();
    
    var res = null;
    try {
        res = verify.verify(publicKey, Buffer.from(new Uint8Array(expectedSignature)));
    } catch (e) {console.error(e);}

    return res;
}

function toArrayBuffer(buf, name) {
    if (!name) {
        throw new TypeError("name not specified");
    }

    if (typeof buf === "string") {
        buf = buf.replace(/-/g, "+").replace(/_/g, "/");
        buf = Buffer.from(buf, "base64");
    }

    if (buf instanceof Buffer || Array.isArray(buf)) {
        buf = new Uint8Array(buf);
    }

    if (buf instanceof Uint8Array) {
        buf = buf.buffer;
    }

    if (!(buf instanceof ArrayBuffer)) {
        throw new TypeError(`could not convert '${name}' to ArrayBuffer`);
    }

    return buf;
}

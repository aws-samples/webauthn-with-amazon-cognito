const express = require('express');
const router = express.Router();
const { Fido2Lib } = require('fido2-lib');
const { coerceToBase64Url, coerceToArrayBuffer } = require('fido2-lib/lib/utils');

router.use(express.json());

const f2l = new Fido2Lib({
    timeout: 30*1000*60,
    rpId: process.env.HOSTNAME,
    rpName: "WebAuthn With Cognito",
    challengeSize: 32,
    cryptoParams: [-7]
});


/**
 * Respond with required information to call navigator.credential.create()
 * Response format:
 * {
     rp: {
       id: String,
       name: String
     },
     user: {
       displayName: String,
       id: String,
       name: String
     },
     publicKeyCredParams: [{  
       type: 'public-key', alg: -7
     }],
     timeout: Number,
     challenge: String,
     excludeCredentials: [{
       id: String,
       type: 'public-key',
       transports: [('ble'|'nfc'|'usb'|'internal'), ...]
     }, ...],
     authenticatorSelection: {
       authenticatorAttachment: ('platform'|'cross-platform'),
       requireResidentKey: Boolean,
       userVerification: ('required'|'preferred'|'discouraged')
     },
     attestation: ('none'|'indirect'|'direct')
 * }
 **/
router.post('/createCredRequest', async (req, res) => {
  f2l.config.rpId = `${req.get('host')}`;
 
  try {
    
    const response = await f2l.attestationOptions();
    response.user = {
      displayName: req.body.name,
      id: req.body.username,
      name: req.body.username
    };
    response.challenge = coerceToBase64Url(response.challenge, 'challenge');
    
    response.excludeCredentials = [];
    response.pubKeyCredParams = [];
    // const params = [-7, -35, -36, -257, -258, -259, -37, -38, -39, -8];
    const params = [-7, -257];
    for (let param of params) {
      response.pubKeyCredParams.push({type:'public-key', alg: param});
    }
    const as = {}; // authenticatorSelection
    const aa = req.body.authenticatorSelection.authenticatorAttachment;
    const rr = req.body.authenticatorSelection.requireResidentKey;
    const uv = req.body.authenticatorSelection.userVerification;
    const cp = req.body.attestation; // attestationConveyancePreference
    let asFlag = false;

    if (aa && (aa == 'platform' || aa == 'cross-platform')) {
      asFlag = true;
      as.authenticatorAttachment = aa;
    }
    if (rr && typeof rr == 'boolean') {
      asFlag = true;
      as.requireResidentKey = rr;
    }
    if (uv && (uv == 'required' || uv == 'preferred' || uv == 'discouraged')) {
      asFlag = true;
      as.userVerification = uv;
    }
    if (asFlag) {
      response.authenticatorSelection = as;
    }
    if (cp && (cp == 'none' || cp == 'indirect' || cp == 'direct')) {
      response.attestation = cp;
    }

    res.json(response);
  } catch (e) {
    res.status(400).send({ error: e });
  }
});


/**
 * Register user credential.
 * Input format:
 * {
     id: String,
     type: 'public-key',
     rawId: String,
     response: {
       clientDataJSON: String,
       attestationObject: String,
       signature: String,
       userHandle: String
     }
 * }
 **/
router.post('/parseCredResponse', async (req, res) => {
  f2l.config.rpId = `${req.get('host')}`;

  try {
    const clientAttestationResponse = { response: {} };
    clientAttestationResponse.rawId = coerceToArrayBuffer(req.body.rawId, "rawId");
    clientAttestationResponse.response.clientDataJSON = coerceToArrayBuffer(req.body.response.clientDataJSON, "clientDataJSON");
    clientAttestationResponse.response.attestationObject = coerceToArrayBuffer(req.body.response.attestationObject, "attestationObject");
    
    let origin = '';
    if (req.get('User-Agent').indexOf('okhttp') > -1) {
      const octArray = process.env.ANDROID_SHA256HASH.split(':').map(h => parseInt(h, 16));
      const androidHash = coerceToBase64Url(octArray, 'Android Hash');
      origin = `android:apk-key-hash:${androidHash}`; // TODO: Generate
    } else {
      origin = `https://${req.get('host')}`;
    }

    const attestationExpectations = {
      challenge: req.body.challenge,
      origin: origin,
      factor: "either"
    };

    const regResult = await f2l.attestationResult(clientAttestationResponse, attestationExpectations);
    
    //console.log(JSON.stringify(regResult));
    //console.log(regResult.authnrData.get("flags"));

    const credential = {
      credId: coerceToBase64Url(regResult.authnrData.get("credId"), 'credId'),
      publicKey: regResult.authnrData.get("credentialPublicKeyPem"),
      aaguid: coerceToBase64Url(regResult.authnrData.get("aaguid"), 'aaguid'),
      prevCounter: regResult.authnrData.get("counter"),
      flags: regResult.authnrData.get("flags")
    };

    // Respond with user info
    res.json(credential);
  } catch (e) {
    res.clearCookie('challenge');
    res.status(400).send({ error: e.message });
  }
});


module.exports = router;

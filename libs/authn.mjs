/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file.
 * This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import express from "express";
const router = express.Router();
import { Fido2Lib } from "fido2-lib";
import { coerceToBase64Url, coerceToArrayBuffer } from "fido2-lib/lib/utils.js";

router.use(express.json());

const f2l = new Fido2Lib({
  timeout: 30 * 1000 * 60,
  //rpId: process.env.HOSTNAME,
  rpName: "WebAuthn With Cognito",
  challengeSize: 32,
  cryptoParams: [-7],
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
     allowCredentials : [{
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
router.post("/createCredRequest", async (req, res) => {
  f2l.config.rpId = `${req.get("host")}`;

  try {
    const response = await f2l.attestationOptions();
    response.user = {
      displayName: req.body.name,
      id: req.body.username,
      name: req.body.username,
    };
    response.challenge = coerceToBase64Url(response.challenge, "challenge");

    response.excludeCredentials = [];
    response.pubKeyCredParams = [];
    // const params = [-7, -35, -36, -257, -258, -259, -37, -38, -39, -8];
    const params = [-7, -257];
    for (let param of params) {
      response.pubKeyCredParams.push({ type: "public-key", alg: param });
    }
    const as = {}; // authenticatorSelection
    const aa = req.body.authenticatorSelection.authenticatorAttachment;
    const rr = req.body.authenticatorSelection.requireResidentKey;
    const uv = req.body.authenticatorSelection.userVerification;
    const cp = req.body.attestation; // attestationConveyancePreference
    let asFlag = false;

    if (aa && (aa == "platform" || aa == "cross-platform")) {
      asFlag = true;
      as.authenticatorAttachment = aa;
    }
    if (rr && typeof rr == "boolean") {
      asFlag = true;
      as.requireResidentKey = rr;
    }
    if (uv && (uv == "required" || uv == "preferred" || uv == "discouraged")) {
      asFlag = true;
      as.userVerification = uv;
    }
    if (asFlag) {
      response.authenticatorSelection = as;
    }
    if (cp && (cp == "none" || cp == "indirect" || cp == "direct")) {
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
router.post("/parseCredResponse", async (req, res) => {
  f2l.config.rpId = `${req.get("host")}`;

  try {
    const clientAttestationResponse = { response: {} };
    clientAttestationResponse.rawId = coerceToArrayBuffer(
      req.body.rawId,
      "rawId"
    );
    clientAttestationResponse.response.clientDataJSON = coerceToArrayBuffer(
      req.body.response.clientDataJSON,
      "clientDataJSON"
    );
    clientAttestationResponse.response.attestationObject = coerceToArrayBuffer(
      req.body.response.attestationObject,
      "attestationObject"
    );

    let origin = `https://${req.get("host")}`;

    const attestationExpectations = {
      challenge: req.body.challenge,
      origin: origin,
      factor: "either",
    };

    const regResult = await f2l.attestationResult(
      clientAttestationResponse,
      attestationExpectations
    );

    const credential = {
      credId: coerceToBase64Url(regResult.authnrData.get("credId"), "credId"),
      publicKey: regResult.authnrData.get("credentialPublicKeyPem"),
      aaguid: coerceToBase64Url(regResult.authnrData.get("aaguid"), "aaguid"),
      prevCounter: regResult.authnrData.get("counter"),
      flags: regResult.authnrData.get("flags"),
    };

    // Respond with user info
    res.json(credential);
  } catch (e) {
    res.status(400).send({ error: e.message });
  }
});

// module.exports = router;
export default router;

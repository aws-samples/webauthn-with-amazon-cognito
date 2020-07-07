# WebAuthn with Amazon Cognito

This project is a demonestration of how to implement FIDO-based authentication with Amazon Cognito user pools. The full technical write-up on this topic is available in this [blog post].

## Requirements
- AWS account and permissions to create CloudFromation stacks, Cognito resources and lambda functions
- Nodejs and NPM
- Browser/Device that supports FIDO2. Refer to [FIDO Alliance]

## Deployment steps
###### Clone the project
```sh
$ git clone https://github.com/aws-samples/webauthn-with-amazon-cognito.git
$ cd webauthn-with-amazon-cognito
```
###### Create Cognito resaources and lambda triggers
```sh
$ aws cloudformation create-stack --stack-name webauthn-cognito --template-body file://aws/UserPoolTemplate.yaml --capabilities CAPABILITY_AUTO_EXPAND CAPABILITY_IAM CAPABILITY_NAMED_IAM
```
Wait for the stack to be created successfully and then get the user-pool-id and app-client-id from outputs section. you can do this from CloudFromation console or using describe-stacks command
```sh
$ aws cloudformation describe-stacks --stack-name webauthn-cognito 
```
Edit the file views/webauthn.html to use the new user-pool that you just created.
```javascript
  var poolData = {
    UserPoolId: 'user_pool_id',
    ClientId: 'app_client_id'
  };
```
###### Install and run the application
```sh
$ npm install
$ node server.js
```
###### Note
WebAuthn APIs will be exposed by the user-agent only if secure transport is established without errors. This means you have to access the demo application vial HTTPS.
In the demo recording below, I used AWS Cloud9 which gives you a quick way to deploy and test the app. if you deploy this app on your own workstation or on a separate VM, you need to configure SSL.

Here is a quick demo of deploying and running this project in a fresh Cloud9 environment.

[![Watch the demo](https://webauthn-with-amazon-cognito.s3-us-west-2.amazonaws.com/WebAuthn.gif)](https://webauthn-with-amazon-cognito.s3-us-west-2.amazonaws.com/WebAuthn.mp4)

   [FIDO Alliance]: <https://fidoalliance.org/fido2/fido2-web-authentication-webauthn/>
   [blog post]: <https://aws.amazon.com/blogs/security/>
   
## Lambda triggers
The cloudformation template provided in this repo will deploy three lambda triggers to implement custom authentication flow.

###### Define Auth Challenge

```javascript
/**
 * 1- if user doesn't exist, throw exception
 * 2- if CUSTOM_CHALLENGE answer is correct, authentication successful
 * 3- if PASSWORD_VERIFIER challenge answer is correct, return custom challeneg (3,4 will be appliable if password+fido is selected)
 * 4- if challenge name is SRP_A, return PASSWORD_VERIFIER challenge (3,4 will be appliable if password+fido is selected)
 * 5- if 5 attempts with no correct answer, fail authentication
 * 6- default is to respond with CUSTOM_CHALLENEG --> password-less authentication
 * */

exports.handler = (event, context, callback) => {
    
    // If user is not registered
    if (event.request.userNotFound) {
        event.response.issueToken = false;
        event.response.failAuthentication = true;
        throw new Error("User does not exist");
    }
    
    if (event.request.session &&
        event.request.session.length &&
        event.request.session.slice(-1)[0].challengeName === 'CUSTOM_CHALLENGE' &&
        event.request.session.slice(-1)[0].challengeResult === true) {
        // The user provided the right answer; succeed auth
        event.response.issueTokens = true;
        event.response.failAuthentication = false;
        
    }else if (event.request.session &&
        event.request.session.length &&
        event.request.session.slice(-1)[0].challengeName === 'PASSWORD_VERIFIER' &&
        event.request.session.slice(-1)[0].challengeResult === true){
            
        event.response.issueTokens = false;
        event.response.failAuthentication = false;
        event.response.challengeName = 'CUSTOM_CHALLENGE';
        
    }else if (event.request.session &&
        event.request.session.length &&
        event.request.session.slice(-1)[0].challengeName === 'SRP_A'){
            
        event.response.issueTokens = false;
        event.response.failAuthentication = false;
        event.response.challengeName = 'PASSWORD_VERIFIER';
        
    }else if(event.request.session.length >= 5 && 
        event.request.session.slice(-1)[0].challengeResult === false){
            
        event.response.issueToken = false;
        event.response.failAuthentication = true;
        throw new Error("Invalid credentials");
    }else{
        
        event.response.issueTokens = false;
        event.response.failAuthentication = false;
        event.response.challengeName = 'CUSTOM_CHALLENGE';
        
    }
    
    // Return to Amazon Cognito
    callback(null, event);
}

```

###### Create Auth Challenge

```javascript
const crypto = require("crypto");

exports.handler = async (event) => {
    
    var publicKeyCred = event.request.userAttributes["custom:publicKeyCred"];
    var publicKeyCredJSON = Buffer.from(publicKeyCred, 'base64').toString('ascii');
    
    const challenge = crypto.randomBytes(64).toString('hex');
    
    event.response.publicChallengeParameters = {
        credId: JSON.parse(publicKeyCredJSON).id, //credetnial id
        challenge: challenge
    };
    
    event.response.privateChallengeParameters = { challenge : challenge};
    return event;
};

```

###### Verify Auth Challenge

```javascript
var crypto = require("crypto");

exports.handler = async (event) => {
   
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
    
    var res = false;
    try {
        res = verify.verify(publicKey, Buffer.from(new Uint8Array(expectedSignature)));
    } catch (e) {console.error(e);}

    return res;
}

```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.


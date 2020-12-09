# WebAuthn with Amazon Cognito

This project is a demonstration of how to implement FIDO-based authentication with Amazon Cognito user pools.

## Requirements
- AWS account and permissions to create CloudFormation stacks, Cognito resources and lambda functions
- Nodejs and NPM
- Browser and security key that supports FIDO2. Refer to [FIDO Alliance]

## Deployment steps
###### Clone the project
```sh
$ git clone https://github.com/aws-samples/webauthn-with-amazon-cognito.git
$ cd webauthn-with-amazon-cognito
```
###### Create Cognito resaources and lambda triggers
```sh
$ aws --region us-west-2 cloudformation create-stack --stack-name webauthn-cognito --template-body file://aws/UserPoolTemplate.yaml --capabilities CAPABILITY_AUTO_EXPAND CAPABILITY_IAM CAPABILITY_NAMED_IAM
```
Wait for the stack to be created successfully and then get the user-pool-id and app-client-id from outputs section. you can do this from CloudFromation console or using describe-stacks command
```sh
$ aws --region us-west-2 cloudformation describe-stacks --stack-name webauthn-cognito 
```
Edit the file public/webauthn-client.js to use the new user-pool that you just created.
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
**WebAuthn APIs will be exposed by the user-agent only if secure transport is established without errors. This means you have to access the demo application via HTTPS.
In the demo recording below, I used AWS Cloud9 which gives you a quick way to deploy and test the app. if you deploy this app on your own workstation or on a separate VM, you need to configure SSL.**

Here is a quick demo of deploying and running this project in a fresh Cloud9 environment.

[![Watch the demo](https://webauthn-with-amazon-cognito.s3-us-west-2.amazonaws.com/WebAuthn.gif)](https://webauthn-with-amazon-cognito.s3-us-west-2.amazonaws.com/WebAuthn.mp4)

   [FIDO Alliance]: <https://fidoalliance.org/fido2/fido2-web-authentication-webauthn/>
   [blog post]: <https://aws.amazon.com/blogs/security/>
   
## User registration
Registration starts by calling createCredential function in webauthn-client.js. This function will construct credentials options object and use it to create credentials with an available authenticator. 

Creating credentials will use `navigator.credentials.create` browser API, this API takes createCredentialOptions object as input and this object contains parameters about the relying party, the user and some flags to indicate which authenticators are allowed and whether user verification is required or not. In this demo, credentialOptions object is created server side using `createCredRequest` in libs/authn.js

The dictionary structure of CreateCredentialOptions object could include parameters as below (note that not all parameters are required and this is an extension point that can be extended in the future to support additional parameters):
```javascript
 {
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
       transports: [('ble'|'nfc'|'usb'|'internal')]
     }],
     authenticatorSelection: {
       authenticatorAttachment: ('platform'|'cross-platform'),
       requireResidentKey: Boolean,
       userVerification: ('required'|'preferred'|'discouraged')
     },
     attestation: ('none'|'indirect'|'direct')
 }
```
After creating credentials, `createCredential` function will parse response from authenticator to extract credential-id and public-key then it will call signUp function to start the signUp process with Cognito and will store the public-key and credential-id as custom attribute in cognito.

## User authentication
This demo application includes multiple scenarios for demonestration and education purposes.

Authentication starts by calling `signIn()` function in webauthn-client.js. This function will evaluate which sign-in option was chosen; e.g. sign-in with password only (for example to sign in with temp password for account recovery if authenticator device is lost), sign-in with FIDO only (this is the passwordless option) OR sign-in with password + FIDO (this is when using password as primary factor and using FIDO as second factor).

Based on the selected option, `signIn()` will make a call to authentication the user with Cognito. Authentication flows that utilize FIDO will be sent to Cognito as CUSTOM_AUTH flows, this will trigger Define Auth Challenge and process the authentication with custom challenge.

On client-side, FIDO challenge will be triggered when client receives a `customChallenge` response in the `authCallBack` function, this will use the challenge and credential-id returned in custom challenge to call `navigator.credentials.get` browser API which will ask the user to use the authenticator to sign-in. Authenticator will then validate inputs (relying party, credential-id ...etc. ) and after validation, authenticator response is sent to cognito using `cognitoUser.sendCustomChallengeAnswer` API and will be verified in Verify Auth Challenge lambda trigger.

## Lambda triggers
The cloudformation template aws/UserPoolTemplate.yaml will deploy three lambda triggers to implement custom authentication flow.

###### Define Auth Challenge
This lamda function is triggered when authentication flow is CUSTOM_AUTH to evaluate the authentication progress and decide what is the next step. For reference, the code for this lambda trigger is under aws/DefineAuthChallenge.js

Define auth challenge will go through the logic below to decide next challenge:

```javascript
/**
 * 1- if user doesn't exist, throw exception
 * 2- if CUSTOM_CHALLENGE answer is correct, authentication successful (issue-tokens will be set to true)
 * 3- if PASSWORD_VERIFIER challenge answer is correct, return custom challenge (steps 3,4 will be applicable if password+fido is selected and these steps handle SRP authentication)
 * 4- if challenge name is SRP_A, return PASSWORD_VERIFIER challenge (steps 3,4 will be appliable if password+fido is selected and these steps handle SRP authentication)
 * 5- if 5 attempts with no correct answer, fail authentication
 * 6- default is to respond with CUSTOM_CHALLENGE --> password-less authentication
 * */
```

###### Create Auth Challenge
This lambda function is triggered when the next step (set from define auth challenge) is CUSTOM_CHALLENGE. For reference, the code of this lambda trigger is under aws/CreateAuthChallenge.js

This function will do three things:
1- extract credential-id from user's profile (this is the credential-id created by authenticator during registration step)
2- create random string to be used as a chanllenge
3- return credential-id and challenge string to client as custom challenge

###### Verify Auth Challenge
This lambda will be triggered when challenge response is passed on from client to Cognito service. challenge response includes the response generated from authenticator device, this response will be parsed and validated using the stored paublic-key in user's profile. For reference, the code of this lambda trigger is under aws/DefineAuthChallenge.js

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.


# WebAuthn with Amazon Cognito

This project is a demonestration of how to implement FIDO-based authentication with Amazon Cognito user pools. The full technical write-up on this topic is available in this [blog post].

# Requirements
- AWS account and permissions to create CloudFromation stacks, Cognito resources and lambda functions
- Nodejs and NPM
- Browser/Device that supports FIDO2. Refer to [FIDO Alliance]

# Deployment steps
Clone the project
```sh
$ git clone https://github.com/mmatouk/webauthn-with-amazon-cognito.git
$ cd webauthn-with-amazon-cognito
```
Create Cognito resaources and lambda triggers
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
Install and run the application
```sh
$ npm install
$ node server.js
```

You can deploy and run this application in few minutes on AWS Cloud9. Here is a quick demo.
[![Watch the demo](https://webauthn-with-amazon-cognito.s3-us-west-2.amazonaws.com/WebAuthn.gif)](https://webauthn-with-amazon-cognito.s3-us-west-2.amazonaws.com/WebAuthn.mp4)

![](https://webauthn-with-amazon-cognito.s3-us-west-2.amazonaws.com/WebAuthn.gif)

   [FIDO Alliance]: <https://fidoalliance.org/fido2/fido2-web-authentication-webauthn/>
   [blog post]: <https://aws.amazon.com/blogs/security/>

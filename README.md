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
Login to your AWS account and wait for the stack to be created successfully. Note the user-pool ID and app-client ID from the outputs section of your stack.

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



   [FIDO Alliance]: <https://fidoalliance.org/fido2/fido2-web-authentication-webauthn/>
   [blog post]: <https://aws.amazon.com/blogs/security/>

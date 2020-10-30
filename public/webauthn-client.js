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
  
  
  let globalRegisteredCredentials = "";
  let globalRegisteredCredentialsJSON = {};
  
  let poolData = {
    UserPoolId: 'user-pool-id', // Your user pool id here
    ClientId: 'app-client-id' //Your app client id here
  };
  let userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
  
  //create credentials using platform or roaming authenticator
  createCredential = async () => {
    
      try {
        
          //build the credentials options requirements
          var credOptionsRequest = {
            attestation: 'none',
            username: $("#reg-username").val() ,
            name: $("#reg-username").val(),
            authenticatorSelection: {
              authenticatorAttachment: ['platform','cross-platform'],
              userVerification: 'preferred',
              requireResidentKey: false
            }
          };
          
          //generate credentials request to be sent to navigator.credentials.create
          var credOptions = await _fetch('/authn/createCredRequest' , credOptionsRequest);
          var challenge = credOptions.challenge;
          credOptions.user.id = base64url.decode(credOptions.user.id);
          credOptions.challenge = base64url.decode(credOptions.challenge);
          
          //----------create credentials using available authenticator
          const cred = await navigator.credentials.create({
              publicKey: credOptions
          });
          
          // parse credentials response to extract id and public-key, this is the information needed to register the user in Cognito
          const credential = {};
          credential.id =     cred.id;
          credential.rawId =  base64url.encode(cred.rawId);
          credential.type =   cred.type;
          credential.challenge = challenge;
          
          if (cred.response) {
            const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
            const attestationObject = base64url.encode(cred.response.attestationObject);
            credential.response = {
              clientDataJSON,
              attestationObject
            };
          }
          
          credResponse = await _fetch('/authn/parseCredResponse' , credential);
          
          globalRegisteredCredentialsJSON = {id: credResponse.credId,publicKey: credResponse.publicKey};
          globalRegisteredCredentials = JSON.stringify(globalRegisteredCredentialsJSON);
          console.log(globalRegisteredCredentials);
          
          //----------credentials have been created, now sign-up the user in Cognito
          signUp();
        
      } catch (e) {console.error(e);}
  };

  //---------------Cognito sign-up
  signUp = async () =>{
  
      var email = $("#reg-email").val();
      var username = $("#reg-username").val();
      var password =$("#reg-password").val();
      var name = $("#reg-name").val();
      var publicKeyCred = btoa(globalRegisteredCredentials);//base64 encode credentials json string (credId, public-key)
      
      var attributeList = [];
  
      var dataEmail = {Name: 'email',Value: email};
      var dataName = { Name: 'name',Value: name};
      var dataPublicKeyCred = { Name: 'custom:publicKeyCred',Value: publicKeyCred};
      
      var attributeEmail = new AmazonCognitoIdentity.CognitoUserAttribute(dataEmail);
      var attributePublicKeyCred = new AmazonCognitoIdentity.CognitoUserAttribute(dataPublicKeyCred);
      var attributeName = new AmazonCognitoIdentity.CognitoUserAttribute(dataName);
  
      attributeList.push(attributeEmail);
      attributeList.push(attributePublicKeyCred);
      attributeList.push(attributeName);
      
      userPool.signUp(username, password, attributeList, null, function(err, result ) {
        if (err) {
          console.log(err.message || JSON.stringify(err));
          return;
        }else{
          var cognitoUser = result.user;
          
          var confirmationCode = prompt("Please enter confirmation code:");
          cognitoUser.confirmRegistration(confirmationCode, true, function(err, result) {
            if (err) {
              alert(err.message || JSON.stringify(err));
              return;
            }
            console.log('call result: ' + result);
            alert("Registration successful, now sign-in.");
          });
          
          console.log('user name is ' + cognitoUser.getUsername());
        }
      });
  }


  //---------------Cognito sign-in user
  signIn = async () => {
  
      var username = $("#login-username").val();
      var password = $("#login-password").val();
      var flow = $("input[name='authentication']:checked").val();
      
      var authenticationData = {
        Username: username, //only username required since we will authenticate user using custom auth flow and will use security key
        Password: password
      };
      
      var userData = {
        Username: username,
        Pool: userPool,
      };
  
      var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);
      cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
      
      if(flow === 'password'){ //sign-in using password only

        /**
        authenticateUser method will trigger authentication with USER_SRP_AUTH flow
        USER_SRP_AUTH doesn't trigger define auth challenge, this will just authenticate the user using password 
        (if SMS/TOTP MFA is configured for the user it will also be triggered)
        **/
        cognitoUser.authenticateUser(authenticationDetails, authCallBack);
        
      }else if(flow === 'fido'){ // sign-in using FIDO authenticator only
        /**
        initiateAuth method will trigger authentication with CUSTOM_AUTH flow and will not provide any challenge data initially
        This will allow define auth challenge to respond with CUSTOM_CHALLENGE
        **/
        
        cognitoUser.setAuthenticationFlowType('CUSTOM_AUTH');
        cognitoUser.initiateAuth(authenticationDetails, authCallBack);
        
      }else{ //sign-in with password and use FIDO for 2nd factor
        /**
        authenticateUser method will trigger authentication with CUSTOM_AUTH flow and will provide SRP_A as the challenge
        This will allow define auth challenge to authenticate user using SRP first and then respond with CUSTOM_AUTH
        **/
        
        cognitoUser.setAuthenticationFlowType('CUSTOM_AUTH');
        cognitoUser.authenticateUser(authenticationDetails, authCallBack);
        
      }
  }
  
  authCallBack = {
  	
    onSuccess: function(result) {
      var accessToken = result.getAccessToken().getJwtToken();
      var idToken = result.getIdToken().getJwtToken();
      var refreshToken = result.getRefreshToken().getToken();
      
      $("#idToken").html('<b>ID Token</b><br>'+JSON.stringify(parseJwt(idToken),null, 2));
      $("#accessToken").html('<b>Access Token</b><br>'+JSON.stringify(parseJwt(accessToken), null, 2));
      //$("#refreshToken").html('<b>Refresh Token</b><br>'+refreshToken);

    },
    customChallenge: async function(challengeParameters) {
      // User authentication depends on challenge response
      
      console.log("Custom Challenge from Cognito:");console.log(challengeParameters);
      
      
      //----------get creds from security key or platform authenticator
      var signinOptions = {
         "challenge": base64url.decode(challengeParameters.challenge),//challenge was generated and sent from CreateAuthChallenge lambda trigger
         "timeout":1800000,
         "rpId":window.location.hostname,
         "userVerification":"preferred",
         "allowCredentials":[
            {
               "id": base64url.decode(challengeParameters.credId),
               "type":"public-key",
               "transports":["ble","nfc","usb","internal"]
            }
         ]
      }
      
      //get sign in credentials from authenticator
      const cred = await navigator.credentials.get({
        publicKey: signinOptions
      });
      
      //prepare credentials challenge response
      const credential = {};
      if (cred.response) {
        const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
        const authenticatorData = base64url.encode(cred.response.authenticatorData);
        const signature = base64url.encode(cred.response.signature);
        const userHandle = base64url.encode(cred.response.userHandle);
        
        credential.response = {clientDataJSON, authenticatorData, signature, userHandle};
      }
      
      //send credentials to Cognito VerifyAuthChallenge lambda trigger for verification
      cognitoUser.sendCustomChallengeAnswer(JSON.stringify(credential), this);
      
    },
    onFailure: function(err) {
    	console.error("Error authenticateUser:"+err);
      console.log(err.message || JSON.stringify(err));
    },
  }

  //---------------------Set of helper functions-----------------------//
  //------------------------------------------------------------------//

  //tabs UI
  $( function() {
    $( "#tabs" ).tabs();
  } );

  //helper function
  _fetch = async (path, payload = '') => {
    const headers = {'X-Requested-With': 'XMLHttpRequest'};
    if (payload && !(payload instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(payload);
    }
    const res = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: headers,
      body: payload
    });
    if (res.status === 200) {
      return res.json();
    } else {
      const result = await res.json();
      throw result.error;
    }
  };
  
  function parseJwt (token) {
      var base64Url = token.split('.')[1];
      var base64 = base64Url.replace('-', '+').replace('_', '/');
      return JSON.parse(window.atob(base64));
  };

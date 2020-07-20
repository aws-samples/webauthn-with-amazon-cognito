/**
 * 1- if user doesn't exist, throw exception
 * 2- if CUSTOM_CHALLENGE answer is correct, authentication successful
 * 3- if PASSWORD_VERIFIER challenge answer is correct, return custom challeneg (3,4 will be appliable if password+fido is selected)
 * 4- if challenge name is SRP_A, return PASSWORD_VERIFIER challenge (3,4 will be appliable if password+fido is selected)
 * 5- if 5 attempts with no correct answer, fail authentication
 * 6- default is to respond with CUSTOM_CHALLENEG --> password-less authentication
 * */

exports.handler = (event, context, callback) => {
    
    console.log(event);
    console.log(event.request.session);
    console.log(context);
    
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

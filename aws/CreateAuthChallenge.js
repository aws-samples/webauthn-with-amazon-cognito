const crypto = require("crypto");

exports.handler = async (event) => {
    console.log(event);
    
    var publicKeyCred = event.request.userAttributes["custom:publicKeyCred"];
    var publicKeyCredJSON = Buffer.from(publicKeyCred, 'base64').toString('ascii');
    console.log(JSON.parse(publicKeyCredJSON));
    
    const challenge = crypto.randomBytes(64).toString('hex');
    
    event.response.publicChallengeParameters = {
        credId: JSON.parse(publicKeyCredJSON).id, //credetnial id
        challenge: challenge
    };
    
    event.response.privateChallengeParameters = { challenge : challenge};
    console.log("privateChallengeParameters="+event.response.privateChallengeParameters);
    
    return event;
};

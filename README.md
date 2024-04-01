express-usercontrols

====================

### express-usercontrols is a module that interacts with express, to streamline login, payment and phone number verification while interacting with a mongoDB server to efficiently store all user information.

  
  
  

Setup
Full documentation + setup at https://tableflipped.xyz?project=express-usercontrols-1-2-1
-----

### 

1.  [Install mongoDB community edition server](https://www.mongodb.com/try/download/community) and [mongoDB compass](https://www.mongodb.com/try/download/compass)
\`>Create a new database with a name of your choice, and then 3 new collections. There MUST be a collection called users to store all user data, and a collection called codes if you are using ANY stripe billing functions  

6.  `$ npm install express-usercontrols`
7.  Get oauth2 credentials (get the client ID and the client secret), and set the redirect URI to: server-url/auth/provider-name/callback, for example https://tableflipped.xyz/auth/discord/callback. This module supports oauth2 for [discord](https://discord.com/developers/applications), [microsoft](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade), [google](https://console.cloud.google.com/apis/credentials), [github](https://github.com/settings/developers) and [other providers](https://www.passportjs.org) listed to work with passportjs`.
8.  Start express-usercontrols. (For uneccessary fields enter null)
    `const usercontrols = require("express-usercontrols")
       usercontrols.initialise(config)`
9.  Enter the oauth2 credentials into their respective functions.  
    `usercontrols.discord_oauth2(clientId, clientSecret)  
     usercontrols.google_oauth2(clientId, clientSecret) 
       usercontrols.github_oauth2(clientId, clientSecret) 
         usercontrols.microsoft_oauth2(clientId, clientSecret)`
    
10. Set up email/password login
    `usercontrols.local_auth(validate_email, default_mfa, auth_route, secret)`

11.  Set up sms verification with twilio/TWverify (optional)
    `usercontrols.sms_verify(authroute,authrouteverify,accountSid,authToken,verifySid, trial_balance)`

Your express app should now be set up with express-usercontrols! You can now...


1.  Validate hcaptcha-protected forms from routes (optional)  
    `app.post('/verify', validatecaptcha, async(req, res) =>{})`
2.  Check that a user is logged in and is unbanned on selected routes, and return their up-to-date user object in req.session.user. Optionally requiring them to have verified their phone number  
    `app.get('/dashboard', determineuser(true), async(req, res) =>{})` determineuser(verified_phone_number_required)


Full documentation + setup at https://tableflipped.xyz?project=express-usercontrols-1-2-1
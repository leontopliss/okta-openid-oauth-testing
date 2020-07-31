const okta = require('./okta_oauth_helper');
const jwtDecode = require('jwt-decode');
const dotenv = require('dotenv');
dotenv.config();

/**
 * The type of token we are requesting
 * token = an access token only (bearer token)
 * id_token = an id token only
 * token+id_token = both are returned in the same request
 * 
 * If you are testing API access you will only need a token
 */
const TYPE = 'token+id_token';

// The scopes we require in the token add any other scopes here
const SCOPES = ['openid', 'profile', 'email',];

(async () => {
    // Get config
    // Typically fetched from .env, check the example.env for params required
    // You probably want to adapt this to fetch the username and password
    // secrets management solution
    const oktaDomain = process.env.OKTA_DOMAIN;
    if (!oktaDomain) throw new Error('env variable OKTA_DOMAIN not set');
    const appClientId = process.env.APP_CLIENT_ID;
    if (!appClientId) throw new Error('env variable APP_CLIENT_ID not set');
    const callbackUri = process.env.CALLBACK_URI;
    if (!callbackUri) throw new Error('env variable CALLBACK_URI not set');
    const oktaUsername = process.env.OKTA_USERNAME;
    if (!oktaUsername) throw new Error('env variable OKTA_USERNAME not set');
    const oktaPassword = process.env.OKTA_PASSWORD;
    if (!oktaPassword) throw new Error('env variable OKTA_PASSWORD not set');


    // Get a session token
    const sessionToken = await okta.getSessionToken(oktaDomain, oktaUsername, oktaPassword)
        .catch(err => console.log(err));

    if (sessionToken) {
        // Get id and access tokens
        const [idToken, accessToken] = await okta.getOauthToken(oktaDomain, sessionToken, appClientId, callbackUri, SCOPES, TYPE)
            .catch(err => console.log(err));


        if (idToken) {
            // Print the raw ID Token
            console.log('Encoded ID Token:');
            console.log(idToken);

            // Print the decoded ID Token
            console.log('Decoded ID Token:');
            console.log(jwtDecode(idToken));
        }

        if (accessToken) {
            // Print the raw Access Token
            console.log('Encoded Access Token:');
            console.log(accessToken);

            // Print the decoded Access Token
            console.log('Decoded Access Token:');
            console.log(jwtDecode(accessToken));
        }

        // You can now take the access token and pass it to 
        // your endpoint in a header to access protected resources
    }
})();
const fetch = require('isomorphic-fetch');
const url = require('url');
const querystring = require('querystring');
const crypto = require('crypto');

/**
 * Get an Okta Session Token
 *
 *  @param {String} oktaDomain The Okta domain we are accessing eg. acme.okta.com
 *  @param {String} username A username of a user we want a session token for
 *  @param {String} password A password of a user we want a session token for
 *  @returns {String} Okta session token for a given username
 */
async function getSessionToken(oktaDomain, username, password) {
    // Make a call to the authn api to get a sessionToken
    const fetchResponse = await fetch(`https://${oktaDomain}/api/v1/authn`, {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username: username,
            password: password
        })
    })

    const response = await fetchResponse.json();

    // Check for errors
    if (response.status && response.status != 'SUCCESS') {
        // AuthN error
        throw new Error('authn status: ' + response.status);
    } else if (response.errorSummary) {
        //Okta API error
        throw new Error('okta api error while atttempting to get session token: ' + response.errorSummary)
    }

    return response.sessionToken;
}

/**
 * Get an Okta ID or Access Token
 *
 *  @param {String} oktaDomain The Okta domain we are accessing eg. acme.okta.com
 *  @param {String} sessionToken A session token for the user. can be generated with the getSessionToken function
 *  @param {String} appClientId The client ID of the application in the Okta environment
 *  @param {String} appRedirectUri The application redirect URL, mandatory in the request (but not used) and
 *      must match a redirect url configured against the application
 *  @param {Array} scopes The scopes we are requesting in the token
 *  @param {String} type Whether an id token is required (id_token), access token (token), or both (id_token+token)
 *      by default both are returned
 *  @returns {String} An OAuth access tokens
 */
async function getOauthToken(oktaDomain, sessionToken, appClientId, appRedirectUri, scopes, type='id_token+token') {

    // Parse the scopes array into a suitable string
    var scopeString;
    for (var i = 0; i < scopes.length; i++) {
        if (i == 0) {
            scopeString = scopes[i];
        } else {
            scopeString = scopeString + '+' + scopes[i];
        }
    }

    // nonce: A value that is returned in the ID token and should be random. It is used to mitigate replay attacks.
    // random 32 char string
    const nonce = crypto.randomBytes(16).toString('base64');
    // state: A value to be returned in the token. 
    // The client application can use it to remember the state of its interaction with the end user at the time of the authentication call
    // random 32 char string
    const state = crypto.randomBytes(16).toString('base64');

    // Send the session token as a query param in a GET request to the authorize api
    const authorizeRes = await fetch(
        `https://${oktaDomain}/oauth2/default/v1/authorize?` +
        `response_type=${type}&` +
        `scope=${scopeString}&` +
        `state=${state}&` +
        `nonce=${nonce}&` +
        `client_id=${appClientId}&` +
        `redirect_uri=${appRedirectUri}&` +
        `sessionToken=${sessionToken}`);

    var idToken;
    var accessToken;

    if (authorizeRes.url) {
        // Parse the fragment on the url returned
        const fragmentParams = querystring.parse(url.parse(authorizeRes.url).hash.replace('#', ''));
        if (fragmentParams.error_description) {
            // if the fragment contains an Okta generated error 
            throw new Error(fragmentParams.error_description);
        } else if (fragmentParams.access_token || fragmentParams.id_token) {
            if (fragmentParams.access_token) accessToken = fragmentParams.access_token;
            if (fragmentParams.id_token) idToken = fragmentParams.id_token;
        } else {
            // The URL has an unexpected pattern
            throw new Error('unexpected response, no token in the fragment. full URL returned: ' + authorizeRes.url);
        }
    } else {
        // No url parameter in the response
        throw new Error('url not returned, full response: ' + authorizeRes);
    }

    return [idToken, accessToken];
    
}

module.exports = {
    getSessionToken: getSessionToken,
    getOauthToken: getOauthToken
}
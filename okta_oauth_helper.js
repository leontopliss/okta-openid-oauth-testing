/**
    MIT License

    Copyright (c) 2020 Leon Topliss

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

const fetch = require('node-fetch');
const url = require('url');
const querystring = require('querystring');
const crypto = require('crypto');

/**
 * Get an Okta Session Token
 *
 *  @param {String} oktaDomain the Okta domain we are accessing eg. acme.okta.com
 *  @param {String} username a username of a user we want a session token for
 *  @param {String} password a password of a user we want a session token for
 *  @param {String} passCode optional - If MFA is enabled the Okta Verify OTP
 *  
 *  Note: A OTP can be generated with the factor secret and a library such as otplib
 * 
 *  @returns {String} Okta session token for a given username
 */
async function getSessionToken(oktaDomain, username, password, passCode=null) {
    // Make a call to the authn api to get a sessionToken
    const fetchResponseAuth = await fetch(`https://${oktaDomain}/api/v1/authn`, {
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

    const authResponse = await fetchResponseAuth.json();

    // return the session token
    if (authResponse.status == 'SUCCESS' || authResponse.sessionToken) {
        // If Okta responds with a session token then use it
        let sessionToken = authResponse.sessionToken
        return sessionToken;
    } else if (authResponse.status && authResponse.status == 'MFA_REQUIRED') {
        // if the status is MFA_REQUIRED at state token and list of factors
        // is returned from the auth request
        // Along with the passCode we can convert these three items to a sessionToken
        if (!passCode) {
            throw new Error('MFA required and pass code not set');    
        }
        const stateToken = authResponse.stateToken;
        const factors = authResponse._embedded.factors;
        let sessionToken = await mfaChallange(stateToken, passCode, factors);
        return sessionToken;
    } 
    
    // Error handling
    if (authResponse.status) {
        // AuthN API error
        throw new Error('error authn status: ' + authResponse.status);
    } else if (authResponse.errorSummary) {
        // Generic Okta API error
        throw new Error('okta api error: ' + authResponse.errorSummary)
    } else {
        throw new Error('error while attempting to authenticate')
    }
}


/**
 *  Complete MFA Challenge
 *  stateToken and factors are returned from the authentication request 
 *  that returned MFA_REQUIRED (https://${oktaDomain}/api/v1/authn)
 *
 *  @param {String} stateToken the state token
 *  @param {String} passCode if MFA is enabled the Okta Verify OTP
 *  @param {Object} factors a list of factors
 *  
 *  @returns {String} Okta session token for a given username
 */
async function mfaChallange(stateToken, passCode, factors) {
    // The Okta OTP Verify Factor is token:software:totp
    const factorType = 'token:software:totp';

    // Loop through the available factors
    // Each factor has a name and a HATEOAS style link is
    // returned for factor verification. We need to take the relevant link
    var factorUrl;
    factors.forEach(function(factor) {
        if (factor.factorType == factorType){
            factorUrl = factor._links.verify.href;
        }
    });

    if (!factorUrl) {
        throw new Error('could not find the factor: ' + factorType + ' make sure it is enrolled')
    }

    // POST the state token and OTP pass code to the factor verify endpoint
    // if successful it will return a session token
    const fetchResponseFactor = await fetch(factorUrl, {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            stateToken: stateToken,
            passCode: passCode
        })
    })

    const responseFactor = await fetchResponseFactor.json();

    // Return the session token
    if (responseFactor.status == 'SUCCESS' && responseFactor.sessionToken) {
        let sessionToken = responseFactor.sessionToken;
        return sessionToken;
    }

    // Error handling
    if (responseFactor.status) {
        // AuthN API error
        throw new Error('error authn status: ' + responseFactor.status);
    } else if (responseFactor.errorSummary) {
        // Generic Okta API error
        throw new Error('okta api error: ' + responseFactor.errorSummary)
    } else {
        throw new Error('error while attempting to validate MFA')
    }
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

    // construct the authorization url
    // this includes the session token which will be swapped for an id/access token
    const authorizeUrl = `https://${oktaDomain}/oauth2/default/v1/authorize?` +
        `response_type=${type}&` +
        `scope=${scopeString}&` +
        `state=${state}&` +
        `nonce=${nonce}&` +
        `client_id=${appClientId}&` +
        `redirect_uri=${appRedirectUri}&` +
        `sessionToken=${sessionToken}`

    // Call the authorization URL
    // The URL returns a redirect carrying id/access tokens in a fragment
    // We don't follow the redirect as this is necessary 
    // and if it doesn't exist which might be the case during deployment an error results
    const authorizeRes = await fetch(authorizeUrl, { 
        method: 'GET',
        redirect: 'manual'
    }).catch(err => console.log(err));

    var idToken;
    var accessToken;

    // The auth url returns a redirect. The redirect contains the id/access token fragments
    // get the redirect from the Location header
    const locationHeader = authorizeRes.headers.get('Location');

    // Check the authorization URL returned a redirect
    // and check the location header is set
    if (authorizeRes.status == 302 && locationHeader) {
        // Parse the fragment returned in the location header
        const fragmentParams = querystring.parse(url.parse(locationHeader).hash.replace('#', ''));
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
        throw new Error('url not returned, status: ' + authorizeRes.status + ' message: ' + authorizeRes.statusText);
    }

    return [idToken, accessToken];
    
}

module.exports = {
    getSessionToken: getSessionToken,
    getOauthToken: getOauthToken
}
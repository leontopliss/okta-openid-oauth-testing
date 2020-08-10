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

const okta = require('./okta_oauth_helper');
const jwtDecode = require('jwt-decode');
const otplib = require('otplib');
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

    // OTP Secret is optional, we will only use this
    // if Okta responds MFA required
    const otpSecret = process.env.OTP_SECRET;
    if (otpSecret && otpSecret.length < 16) {
        throw new Error('OTP secret is set but is too short');
    }

    // Get a session token
    var sessionToken;
    if (otpSecret) {
        // Using otplib to generate a code from the secret provided
        const passCode = otplib.authenticator.generate(otpSecret);
        console.log('OTP Code Generated: ' + passCode);
        sessionToken = await okta.getSessionToken(oktaDomain, oktaUsername, oktaPassword, passCode)
            .catch(err => console.log(err));
    } else {
        sessionToken = await okta.getSessionToken(oktaDomain, oktaUsername, oktaPassword)
            .catch(err => console.log(err));
    }
    

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



})().catch(err => console.log(err));
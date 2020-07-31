# Okta OpenID Connect and OAuth Testing

An example implimentation to get an OAuth access token using user credentials (as an alternative to client credentials which would typically be used for system access)

The example can be used without user interaction making it suitable for automated testing.

How this works:
* Fetch a Okta session token (using the Okta API's and not part of the OAuth service) by authenticating with a username and password
* Okta has a facility to exchange a session token for an OpenID Connect or OAuth, id or bearer token

NOTE: This code is for testing only, to retrieve tokens in an application (SPA) please use a relevant SDK eg..
* Angular Okta SDK: https://developer.okta.com/code/angular/
* Angular Alternative: https://github.com/manfredsteyer/angular-oauth2-oidc
* React Okta SDK: https://developer.okta.com/code/react/
* AppAuth: https://appauth.io/
* or another standards based OAuth implimentation...

## Testing

1.	Create an Okta username and password for testing. They must be assigned to the relevant application and have MFA disabled
1.	npm install
1.	Copy sample.env to .env and update the variables. The .env should be similar to the following example:

	```
	OKTA_DOMAIN=acme.oktapreview.com
	APP_CLIENT_ID=0ob60tzlq4amWsF8x0x6
	APP_REDIRECT_URI=https://myapplicationurl.acme.com/implicit/callback
	OKTA_USERNAME=john.smith@acme.com
	OKTA_PASSWORD=<users password>
	```

## Token type

You can request either an ID Token, Access Token (Bearer Token) or both tokens in the same request

In index.js change TYPE to:
 * 'token' for an access token only (bearer token)
 * 'id_token' for an id token only
 * 'token+id_token' to get both tokens in the same response

In a SPA + API Architecture the ID Token is for the consumption of the SPA only only the bearer token is passed to API resources.




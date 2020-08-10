# Okta OpenID Connect and OAuth Testing

An example implementation to get an OAuth access token using user credentials (as an alternative to client credentials which would typically be used for system access)

The example can be used without user interaction making it suitable for automated testing.

How this works:
1. Fetch a Okta session token (using the Okta API's and not part of the OAuth service) by authenticating with a username and password
1. If MFA is enabled step 1 won't return a session token. We can then take some parameters from step 1 to call another endpoint to verify MFA and fetch a session token (as described below)
1. Okta has a facility to exchange a session token for an OpenID Connect or OAuth, id or bearer token

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
	# OTP_SECRET optional
	OTP_SECRET=<16 Digit OTP Secret>
	```

## Token type

You can request either an ID Token, Access Token (Bearer Token) or both tokens in the same request

In index.js change TYPE to:
 * 'token' for an access token only (bearer token)
 * 'id_token' for an id token only
 * 'token+id_token' to get both tokens in the same response

## MFA

If you wish to use this script with MFA it's possible to specify the OTP_SECRET in the .env file

If attempting to authenticate with an account that doesn't have MFA enabled the script will return MFA_ENROLL

To enroll in MFA
 * login to the Okta web interface using the username and password
 * click setup on Okta Verify
 * either iPhone or Android
 * click "Can't scan?"
 * "Setup manually without Push notification"
 * Copy the secret from the box into OTP_SECRET in the env file (copy and paste doesn't work)
 * Click next
 * Run the script and take the code from the top of the output. Enter this in the 'Enter Code' box and click Verify.
 * Run through the remain steps

Now when the script runs it will generate an OTP Code from the secret. When authenticating with a username and password Okta will return MFA_REQUIRED, along with other parameters including a list of factors and a state token

The list of factors included HATEOAS style links for factor verification. The script finds the link for the Okta Verify OTP factor and passes the state token returned in the initial authentication along with the OTP code. This now returns the session token




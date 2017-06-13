# PasswordPing JavaScript Client Library

## TOC

This README covers the following topics:

- [Installation](#installation)
- [API Overview](#api-overview)
- [The PasswordPing constructor](#the-passwordping-constructor)

## Installation

```sh
$ npm install passwordping
```

## API Overview

Here's the API in a nutshell.

```js
var PasswordPing = require('passwordping');

// Create a new PasswordPing instance - this is our primary interface for making API calls
var passwordping = new PasswordPing(YOUR_API_KEY, YOUR_API_SECRET);

// Check whether a password has been compromised
passwordping.checkPassword('password-to-test', function (error, passwordCompromised) {
    if (error) {
        console.log('Error calling API: ' + error);
    }
    else if (passwordCompromised === true) {
        console.log('Password is compromised');
    }
    else {
        console.log('Password is not compromised');
    }
});

// Check whether a specific set of credentials are compromised
passwordping.checkCredentials('test@passwordping.com', 'password-to-test', function (error, credsCompromised) {
    if (error) {
        console.log('Error calling API: ' + error);
    }
    else if (credsCompromised === true) {
        console.log('Credentials are compromised');
    }
    else {
        console.log('Credentials are not compromised');
    }
});

// get all exposures for the given user
passwordping.getExposuresForUser('test@passwordping.com', function(error, result) {
    if (error) {
        console.log('Error calling API: ' + error);
    }
    else {
        console.log(exposures.count + ' exposures found for test@passwordping.com');

        // now get the full details for the first exposure returned in the list
        passwordping.getExposureDetails(result.exposures[0], function(error, exposureDetails) {
            if (error) {
                console.log('Error calling API: ' + error);
            }
            else {
                console.log('First exposure for test@passwordping.com was ' + exposureDetails.title);
            }
        });
    }
});

```

More information in reference format can be found below.

## The PasswordPing constructor

The standard constructor takes the API key and secret you were issued on PasswordPing signup.

```js
var passwordping = new PasswordPing(YOUR_API_KEY, YOUR_API_SECRET);
```

If you were instructed to use an alternate API host, you may call the overloaded constructor and pass the host you were provided.

```js
var passwordping = new PasswordPing(YOUR_API_KEY, YOUR_API_SECRET, "api-alt.passwordping.com");
```

# Enzoic JavaScript Client Library

> :warning: In version 3.0.0, the Enzoic JavaScript library has switched to using promises rather than callbacks.  This is a breaking change and will require updates to code that used previous versions of this library.

## TOC

This README covers the following topics:

- [Installation](#installation)
- [API Overview](#api-overview)
- [The Enzoic constructor](#the-enzoic-constructor)
- [Passwords API Examples](#passwords-api-examples)
- [Credentials API Examples](#credentials-api-examples)
- [Exposures API Examples](#exposures-api-examples)
- [Breach Monitoring by User API Examples](#breach-monitoring-by-user-api-examples)
- [Breach Monitoring by Domain API Examples](#breach-monitoring-by-domain-api-examples)

## Installation

```sh
$ npm install @enzoic/enzoic
```

## API Overview

Below is some simple example code which demonstrates the usage of the API. 

```js
const Enzoic = require('enzoic');

// Create a new Enzoic instance - this is our primary interface for making API calls
const enzoic = new Enzoic(YOUR_API_KEY, YOUR_API_SECRET);

// Check whether a specific set of credentials are compromised
const credsCompromised = await enzoic.checkCredentials('test@enzoic.com', 'password-to-test'); 

if (credsCompromised === true) {
    console.log('Credentials are compromised');
}
else {
    console.log('Credentials are not compromised');
}
```

More information in reference format can be found below.

## The Enzoic constructor

The first step to use the API is to instantiate the Enzoic Client with the API key and secret you were issued on Enzoic signup.

```js
const Enzoic = require('enzoic');

const enzoic = new Enzoic(YOUR_API_KEY, YOUR_API_SECRET);
```

If you were instructed to use an alternate API host, you may call the overloaded constructor and pass the host you were provided.

```js
const Enzoic = require('enzoic');

const enzoic = new Enzoic(YOUR_API_KEY, YOUR_API_SECRET, "api-alt.enzoic.com");
```

## Passwords API Examples

See
https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/passwords-api

```js
// Check whether a password has been compromised
const passwordCompromised = await enzoic.checkPassword('password-to-test');

if (passwordCompromised === true) {
    console.log('Password is compromised');
}
else {
    console.log('Password is not compromised');
}
```

## Credentials API Examples

See https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/credentials-api

```js
// Check whether a specific set of credentials are compromised
const credsCompromised = await enzoic.checkCredentials('test@enzoic.com', 'password-to-test'); 

if (credsCompromised === true) {
    console.log('Credentials are compromised');
}
else {
    console.log('Credentials are not compromised');
}

// Enhanced version of checkCredentials offering more control over performance.
// The call introduces an options object parameter, which supports the following settings:
//
// lastCheckDate: 
// The timestamp for the last check you performed for this user.
// If the date/time you provide for the last check is greater than the timestamp Enzoic has for the last
// breach affecting this user, the check will not be performed.  This can be used to substantially increase performance.
//
// excludeHashAlgorithms: 
// An array of PasswordTypes to ignore when calculating hashes for the credentials check.   
// By excluding computationally expensive PasswordTypes, such as BCrypt, it is possible to balance the performance of this
// call against security.
//
const credsCompromised = await enzoic.checkCredentialsEx('test@enzoic.com', 'password-to-test', 
    {
        lastCheckDate: new Date('2016-12-10T02:05:03.000Z'), 
        excludeHashAlgorithms: [8, 11, 12] // see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/password-hash-algorithms 
    });

if (credsCompromised === true) {
    console.log('Credentials are compromised');
}
else {
    console.log('Credentials are not compromised');
}

// get all passwords Enzoic has for the specified user 
// returns results per 
// https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/credentials-api/cleartext-credentials-api
const userPasswordsResponse = await enzoic.getUserPasswords("eicar_0@enzoic.com");

// print user passwords
for (let i = 0; i < userPasswordsResponse.passwords.length; i++) {
    console.log('Password: ' + userPasswordsResponse.passwords[i].Password + '\n');
}
```

## Exposures API Examples

See https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api

```js
// get all exposures for the given user
const exposuresForUser = await enzoic.getExposuresForUser('test@enzoic.com');
console.log(exposuresForUser.exposures.count + ' exposures found for test@enzoic.com');
    
// now get the full details for the first exposure returned in the list
const exposureDetails = await enzoic.getExposureDetails(result.exposures[0]);
console.log('First exposure for test@enzoic.com was ' + exposureDetails.title);

// get all exposures for a given domain - second parameter indicates whether to include exposure details in results
// returns paged results per 
// https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-a-domain
const exposuresForDomain = enzoic.getExposuresForDomainEx('enzoic.com', true, 20, null);
console.log(exposuresForDomain.count + ' exposures found for enzoic.com');

// print first page of results
for (let i = 0; i < exposuresForDomain.exposures.length; i++) {
    console.log('Exposure: ' + exposuresForDomain.exposures.title + '\n');
}

// if pagingToken present, get next page of results
if (exposuresForDomain.pagingToken) {
    const secondPageResults = await enzoic.getExposuresForDomainEx('enzoic.com', true, 20, exposuresForDomain.pagingToken);
    // ...process second page of results, etc.
}

// get all users exposed for a given domain
// returns paged results per 
// https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-all-email-addresses-in-a-domain
const exposedUsers = await enzoic.getExposedUsersForDomain('enzoic.com', 20, null);

// print first page of results
for (let i = 0; i < exposedUsers.users.length; i++) {
   console.log('Exposed User: ' + exposedUsers.users[i].username + '\n');
}

// if pagingToken present, get next page of results
if (exposedUsers.pagingToken) {
    const secondPageResults = await enzoic.getExposedUsersForDomain('enzoic.com', 20, exposedUsers.pagingToken); 
    // ...process second page of results, etc.
}
```

## Breach Monitoring by User API Examples

See https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user

```js
// a couple of email addresses - note: these will get hashed before submission to the Enzoic API
const arrUsernames = [
    'eicar_0@enzoic.com', 
    'eicar_1@enzoic.com'
];

// subscribe for alerts for these users
const addResponse = await enzoic.addUserAlertSubscriptions(arrUsernames);

console.log('New subscriptions added: ' + addResponse.added + '\n' + 
    'Subscriptions already existing: ' + addResponse.alreadyExisted);

// delete subscriptions for these users
const deleteResponse = await enzoic.deleteUserAlertSubscriptions(arrUsernames);

console.log('Subscriptions deleted: ' + deleteResponse.deleted + '\n' + 
    'Subscriptions not found: ' + deleteResponse.notFound);

// check whether a user is already subscribed
const subscribed = await enzoic.isUserSubscribedForAlerts(arrUsernames[0]);

if (subscribed === true) {
   console.log('User already subscribed');
}
else {
   console.log('User not already subscribed');
}    

// get all users subscribed for alerts on this account 
// returns paged results per 
// https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#retrieve-current-breach-alert-subscriptions
const subscriptionsResponse = await enzoic.getUserAlertSubscriptions(4 /* page size */, null /* paging token - null on first call */);

// print first page of results
for (let i = 0; i < subscriptionsResponse.usernameHashes.length; i++) {
   console.log('Username Hash: ' + subscriptionsResponse.usernameHashes[i] + '\n');
}

// if pagingToken present, get next page of results
if (subscriptionsResponse.pagingToken) {
    const secondPageResponse = await enzoic.getUserAlertSubscriptions(4, subscriptionsResponse.pagingToken);
    // ...process second page of results, etc.
}
```

## Breach Monitoring by Domain API Examples

See https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain

```js
// test domains for alert subscriptions
const arrDomains = [
    'testdomain1.com', 
    'testdomain2.com' 
];

// subscribe for alerts for these domains
const addDomainsResponse = await enzoic.addDomainAlertSubscriptions(arrDomains); 

console.log('New subscriptions added: ' + addDomainsResponse.added + '\n' + 
    'Subscriptions already existing: ' + addDomainsResponse.alreadyExisted);

// delete subscriptions for these domains
const deleteDomainsResponse = await enzoic.deleteDomainAlertSubscriptions(arrDomains);

console.log('Subscriptions deleted: ' + deleteDomainsResponse.deleted + '\n' + 
    'Subscriptions not found: ' + deleteDomainsResponse.notFound);

// check whether a domain is already subscribed
const domainSubscribed = await enzoic.isDomainSubscribedForAlerts(arrDomains[0]); 

if (subscribed === true) {
   console.log('Domain already subscribed');
}
else {
   console.log('Domain not already subscribed');
}    

// get all users subscribed for alerts on this account 
// returns pages results per 
// https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#retrieve-current-breach-alert-subscriptions
const domainSubsResponse = await enzoic.getDomainAlertSubscriptions(4 /* page size */, null /* paging token - null on first call */);

// print first page of results
for (let i = 0; i < domainSubsResponse.domains.length; i++) {
   console.log('Domain: ' + domainSubsResponse.domains[i] + '\n');
}

// if pagingToken present, get next page of results
if (domainSubsResponse.pagingToken) {
    const secondPageResponse = await enzoic.getDomainAlertSubscriptions(4, domainSubsResponse.pagingToken);
    // ...process second page of results, etc.
}
```

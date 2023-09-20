'use strict';
const https = require('https');
const Hashing = require('./src/hashing');
const PasswordType = require('./src/passwordtype');

/**
 * Creates a new instance of Enzoic
 *
 * @param sAPIKey your Enzoic API key
 * @param sSecret your Enzoic API secret
 * @param sBaseAPIHost override the default base API URL with an alternate - typically not necessary
 * @constructor
 */
function Enzoic(sAPIKey, sSecret, sBaseAPIHost, sEncryptionKey) {
    this.apiKey = sAPIKey;
    this.secret = sSecret;
    this.host = sBaseAPIHost;
    this.encryptionKey = sEncryptionKey;

    if (!this.apiKey || !this.secret) {
        throw 'API key and Secret must be provided';
    }

    this.authString = new Buffer(this.apiKey + ':' + this.secret).toString('base64');

    if (!this.host) {
        // default host
        this.host = 'api.enzoic.com';
    }
}

/**
 * Calls the Enzoic CheckCredentials API in a secure fashion to check whether the provided username and password
 * are known to be compromised.
 * This call is made securely to the server - only a salted and hashed representation of the credentials are passed and
 * the salt value is not passed along with it.
 * The Ex version of the call includes an option object parameter that allow the caller to tweak the performance of the call.
 * <p>
 * options.lastCheckDate allows the caller to pass in the date of the last check that was made for the credentials in question.
 * If the lastCheckDate is after the last new breach that was recorded for those credentials, there is no need to check them again
 * and no hashes will be calculated and no credentials API call will be made.  This can substantially improve performance.
 * Note that for this to work, the calling application will need to cache the date/time the last credentials check was
 * made for a given set of user credentials and invalidate reset that date/time if the credentials are changed.
 * <p>
 * options.excludeHashAlgorithms allows the calling application to exclude certain expensive password hash algorithms from being
 * calculated (e.g. BCrypt).  This can reduce the CPU impact of the call as well as potentially decrease the latency
 * it introduces.
 * @param sUsername the username to check
 * @param sPassword the password to check
 * @param oOptions an object with lastCheckDate and/or excludeHashAlgorithms specified
 * @returns {Promise<{exposures: *[]}|boolean>} if true, then the credentials are known to be compromised
 */
Enzoic.prototype.checkCredentialsEx = async function (sUsername, sPassword, oOptions) {
    const accountsPath = '/v1/accounts';
    const credentialsPath = '/v1/credentials';

    const excludeHashAlgorithms = (oOptions && oOptions.excludeHashAlgorithms)
        ? oOptions.excludeHashAlgorithms
        : [];
    const lastCheckDate = (oOptions && oOptions.lastCheckDate)
        ? oOptions.lastCheckDate
        : new Date('1980-01-01');
    const includeExposures = (oOptions && oOptions.includeExposures)
        ? oOptions.includeExposures
        : false;

    const accountResponse = await this.makeRestCall(accountsPath,
        'username=' + Hashing.sha256(sUsername.toLowerCase()), 'GET', null);
    if (accountResponse === 404) {
        return false;
    }
    else {
        // first check the date threshold
        if (new Date(accountResponse.lastBreachDate) <= lastCheckDate) {
            // if we checked these credentials after the date of the last breach in the Enzoic system,
            // bail out and return false
            return false;
        }

        const hashesRequired = accountResponse.passwordHashesRequired;

        let bcryptCount = 0;
        let queryString = '';
        const credentialHashCalcs = [];

        for (let i = 0; i < hashesRequired.length; i++) {
            const hashSpec = hashesRequired[i];

            if (excludeHashAlgorithms.indexOf(hashSpec.hashType) >= 0) {
                // skip this one if user chose to exclude this type
                continue;
            }

            // bcrypt gets far too expensive for good response time if there are many of them to calculate.
            // some mostly garbage accounts have accumulated a number of them in our DB and if we happen to hit one it
            // kills performance, so short circuit out after at most 2 BCrypt hashes
            if (hashSpec.hashType !== PasswordType.BCrypt || bcryptCount <= 2) {
                if (hashSpec.hashType === PasswordType.BCrypt) {
                    bcryptCount++;
                }
            }

            if (hashSpec.hashType) {
                credentialHashCalcs.push(
                    this.calcCredentialHash(sUsername.toLowerCase(), sPassword, accountResponse.salt, hashSpec)
                );
            }
        }

        // wait for all the credential hash calculations to finish
        try {
            const credentialsHashes = await Promise.all(credentialHashCalcs);

            // build the query string for the credentials call
            for (let i = 0; i < credentialsHashes.length; i++) {
                if (credentialsHashes[i]) {
                    if (queryString.length === 0) {
                        queryString += "partialHashes=" + credentialsHashes[i].substr(0, 10);
                    }
                    else {
                        queryString += "&partialHashes=" + credentialsHashes[i].substr(0, 10);
                    }
                }
            }

            if (includeExposures === true) {
                queryString += "&includeExposures=1";
            }

            if (queryString.length > 0) {
                // make the credentials call
                const credsResponse = await this.makeRestCall(credentialsPath, queryString, "GET", null);
                if (credsResponse !== 404) {
                    if (includeExposures === true) {
                        const results = {exposures: []};
                        let found = false;

                        // compare the candidate results to the local full hashes
                        for (let i = 0; i < credsResponse.candidateHashes.length; i++) {
                            if (credentialsHashes.indexOf(credsResponse.candidateHashes[i].hash) >= 0) {
                                results.exposures.push(...credsResponse.candidateHashes[i].exposures);
                                found = true;
                            }
                        }

                        if (found === true) {
                            // return results in this case
                            results.exposures = [...new Set(results.exposures)];
                            return results;
                        }
                    }
                    else {
                        // compare the candidate results to the local full hashes
                        for (let i = 0; i < credsResponse.candidateHashes.length; i++) {
                            if (credentialsHashes.indexOf(credsResponse.candidateHashes[i]) >= 0) {
                                return true;
                            }
                        }
                    }
                }

                return false;
            }
            else {
                return false;
            }
        }
        catch (err) {
            console.error('Error while calculating password hashes: ' + err);
            throw 'Error while calculating password hashes: ' + err;
        }
    }
};

/**
 * Calls the Enzoic CheckCredentials API in a secure fashion to check whether the provided username and password
 * are known to be compromised.
 * This call is made securely to the server - only a salted and hashed representation of the credentials are passed and
 * the salt value is not passed along with it.
 * @param sUsername the username to check
 * @param sPassword the password to check
 * @returns {Promise<{exposures: *[]}|boolean>} if true, then the credentials are known to be compromised
 */
Enzoic.prototype.checkCredentials = async function (sUsername, sPassword) {
    return this.checkCredentialsEx(sUsername.toLowerCase(), sPassword, null);
};

/**
 * Checks whether the provided password is in the Enzoic database of known, compromised passwords.
 * @param sPassword The cleartext password to be checked
 * @returns {Promise<boolean>} If true, the password is a known, compromised password and should not be used.
 */
Enzoic.prototype.checkPassword = async function (sPassword) {
    const path = '/v1/passwords';
    const md5 = Hashing.md5(sPassword);
    const sha1 = Hashing.sha1(sPassword);
    const sha256 = Hashing.sha256(sPassword);
    const queryString = 'partial_md5=' + md5.substr(0, 10) +
        '&partial_sha1=' + sha1.substr(0, 10) +
        '&partial_sha256=' + sha256.substr(0, 10);

    const result = await this.makeRestCall(path, queryString, 'GET', null);
    if (typeof (result) === 'object') {
        // loop through and see if we have a match
        for (let i = 0; i < result.candidates.length; i++) {
            if (result.candidates[i].md5 === md5 ||
                result.candidates[i].sha1 === sha1 ||
                result.candidates[i].sha256 === sha256) {
                return true;
            }
        }
    }

    return false;
};

/**
 * Returns all of the credentials Exposures that have been found for a given username.
 * see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-an-email-address
 * @param sUsername The username or email address of the user to check
 * @param bIncludeExposureDetails whether to retrieve the details for each exposure and include them inline in the response
 * @returns {Promise<unknown>} see link for details on response content
 */
Enzoic.prototype.getExposuresForUser = async function (sUsername, bIncludeExposureDetails = false) {
    const path = '/v1/exposures-for-usernames';

    const response = await this.makeRestCall(path, 'username=' + Hashing.sha256(sUsername.toLowerCase()) +
        (bIncludeExposureDetails === true ? "&includeExposureDetails=1" : ""),
        'GET', null);
    if (response === 404) {
        // don't have this email in the DB - return empty response
        return {
            count: 0,
            exposures: []
        };
    }
    else {
        return response;
    }
};

/**
 * Returns a list of all users for a given email domain who have had credentials revealed in exposures.
 * The results of this call are paginated.  pagingToken is a value returned with each page of results and should be
 * passed into this call to retrieve the next page of results.
 * see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-all-email-addresses-in-a-domain
 * @param sDomain the domain to check
 * @param iPageSize The results of this call are paginated.  iPageSize can be any value from 1 to 1000 (default 1000).
 * @param sPagingToken a value returned with each page of results and should be passed into this call to retrieve the next page of results
 * @returns {Promise<unknown>} see link for details on response content
 */
Enzoic.prototype.getExposedUsersForDomain = async function (sDomain, iPageSize, sPagingToken) {
    const path = '/v1/exposures';

    let queryString = 'accountDomain=' + sDomain;

    if (iPageSize) {
        queryString += '&pageSize=' + iPageSize;
    }

    if (sPagingToken) {
        queryString += '&pagingToken=' + sPagingToken;
    }

    const response = await this.makeRestCall(path, queryString, 'GET', null);
    if (response === 404) {
        // don't have this email in the DB - return empty response
        return {
            count: 0,
            users: []
        };
    }
    else {
        return response;
    }
};

/**
 * Returns a list of all exposures found involving users with email addresses from a given domain.
 * The result will be an array of exposure IDs which can be used with the GetExposureDetails call to retrieve details, or
 * if bIncludeExposureDetails was specified, the details will be included in the response inline.
 * Max number returned in a single call is 100.  To retrieve additional results, use getExposuresForDomainEx.
 * @param sDomain the domain to check
 * @param bIncludeExposureDetails whether to include exposure details inline or just the exposure IDs
 * @returns {Promise<unknown>} if bIncludeExposureDetails is false, this will be an array of exposure IDs which can be
 * used with the getExposureDetails call to retrieve details.  If bIncludeExposureDetails is true, this will be an array
 * with full exposure details.  See link above for full details on the response content.
 */
Enzoic.prototype.getExposuresForDomain = async function (sDomain, bIncludeExposureDetails) {
    return this.getExposuresForDomainEx(sDomain, bIncludeExposureDetails, null, null);
};

/**
 * Returns a list of all exposures found involving users with email addresses from a given domain.
 * The result will be an array of exposure IDs which can be used with the GetExposureDetails call to retrieve details, or
 * if bIncludeExposureDetails was specified, the details will be included in the response inline.
 * The results of this call are paginated.  pagingToken is a value returned with each page of results and should be
 * passed into this call to retrieve the next page of results.
 * see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-a-domain
 * @param sDomain the domain to check
 * @param bIncludeExposureDetails whether to include exposure details inline or just the exposure IDs
 * @param iPageSize The results of this call are paginated.  iPageSize can be any value from 1 to 500 (default 100).
 * @param sPagingToken a value returned with each page of results and should be passed into this call to retrieve the next page of results.
 * @returns {Promise<unknown>} if bIncludeExposureDetails is false, this will be an array of exposure IDs which can be
 * used with the getExposureDetails call to retrieve details.  If bIncludeExposureDetails is true, this will be an array
 * with full exposure details.  See link above for full details on the response content.
 */
Enzoic.prototype.getExposuresForDomainEx = async function (sDomain, bIncludeExposureDetails, iPageSize, sPagingToken) {
    const path = '/v1/exposures';

    let queryString = 'domain=' + sDomain;

    if (bIncludeExposureDetails === true) {
        queryString += '&includeExposureDetails=1';
    }

    if (iPageSize) {
        queryString += '&pageSize=' + iPageSize;
    }

    if (sPagingToken) {
        queryString += '&pagingToken=' + sPagingToken;
    }

    const response = await this.makeRestCall(path, queryString, 'GET', null);
    if (response === 404) {
        // don't have this domain in the DB - return empty response
        return {
            count: 0,
            exposures: []
        };
    }
    else {
        return response;
    }
};

/**
 * Returns the detailed information for a credentials Exposure, given its Exposure ID.
 * see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/retrieve-details-for-an-exposure
 * @param sExposureID the Exposure ID
 * @returns {Promise<unknown>} returns an object containing all of the details for this exposure (see link in description for details)
 */
Enzoic.prototype.getExposureDetails = async function (sExposureID) {
    const path = '/v1/exposures';

    const response = await this.makeRestCall(path, 'id=' + encodeURIComponent(sExposureID), 'GET', null);
    if (response === 404) {
        return null;
    }
    else {
        return response;
    }
};

/**
 * Takes an array of email addresses and adds them to the list of users your account monitors
 * for new credentials exposures.  The sCustomData parameter can optionally be used with any string value to tag the
 * new subscription items with a custom value.  This value will be sent to your webhook when a new alert is found for
 * one of these users and can also be used to lookup or delete entries.
 * see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#add-breach-alert-subscriptions
 * @param arrUsernames an array of email addresses to monitor
 * @param sCustomData an optional tag value to use for these monitored usernames
 * @returns {Promise<unknown>} returns a response object as specified in the link above
 */
Enzoic.prototype.addUserAlertSubscriptions = async function (arrUsernames, sCustomData = null) {
    const path = '/v1/alert-subscriptions';

    // hash the usernames prior to submission
    let usernameHashes;
    if (Array.isArray(arrUsernames))
        usernameHashes = arrUsernames.map((username) => Hashing.sha256(username.toLowerCase()));
    else
        usernameHashes = Hashing.sha256(arrUsernames.toLowerCase());

    const requestObject = {
        usernameHashes: usernameHashes
    };
    if (sCustomData && sCustomData.trim()) requestObject.customData = sCustomData.trim();

    return this.makeRestCall(path, '', 'POST', JSON.stringify(requestObject));
};

/**
 * Takes an array of email addresses you wish to remove from monitoring for new credentials exposures.
 * see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#remove-breach-alert-subscriptions
 * @param arrUsernames an array of email addresses to remove from monitoring
 * @returns {Promise<unknown>} returns a response object as specified in the link above
 */
Enzoic.prototype.deleteUserAlertSubscriptions = async function (arrUsernames) {
    const path = '/v1/alert-subscriptions';

    // hash the usernames prior to submission
    let usernameHashes;
    if (Array.isArray(arrUsernames))
        usernameHashes = arrUsernames.map((username) => Hashing.sha256(username.toLowerCase()));
    else
        usernameHashes = Hashing.sha256(arrUsernames.toLowerCase());

    const requestObject = {
        usernameHashes: usernameHashes
    };

    return this.makeRestCall(path, '', 'DELETE', JSON.stringify(requestObject));
};

/**
 * Takes a customData value and deletes all alert subscriptions that have that value.
 * see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#remove-breach-alert-subscriptions
 * @param sCustomData the customData tag value that was submitted when the users were added for monitoring
 * @returns {Promise<unknown>} returns a response object as specified in the link above
 */
Enzoic.prototype.deleteUserAlertSubscriptionsByCustomData = async function (sCustomData) {
    const path = '/v1/alert-subscriptions';

    const requestObject = {
        usernameCustomData: sCustomData
    };

    return this.makeRestCall(path, '', 'DELETE', JSON.stringify(requestObject));
};

/**
 * Returns a list of all the users your account is monitoring for new credentials exposures.
 * The results of this call are paginated.  pageSize can be any value from 1 to 1000.  If pageSize is not specified, the default is 1000.
 * sPagingToken is a value returned with each page of results and should be passed into this call to retrieve the next page of results.
 * see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#retrieve-current-breach-alert-subscriptions
 * @param iPageSize The results of this call are paginated.  iPageSize can be any value from 1 to 1000 (default 1000).
 * @param sPagingToken a value returned with each page of results and should be passed into this call to retrieve the next page of results.
 * @returns {Promise<unknown>} returns a response object as specified in the link above
 */
Enzoic.prototype.getUserAlertSubscriptions = async function (iPageSize, sPagingToken) {
    const path = '/v1/alert-subscriptions';

    let queryString = '';

    if (iPageSize) {
        queryString += 'pageSize=' + iPageSize;
    }

    if (sPagingToken) {
        if (queryString !== '') queryString += '&';
        queryString += 'pagingToken=' + sPagingToken;
    }

    return this.makeRestCall(path, queryString, 'GET', null);
};

/**
 * Takes a username and returns true if the user is subscribed for alerts, false otherwise.
 * see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#retrieve-current-breach-alert-subscriptions
 * @param sUsername the email address of the user to check
 * @returns {Promise<boolean>} true if the email address is being monitored, false otherwise
 */
Enzoic.prototype.isUserSubscribedForAlerts = async function (sUsername) {
    const path = '/v1/alert-subscriptions';

    const usernameHash = Hashing.sha256(sUsername.toLowerCase());
    const response = await this.makeRestCall(path, 'usernameHash=' + usernameHash, 'GET', null);
    return response !== 404;
};

/**
 * Takes an array of domains (e.g. enzoic.com) and adds them to the list of domains your account monitors
 * for new credentials exposures.
 * see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#add-breach-alert-subscriptions
 * @param arrDomains an array of domains to monitor
 * @returns {Promise<unknown>} returns a response object as specified in the link above
 */
Enzoic.prototype.addDomainAlertSubscriptions = async function (arrDomains) {
    const path = '/v1/alert-subscriptions';

    const requestObject = {
        domains: arrDomains
    };

    return this.makeRestCall(path, '', 'POST', JSON.stringify(requestObject));
};

/**
 * Takes an array of domains you wish to remove from monitoring for new credentials exposures.
 * see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#remove-breach-alert-subscriptions
 * @param arrDomains an array of domains to remove from monitoring
 * @returns {Promise<unknown>} returns a response object as specified in the link above
 */
Enzoic.prototype.deleteDomainAlertSubscriptions = async function (arrDomains) {
    const path = '/v1/alert-subscriptions';

    const requestObject = {
        domains: arrDomains
    };

    return this.makeRestCall(path, '', 'DELETE', JSON.stringify(requestObject));
};

/**
 * Returns a list of all the domains your account is monitoring for new credentials exposures.
 * The results of this call are paginated.  pageSize can be any value from 1 to 1000.  If pageSize is not specified, the default is 1000.
 * sPagingToken is a value returned with each page of results and should be passed into this call to retrieve the next page of results.
 * see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#retrieve-current-breach-alert-subscriptions
 * @param iPageSize The results of this call are paginated.  iPageSize can be any value from 1 to 1000 (default 1000).
 * @param sPagingToken a value returned with each page of results and should be passed into this call to retrieve the next page of results.
 * @returns {Promise<unknown>} returns a response object as specified in the link above
 */
Enzoic.prototype.getDomainAlertSubscriptions = async function (iPageSize, sPagingToken) {
    const path = '/v1/alert-subscriptions';

    let queryString = 'domains=1&';

    if (iPageSize) {
        queryString += 'pageSize=' + iPageSize;
    }

    if (sPagingToken) {
        if (queryString !== '') queryString += '&';
        queryString += 'pagingToken=' + sPagingToken;
    }

    return this.makeRestCall(path, queryString, 'GET', null);
};

/**
 * Takes a domain and returns true if the domain is subscribed for alerts, false otherwise.
 * see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#retrieve-current-breach-alert-subscriptions
 * @param sDomain the domain to check
 * @returns {Promise<boolean>} true if the domain is monitored, false if not
 */
Enzoic.prototype.isDomainSubscribedForAlerts = async function (sDomain) {
    const path = '/v1/alert-subscriptions';

    const response = await this.makeRestCall(path, 'domain=' + sDomain, 'GET', null);
    return response !== 404;
};

Enzoic.prototype.addCredentialsAlertSubscription = async function (sUsername, sPassword, sCustomData) {
    const path = '/v1/alert-subscriptions';

    const passwordCrypt = await Hashing.aes256Encrypt(sPassword, this.encryptionKey);
    const requestObject = {
        usernameHash: Hashing.sha256(sUsername.toLowerCase()),
        password: passwordCrypt,
        customData: sCustomData
    };

    return this.makeRestCall(path, '', 'POST', JSON.stringify(requestObject));
};

Enzoic.prototype.deleteCredentialsAlertSubscription = async function (sMonitoredCredentialsID) {
    const path = '/v1/alert-subscriptions';

    const requestObject = {
        monitoredCredentialsID: sMonitoredCredentialsID
    };

    return this.makeRestCall(path, '', 'DELETE', JSON.stringify(requestObject));
};

Enzoic.prototype.deleteCredentialsAlertSubscriptionByCustomData = async function (sCustomData) {
    const path = '/v1/alert-subscriptions';

    const requestObject = {
        customData: sCustomData
    };

    return this.makeRestCall(path, '', 'DELETE', JSON.stringify(requestObject));
};

Enzoic.prototype.getCredentialsAlertSubscriptions = async function (iPageSize, sPagingToken) {
    const path = '/v1/alert-subscriptions';

    let queryString = 'credentials=1';

    if (iPageSize) {
        queryString += 'pageSize=' + iPageSize;
    }

    if (sPagingToken) {
        if (queryString !== '') queryString += '&';
        queryString += 'pagingToken=' + sPagingToken;
    }

    return this.makeRestCall(path, queryString, 'GET', null);
};

Enzoic.prototype.getCredentialsAlertSubscriptionsForUser = async function (sUsername) {
    const path = '/v1/alert-subscriptions';

    const queryString = 'credentials=1&usernameHash=' + Hashing.sha256(sUsername.toLowerCase());

    return this.makeRestCall(path, queryString, 'GET', null);
};

/**
 * Returns a list of passwords that Enzoic has found for a specific user.  This call must be enabled
 * for your account or you will receive a 403 rejection when attempting to call it.
 * see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/credentials-api/cleartext-credentials-api
 * @param sUsername the email address to retrieve password for
 * @returns {Promise<*|boolean>} returns a response object as specified in the link above
 */
Enzoic.prototype.getUserPasswords = async function (sUsername) {
    const path = '/v1/accounts';

    const usernameHash = Hashing.sha256(sUsername.toLowerCase());
    const partialUsernameHash = usernameHash.substring(0, 8);

    const queryString = 'partialUsernameHash=' + partialUsernameHash +
        '&includePasswords=1';

    const response = await this.makeRestCall(path, queryString, 'GET', null);
    if (response && response.candidates && response.candidates.length) {
        // see if there's a match
        for (let i = 0; i < response.candidates.length; i++) {
            if (response.candidates[i].usernameHash === usernameHash) {
                return response.candidates[i];
            }
        }
    }

    return false;
}

/**
 * @deprecated since 3.0.0 due to performance issues.
 * @param sUsername
 * @param bIncludeExposureDetails
 * @returns {Promise<*|boolean>}
 */
Enzoic.prototype.getUserPasswordsEx = async function (sUsername, bIncludeExposureDetails) {
    console.warn("This method is deprecated and should no longer be used.");
    const path = '/v1/accounts';

    const usernameHash = Hashing.sha256(sUsername.toLowerCase());
    const partialUsernameHash = usernameHash.substring(0, 8);

    const queryString = 'partialUsernameHash=' + partialUsernameHash +
        '&includePasswords=1' +
        (bIncludeExposureDetails ? '&includeExposureDetails=1' : '');

    const response = await this.makeRestCall(path, queryString, 'GET', null);
    if (response && response.candidates && response.candidates.length) {
        // see if there's a match
        for (let i = 0; i < response.candidates.length; i++) {
            if (response.candidates[i].usernameHash === usernameHash) {
                return response.candidates[i];
            }
        }
    }

    return false;
}

/**
 * Private method
 */
Enzoic.prototype.makeRestCall = async function (sPath, sQueryString, sMethod, sBody) {

    const options = {
        agent: false,
        host: this.host,
        path: sPath + (sQueryString ? '?' + sQueryString : ''),
        method: sMethod,
        headers: {
            'authorization': 'basic ' + this.authString,
            'content-length': sBody ? sBody.length : 0,
            'content-type': 'application/json'
        }
    };

    return new Promise((resolve, reject) => {
        const req = https.request(options, function (res) {
            res.setEncoding('utf8');

            if (res.statusCode === 200 || res.statusCode === 201) {
                let responseData = '';

                res.on('data', function (chunk) {
                    responseData += chunk;
                });

                res.on('end', function () {
                    resolve(JSON.parse(responseData));
                });
            }
            else if (res.statusCode === 404) {
                resolve(res.statusCode);
            }
            else {
                reject('Unexpected error from Enzoic API: ' + res.statusCode + ' ' + res.statusMessage, null);
            }
        });

        req.on('error', function (e) {
            reject('Unexpected error calling Enzoic API: ' + e.message);
        });

        if (sMethod === 'POST' || sMethod === 'PUT' || sMethod === 'DELETE') {
            req.write(sBody);
        }

        req.end();
    });
};

/**
 * Private method
 */
Enzoic.prototype.calcCredentialHash = async function (sUsername, sPassword, sSalt, oHashSpec) {
    let passwordHash = null;
    try {
        passwordHash = await this.calcPasswordHash(oHashSpec.hashType, sPassword, oHashSpec.salt);
    }
    catch (ex) {
        console.error("Error calculating password hash: " + ex);
        return null;
    }

    const hashResult = await Hashing.argon2(sUsername.toLowerCase() + "$" + passwordHash, sSalt);
    const justhash = hashResult.substring(hashResult.lastIndexOf('$') + 1);
    return new Buffer(justhash, 'base64').toString('hex');
};

/**
 * Private method
 */
Enzoic.prototype.calcPasswordHash = async function (iPasswordType, sPassword, sSalt) {

    function checkSalt(salt) {
        if (typeof (salt) !== 'string' || salt.length === 0) {
            throw "Invalid salt";
        }
    }

    switch (iPasswordType) {
        case PasswordType.MD5:
            return Hashing.md5(sPassword);
        case PasswordType.SHA1:
            return Hashing.sha1(sPassword);
        case PasswordType.SHA256:
            return Hashing.sha256(sPassword);
        case PasswordType.IPBoard_MyBB:
            checkSalt(sSalt);
            return Hashing.ipb_mybb(sPassword, sSalt);
        case PasswordType.VBulletinPre3_8_5:
        case PasswordType.VBulletinPost3_8_5:
            checkSalt(sSalt);
            return Hashing.vBulletin(sPassword, sSalt);
        case PasswordType.BCrypt:
            checkSalt(sSalt);
            return Hashing.bcrypt(sPassword, sSalt);
        case PasswordType.CRC32:
            return Hashing.crc32(sPassword);
        case PasswordType.PHPBB3:
            checkSalt(sSalt);
            return Hashing.phpbb3(sPassword, sSalt);
        case PasswordType.CustomAlgorithm1:
            checkSalt(sSalt);
            return Hashing.customAlgorithm1(sPassword, sSalt);
        case PasswordType.CustomAlgorithm2:
            checkSalt(sSalt);
            return Hashing.customAlgorithm2(sPassword, sSalt);
        case PasswordType.SHA512:
            return Hashing.sha512(sPassword);
        case PasswordType.MD5Crypt:
            checkSalt(sSalt);
            return Hashing.md5Crypt(sPassword, sSalt);
        case PasswordType.CustomAlgorithm4:
            checkSalt(sSalt);
            return Hashing.customAlgorithm4(sPassword, sSalt);
        case PasswordType.CustomAlgorithm5:
            checkSalt(sSalt);
            return Hashing.customAlgorithm5(sPassword, sSalt);
        case PasswordType.osCommerce_AEF:
            checkSalt(sSalt);
            return Hashing.osCommerce_AEF(sPassword, sSalt);
        case PasswordType.DESCrypt:
            checkSalt(sSalt);
            return Hashing.desCrypt(sPassword, sSalt);
        case PasswordType.MySQLPre4_1:
            return Hashing.mySqlPre4_1(sPassword);
        case PasswordType.MySQLPost4_1:
            return Hashing.mySqlPost4_1(sPassword);
        case PasswordType.PeopleSoft:
            return Hashing.peopleSoft(sPassword);
        case PasswordType.PunBB:
            checkSalt(sSalt);
            return Hashing.punBB(sPassword, sSalt);
        case PasswordType.CustomAlgorithm6:
            checkSalt(sSalt);
            return Hashing.customAlgorithm6(sPassword, sSalt);
        case PasswordType.PartialMD5_20:
            return Hashing.md5(sPassword).substr(0, 20);
        case PasswordType.PartialMD5_29:
            return Hashing.md5(sPassword).substr(0, 29);
        case PasswordType.AVE_DataLife_Diferior:
            return Hashing.ave_DataLife_Diferior(sPassword);
        case PasswordType.DjangoMD5:
            checkSalt(sSalt);
            return Hashing.djangoMD5(sPassword, sSalt);
        case PasswordType.DjangoSHA1:
            checkSalt(sSalt);
            return Hashing.djangoSHA1(sPassword, sSalt);
        case PasswordType.PliggCMS:
            checkSalt(sSalt);
            return Hashing.pliggCMS(sPassword, sSalt);
        case PasswordType.RunCMS_SMF1_1:
            checkSalt(sSalt);
            return Hashing.runCMS_SMF1_1(sPassword, sSalt);
        case PasswordType.NTLM:
            return Hashing.ntlm(sPassword);
        case PasswordType.SHA1Dash:
            checkSalt(sSalt);
            return Hashing.sha1("--" + sSalt + "--" + sPassword + "--");
        case PasswordType.SHA384:
            return Hashing.sha384(sPassword);
        case PasswordType.CustomAlgorithm7:
            checkSalt(sSalt);
            return Hashing.customAlgorithm7(sPassword, sSalt);
        case PasswordType.CustomAlgorithm8:
            checkSalt(sSalt);
            return Hashing.sha256(sSalt + sPassword);
        case PasswordType.CustomAlgorithm9:
            checkSalt(sSalt);
            return Hashing.customAlgorithm9(sPassword, sSalt);
        case PasswordType.SHA512Crypt:
            checkSalt(sSalt);
            return Hashing.sha512Crypt(sPassword, sSalt);
        case PasswordType.CustomAlgorithm10:
            checkSalt(sSalt);
            return Hashing.customAlgorithm10(sPassword, sSalt);
        case PasswordType.HMACSHA1_SaltAsKey:
            checkSalt(sSalt);
            return Hashing.hmacSHA1SaltAsKey(sPassword, sSalt);
        case PasswordType.AuthMeSHA256:
            checkSalt(sSalt);
            return Hashing.authMeSHA256(sPassword, sSalt);
        default:
            throw "Invalid password type";
    }
};

module.exports = Enzoic;

'use strict';

var https = require('https');
var Hashing = require('./src/hashing');
var PasswordType = require('./src/passwordtype');

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

Enzoic.prototype.checkCredentialsEx = function(sUsername, sPassword, oOptions, fnCallback) {
    var accountsPath = '/v1/accounts';
    var credentialsPath = '/v1/credentials';
    var me = this;

    var excludeHashAlgorithms = (oOptions && oOptions.excludeHashAlgorithms)
        ? oOptions.excludeHashAlgorithms
        : [];
    var lastCheckDate = (oOptions && oOptions.lastCheckDate)
        ? oOptions.lastCheckDate
        : new Date('1980-01-01');
    var includeExposures = (oOptions && oOptions.includeExposures)
        ? oOptions.includeExposures
        : false;

    this.makeRestCall(accountsPath, 'username=' + Hashing.sha256(sUsername.toLowerCase()), 'GET', null, function (err, accountResponse) {
        if (err) {
            fnCallback(err, null);
        }
        else if (accountResponse === 404) {
            fnCallback(null, false);
        }
        else {
            // first check the date threshold
            if (new Date(accountResponse.lastBreachDate) <= lastCheckDate)
            {
                // if we checked these credentials after the date of the last breach in the Enzoic system,
                // bail out and return false
                fnCallback(null, false);
                return;
            }

            var hashesRequired = accountResponse.passwordHashesRequired;

            var bcryptCount = 0;
            var queryString = '';
            var credentialHashCalcs = [];

            for (var i = 0; i < hashesRequired.length; i++) {
                var hashSpec = hashesRequired[i];

                if (excludeHashAlgorithms.indexOf(hashSpec.hashType) >= 0)
                {
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
                        me.calcCredentialHash(sUsername.toLowerCase(), sPassword, accountResponse.salt, hashSpec)
                    );
                }
            }

            // wait for all the credential hash calculations to finish
            Promise.all(credentialHashCalcs)
                .then(credentialsHashes => {
                    // build the query string for the credentials call
                    for (var i = 0; i < credentialsHashes.length; i++) {
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
                        me.makeRestCall(credentialsPath, queryString, "GET", null, function (err, credsResponse) {
                            if (err) {
                                fnCallback(err, null);
                            }
                            else {
                                if (credsResponse !== 404) {
                                    if (includeExposures === true) {
                                        var results = {exposures: []};
                                        var found = false;

                                        // compare the candidate results to the local full hashes
                                        for (var i = 0; i < credsResponse.candidateHashes.length; i++) {
                                            if (credentialsHashes.indexOf(credsResponse.candidateHashes[i].hash) >= 0) {
                                                results.exposures.push(...credsResponse.candidateHashes[i].exposures);
                                                found = true;
                                            }
                                        }

                                        if (found === true) {
                                            // return results in this case
                                            results.exposures = [...new Set(results.exposures)];
                                            fnCallback(null, results);
                                            return;
                                        }
                                    }
                                    else {
                                        // compare the candidate results to the local full hashes
                                        for (var i = 0; i < credsResponse.candidateHashes.length; i++) {
                                            if (credentialsHashes.indexOf(credsResponse.candidateHashes[i]) >= 0) {
                                                fnCallback(null, true);
                                                return;
                                            }
                                        }
                                    }
                                }

                                fnCallback(null, false);
                            }
                        });
                    }
                    else {
                        fnCallback(null, false);
                    }
                })
                .catch((err) => {
                    console.error('Error while calculating password hashes: ' + err);
                });
        }
    });
};

Enzoic.prototype.checkCredentials = function(sUsername, sPassword, fnCallback) {
    this.checkCredentialsEx(sUsername.toLowerCase(), sPassword, null, fnCallback);
};

Enzoic.prototype.checkPassword = function(sPassword, fnCallback) {
    var path = '/v1/passwords';
    var md5 = Hashing.md5(sPassword);
    var sha1 = Hashing.sha1(sPassword);
    var sha256 = Hashing.sha256(sPassword);
    var queryString = 'partial_md5=' + md5.substr(0, 10) +
        '&partial_sha1=' + sha1.substr(0, 10) +
        '&partial_sha256=' + sha256.substr(0, 10);

    this.makeRestCall(path, queryString, 'GET', null, function(err, result) {
        if (err) {
            fnCallback(err, null);
        }
        else if (typeof(result) === 'object') {
            // loop through and see if we have a match
            for (var i = 0; i < result.candidates.length; i++) {
                if (result.candidates[i].md5 === md5 ||
                    result.candidates[i].sha1 === sha1 ||
                    result.candidates[i].sha256 === sha256) {
                    fnCallback(null, true);
                    return;
                }
            }

            fnCallback(null, false);
        }
        else if (result === 404) {
            fnCallback(null, false);
        }
    });
};

Enzoic.prototype.getExposuresForUser = function(sUsername, fnCallback) {
    var path = '/v1/exposures';

    this.makeRestCall(path, 'username=' + Hashing.sha256(sUsername.toLowerCase()), 'GET', null, function(err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else if (response === 404) {
            // don't have this email in the DB - return empty response
            fnCallback(null, {
                count: 0,
                exposures: []
            });
        }
        else {
            fnCallback(null, response);
        }

    });
};

Enzoic.prototype.getExposedUsersForDomain = function (sDomain, iPageSize, sPagingToken, fnCallback) {
    var path = '/v1/exposures';

    var queryString = 'accountDomain=' + sDomain;

    if (iPageSize) {
        queryString += '&pageSize=' + iPageSize;
    }

    if (sPagingToken) {
        queryString += '&pagingToken=' + sPagingToken;
    }

    this.makeRestCall(path, queryString, 'GET', null, function (err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else if (response === 404) {
            // don't have this email in the DB - return empty response
            fnCallback(null, {
                count: 0,
                users: []
            });
        }
        else {
            fnCallback(null, response);
        }

    });
};

Enzoic.prototype.getExposuresForDomain = function (sDomain, bIncludeExposureDetails, fnCallback) {
    return this.getExposuresForDomainEx(sDomain, bIncludeExposureDetails, null, null, fnCallback);
};

Enzoic.prototype.getExposuresForDomainEx = function (sDomain, bIncludeExposureDetails, iPageSize, sPagingToken, fnCallback) {
    var path = '/v1/exposures';

    var queryString = 'domain=' + sDomain;

    if (bIncludeExposureDetails === true) {
        queryString += '&includeExposureDetails=1';
    }

    if (iPageSize) {
        queryString += '&pageSize=' + iPageSize;
    }

    if (sPagingToken) {
        queryString += '&pagingToken=' + sPagingToken;
    }

    this.makeRestCall(path, queryString, 'GET', null, function (err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else if (response === 404) {
            // don't have this domain in the DB - return empty response
            fnCallback(null, {
                count: 0,
                exposures: []
            });
        }
        else {
            fnCallback(null, response);
        }

    });
};

Enzoic.prototype.getExposureDetails = function(sExposureID, fnCallback) {
    var path = '/v1/exposures';

    this.makeRestCall(path, 'id=' + encodeURIComponent(sExposureID), 'GET', null, function(err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else if (response === 404) {
            fnCallback(null, null);
        }
        else {
            fnCallback(null, response);
        }
    });
};

Enzoic.prototype.addUserAlertSubscriptions = function(arrUsernameHashes, fnCallback, sCustomData) {
    var path = '/v1/alert-subscriptions';

    var requestObject = {
        usernameHashes: arrUsernameHashes
    };

    this.makeRestCall(path, '', 'POST', JSON.stringify(requestObject), function(err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else {
            fnCallback(null, response);
        }
    });
};

Enzoic.prototype.deleteUserAlertSubscriptions = function(arrUsernameHashes, fnCallback) {
    var path = '/v1/alert-subscriptions';

    var requestObject = {
        usernameHashes: arrUsernameHashes
    };

    this.makeRestCall(path, '', 'DELETE', JSON.stringify(requestObject), function(err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else {
            fnCallback(null, response);
        }
    });
};

Enzoic.prototype.getUserAlertSubscriptions = function(iPageSize, sPagingToken, fnCallback) {
    var path = '/v1/alert-subscriptions';

    var queryString = '';

    if (iPageSize) {
        queryString += 'pageSize=' + iPageSize;
    }

    if (sPagingToken) {
        if (queryString != '') queryString += '&';
        queryString += 'pagingToken=' + sPagingToken;
    }

    this.makeRestCall(path, queryString, 'GET', null, function (err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else {
            fnCallback(null, response);
        }
    });
};

Enzoic.prototype.addUserAlertSubscriptionsWithCustomData = function(arrUsernameHashes, sCustomData, fnCallback) {
    var path = '/v1/alert-subscriptions';

    var requestObject = {
        usernameHashes: arrUsernameHashes,
        customData: sCustomData
    };

    this.makeRestCall(path, '', 'POST', JSON.stringify(requestObject), function(err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else {
            fnCallback(null, response);
        }
    });
};

Enzoic.prototype.deleteUserAlertSubscriptionsByCustomData = function(sCustomData, fnCallback) {
    var path = '/v1/alert-subscriptions';

    var requestObject = {
        usernameCustomData: sCustomData
    };

    this.makeRestCall(path, '', 'DELETE', JSON.stringify(requestObject), function(err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else {
            fnCallback(null, response);
        }
    });
};

Enzoic.prototype.isUserSubscribedForAlerts = function(sUsernameHash, fnCallback) {
    var path = '/v1/alert-subscriptions';

    this.makeRestCall(path, 'usernameHash=' + sUsernameHash, 'GET', null, function(err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else if (response === 404) {
            fnCallback(null, false);
        }
        else {
            fnCallback(null, true);
        }
    });
};

Enzoic.prototype.addDomainAlertSubscriptions = function(arrDomains, fnCallback) {
    var path = '/v1/alert-subscriptions';

    var requestObject = {
        domains: arrDomains
    };

    this.makeRestCall(path, '', 'POST', JSON.stringify(requestObject), function(err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else {
            fnCallback(null, response);
        }
    });
};

Enzoic.prototype.deleteDomainAlertSubscriptions = function(arrDomains, fnCallback) {
    var path = '/v1/alert-subscriptions';

    var requestObject = {
        domains: arrDomains
    };

    this.makeRestCall(path, '', 'DELETE', JSON.stringify(requestObject), function(err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else {
            fnCallback(null, response);
        }
    });
};

Enzoic.prototype.getDomainAlertSubscriptions = function(iPageSize, sPagingToken, fnCallback) {
    var path = '/v1/alert-subscriptions';

    var queryString = 'domains=1&';

    if (iPageSize) {
        queryString += 'pageSize=' + iPageSize;
    }

    if (sPagingToken) {
        if (queryString != '') queryString += '&';
        queryString += 'pagingToken=' + sPagingToken;
    }

    this.makeRestCall(path, queryString, 'GET', null, function (err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else {
            fnCallback(null, response);
        }
    });
};

Enzoic.prototype.isDomainSubscribedForAlerts = function(sDomain, fnCallback) {
    var path = '/v1/alert-subscriptions';

    this.makeRestCall(path, 'domain=' + sDomain, 'GET', null, function(err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else if (response === 404) {
            fnCallback(null, false);
        }
        else {
            fnCallback(null, true);
        }
    });
};

Enzoic.prototype.addCredentialsAlertSubscription = function(sUsername, sPassword, sCustomData, fnCallback) {
    var path = '/v1/alert-subscriptions';

    Hashing.aes256Encrypt(sPassword, this.encryptionKey, (err, passwordCrypt) => {
        var requestObject = {
            usernameHash: Hashing.sha256(sUsername.toLowerCase()),
            password: passwordCrypt,
            customData: sCustomData
        };

        this.makeRestCall(path, '', 'POST', JSON.stringify(requestObject), function(err, response) {
            if (err) {
                fnCallback(err, null);
            }
            else {
                fnCallback(null, response);
            }
        });
    });
};

Enzoic.prototype.deleteCredentialsAlertSubscription = function(sMonitoredCredentialsID, fnCallback) {
    var path = '/v1/alert-subscriptions';

    var requestObject = {
        monitoredCredentialsID: sMonitoredCredentialsID
    };

    this.makeRestCall(path, '', 'DELETE', JSON.stringify(requestObject), function(err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else {
            fnCallback(null, response);
        }
    });
};

Enzoic.prototype.deleteCredentialsAlertSubscriptionByCustomData = function(sCustomData, fnCallback) {
    var path = '/v1/alert-subscriptions';

    var requestObject = {
        customData: sCustomData
    };

    this.makeRestCall(path, '', 'DELETE', JSON.stringify(requestObject), function(err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else {
            fnCallback(null, response);
        }
    });
};

Enzoic.prototype.getCredentialsAlertSubscriptions = function(iPageSize, sPagingToken, fnCallback) {
    var path = '/v1/alert-subscriptions';

    var queryString = 'credentials=1';

    if (iPageSize) {
        queryString += 'pageSize=' + iPageSize;
    }

    if (sPagingToken) {
        if (queryString != '') queryString += '&';
        queryString += 'pagingToken=' + sPagingToken;
    }

    this.makeRestCall(path, queryString, 'GET', null, function (err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else {
            fnCallback(null, response);
        }
    });
};

Enzoic.prototype.getCredentialsAlertSubscriptionsForUser = function(sUsername, fnCallback) {
    var path = '/v1/alert-subscriptions';

    var queryString = 'credentials=1&usernameHash=' + Hashing.sha256(sUsername.toLowerCase());

    this.makeRestCall(path, queryString, 'GET', null, function (err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else {
            fnCallback(null, response);
        }
    });
};

Enzoic.prototype.getUserPasswords = function(sUsername, fnCallback) {
    var path = '/v1/accounts';

    var queryString = 'username=' + Hashing.sha256(sUsername.toLowerCase()) + '&includePasswords=1';

    this.makeRestCall(path, queryString, 'GET', null, function (err, response) {
        if (err) {
            fnCallback(err, null);
        }
        else if (response === 404) {
            fnCallback(null, false);
        }
        else {
            fnCallback(null, response);
        }
    })
}

Enzoic.prototype.makeRestCall = function(sPath, sQueryString, sMethod, sBody, fnCallback) {

    var options = {
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

    var req = https.request(options, function (res) {
        res.setEncoding('utf8');

        if (res.statusCode === 200 || res.statusCode === 201) {
            var responseData = '';

            res.on('data', function (chunk) {
               responseData += chunk;
            });

            res.on('end', function() {
                fnCallback(null, JSON.parse(responseData));
            });
        }
        else if (res.statusCode === 404) {
            fnCallback(null, res.statusCode);
        }
        else {
            fnCallback('Unexpected error from Enzoic API: ' + res.statusCode + ' ' + res.statusMessage, null);
        }
    });

    req.on('error', function(e) {
        fnCallback('Unexpected error calling Enzoic API: ' + e.message);
    });

    if (sMethod === 'POST' || sMethod === 'PUT' || sMethod === 'DELETE') {
        req.write(sBody);
    }

    req.end();
};

Enzoic.prototype.calcCredentialHash = function(sUsername, sPassword, sSalt, oHashSpec, fnCallback) {
    var me = this;

    return new Promise(function (fulfill, reject) {
        me.calcPasswordHash(oHashSpec.hashType, sPassword, oHashSpec.salt, function(err, passwordHash) {
            if (err) {
                console.error('Error calculating password hash: ' + err);
                fulfill(null);
            }
            else {
                Hashing.argon2(sUsername.toLowerCase() + "$" + passwordHash, sSalt, function(err, hashResult) {
                    if (err) {
                        reject(err);
                    }
                    else {
                        var justhash = hashResult.substring(hashResult.lastIndexOf('$') + 1);
                        fulfill(new Buffer(justhash, 'base64').toString('hex'));
                    }
                });
            }
        });
    });
};

Enzoic.prototype.calcPasswordHash = function(iPasswordType, sPassword, sSalt, fnCallback) {

    function checkSalt(salt) {
        if (typeof(salt) !== 'string' || salt.length === 0) {
            fnCallback('Invalid salt', null);
            return false;
        }
        return true;
    }

    switch (iPasswordType) {
        case PasswordType.MD5:
            fnCallback(null, Hashing.md5(sPassword));
            break;
        case PasswordType.SHA1:
            fnCallback(null, Hashing.sha1(sPassword));
            break;
        case PasswordType.SHA256:
            fnCallback(null, Hashing.sha256(sPassword));
            break;
        case PasswordType.IPBoard_MyBB:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.ipb_mybb(sPassword, sSalt));
            }
            break;
        case PasswordType.VBulletinPre3_8_5:
        case PasswordType.VBulletinPost3_8_5:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.vBulletin(sPassword, sSalt));
            }
            break;
        case PasswordType.BCrypt:
            if (checkSalt(sSalt)) {
                Hashing.bcrypt(sPassword, sSalt, fnCallback);
            }
            break;
        case PasswordType.CRC32:
            fnCallback(null, Hashing.crc32(sPassword));
            break;
        case PasswordType.PHPBB3:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.phpbb3(sPassword, sSalt));
            }
            break;
        case PasswordType.CustomAlgorithm1:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.customAlgorithm1(sPassword, sSalt));
            }
            break;
        case PasswordType.CustomAlgorithm2:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.customAlgorithm2(sPassword, sSalt));
            }
            break;
        case PasswordType.SHA512:
            fnCallback(null, Hashing.sha512(sPassword));
            break;
        case PasswordType.MD5Crypt:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.md5Crypt(sPassword, sSalt));
            }
            break;
        case PasswordType.CustomAlgorithm4:
            if (checkSalt(sSalt)) {
                Hashing.customAlgorithm4(sPassword, sSalt, fnCallback);
            }
            break;
        case PasswordType.CustomAlgorithm5:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.customAlgorithm5(sPassword, sSalt));
            }
            break;
        case PasswordType.osCommerce_AEF:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.osCommerce_AEF(sPassword, sSalt));
            }
            break;
        case PasswordType.DESCrypt:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.desCrypt(sPassword, sSalt));
            }
            break;
        case PasswordType.MySQLPre4_1:
            fnCallback(null, Hashing.mySqlPre4_1(sPassword));
            break;
        case PasswordType.MySQLPost4_1:
            fnCallback(null, Hashing.mySqlPost4_1(sPassword));
            break;
        case PasswordType.PeopleSoft:
            fnCallback(null, Hashing.peopleSoft(sPassword));
            break;
        case PasswordType.PunBB:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.punBB(sPassword, sSalt));
            }
            break;
        case PasswordType.CustomAlgorithm6:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.customAlgorithm6(sPassword, sSalt));
            }
            break;
        case PasswordType.PartialMD5_20:
            fnCallback(null, Hashing.md5(sPassword).substr(0, 20));
            break;
        case PasswordType.PartialMD5_29:
            fnCallback(null, Hashing.md5(sPassword).substr(0, 29));
            break;
        case PasswordType.AVE_DataLife_Diferior:
            fnCallback(null, Hashing.ave_DataLife_Diferior(sPassword));
            break;
        case PasswordType.DjangoMD5:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.djangoMD5(sPassword, sSalt));
            }
            break;
        case PasswordType.DjangoSHA1:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.djangoSHA1(sPassword, sSalt));
            }
            break;
        case PasswordType.PliggCMS:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.pliggCMS(sPassword, sSalt));
            }
            break;
        case PasswordType.RunCMS_SMF1_1:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.runCMS_SMF1_1(sPassword, sSalt));
            }
            break;
        case PasswordType.NTLM:
            fnCallback(null, Hashing.ntlm(sPassword));
            break;
        case PasswordType.SHA1Dash:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.sha1("--" + sSalt + "--" + sPassword + "--"));
            }
            break;
        case PasswordType.SHA384:
            fnCallback(null, Hashing.sha384(sPassword));
            break;
        case PasswordType.CustomAlgorithm7:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.customAlgorithm7(sPassword, sSalt));
            }
            break;
        case PasswordType.CustomAlgorithm8:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.sha256(sSalt + sPassword));
            }
            break;
        case PasswordType.CustomAlgorithm9:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.customAlgorithm9(sPassword, sSalt));
            }
            break;
        case PasswordType.SHA512Crypt:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.sha512Crypt(sPassword, sSalt));
            }
            break;
        case PasswordType.CustomAlgorithm10:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.customAlgorithm10(sPassword, sSalt));
            }
            break;
        case PasswordType.HMACSHA1_SaltAsKey:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.hmacSHA1SaltAsKey(sPassword, sSalt));
            }
            break;
        case PasswordType.AuthMeSHA256:
            if (checkSalt(sSalt)) {
                fnCallback(null, Hashing.authMeSHA256(sPassword, sSalt));
            }
            break;
        default:
            fnCallback('Invalid password type', null);
            break;
    }
};

module.exports = Enzoic;

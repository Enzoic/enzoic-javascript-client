'use strict'

var https = require('https');
var Hashing = require('./src/hashing');
var PasswordType = require('./src/passwordtype');

function PasswordPing(sAPIKey, sSecret, sBaseAPIHost) {
    this.apiKey = sAPIKey;
    this.secret = sSecret;
    this.host = sBaseAPIHost;

    if (!this.apiKey || !this.secret) {
        throw 'API key and Secret must be provided';
    }

    this.authString = new Buffer(this.apiKey + ':' + this.secret).toString('base64');

    if (!this.host) {
        // default host
        this.host = 'api.passwordping.com';
    }
}

PasswordPing.prototype.checkCredentials = function(sUsername, sPassword, fnCallback) {
    var accountsPath = '/v1/accounts';
    var credentialsPath = '/v1/credentials';
    var me = this;

    this.makeRestCall(accountsPath, 'username=' + Hashing.sha256(sUsername), 'GET', null, function (err, accountResponse) {
        if (err) {
            fnCallback(err, null);
        }
        else if (accountResponse === 404) {
            fnCallback(null, false);
        }
        else {
            var hashesRequired = accountResponse.passwordHashesRequired;

            var bcryptCount = 0;
            var queryString = '';
            var credentialHashCalcs = [];

            for (var i = 0; i < hashesRequired.length; i++) {
                var hashSpec = hashesRequired[i];

                // bcrypt gets far too expensive for good response time if there are many of them to calculate.
                // some mostly garbage accounts have accumulated a number of them in our DB and if we happen to hit one it
                // kills performance, so short circuit out after at most 2 BCrypt hashes
                if (hashSpec.hashType != PasswordType.BCrypt || bcryptCount <= 2) {
                    if (hashSpec.hashType === PasswordType.BCrypt) {
                        bcryptCount++;
                    }
                }

                if (hashSpec.hashType) {
                    credentialHashCalcs.push(
                        me.calcCredentialHash(sUsername, sPassword, accountResponse.salt, hashSpec)
                    );
                }
            }

            // wait for all the credential hash calculations to finish
            Promise.all(credentialHashCalcs).then(values => {
                // build the query string for the credentials call
                for (var i = 0; i < values.length; i++) {
                    if (values[i]) {
                        if (queryString.length === 0) {
                            queryString += "hashes=" + values[i];
                        }
                        else {
                            queryString += "&hashes=" + values[i];
                        }
                    }
                }

                if (queryString.length > 0) {
                    // make the credentials call
                    me.makeRestCall(credentialsPath, queryString, "GET", null, function(err, credsResponse) {
                        if (err) {
                            fnCallback(err, null);
                        }
                        else {
                            fnCallback(null, credsResponse != 404);
                        }
                    });
                }
                else {
                    fnCallback(null, false);
                }
            });
        }
    });
};

PasswordPing.prototype.checkPassword = function(sPassword, fnCallback) {
    var path = '/v1/passwords';
    var queryString = 'md5=' + Hashing.md5(sPassword) +
        '&sha1=' + Hashing.sha1(sPassword) +
        '&sha256=' + Hashing.sha256(sPassword);

    this.makeRestCall(path, queryString, 'GET', null, function(err, result) {
        if (err) {
            fnCallback(err, null);
        }
        else if (typeof(result) === 'object') {
            fnCallback(null, true);
        }
        else if (result === 404) {
            fnCallback(null, false);
        }
    });
};

PasswordPing.prototype.getExposuresForUser = function(sUsername, fnCallback) {
    var path = '/v1/exposures';

    this.makeRestCall(path, 'username=' + Hashing.sha256(sUsername), 'GET', null, function(err, response) {
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

PasswordPing.prototype.getExposureDetails = function(sExposureID, fnCallback) {
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

PasswordPing.prototype.makeRestCall = function(sPath, sQueryString, sMethod, sBody, fnCallback) {

    var options = {
        agent: false,
        host: this.host,
        path: sPath + '?' + sQueryString,
        method: sMethod,
        headers: {
            'authorization': 'basic ' + this.authString
        }
    };

    var req = https.request(options, function (res) {
        res.setEncoding('utf8');

        if (res.statusCode === 200) {
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
            fnCallback('Unexpected error from PasswordPing API: ' + res.statusCode + ' ' + res.statusMessage, null);
        }
    });

    req.on('error', function(e) {
        fnCallback('Unexpected error calling PasswordPing API: ' + e.message);
    });

    if (sMethod === 'POST' || sMethod === 'PUT') {
        req.write(sBody);
    }

    req.end();
};

PasswordPing.prototype.calcCredentialHash = function(sUsername, sPassword, sSalt, oHashSpec, fnCallback) {
    var me = this;

    return new Promise(function (fulfill, reject) {
        me.calcPasswordHash(oHashSpec.hashType, sPassword, oHashSpec.salt, function(err, passwordHash) {
            if (err) {
                reject(err);
            }
            else {
                Hashing.argon2(sUsername + "$" + passwordHash, sSalt, function(err, hashResult) {
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

PasswordPing.prototype.calcPasswordHash = function(iPasswordType, sPassword, sSalt, fnCallback) {

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
        default:
            fnCallback('Invalid password type', null);
            break;
    }
};

module.exports = PasswordPing;

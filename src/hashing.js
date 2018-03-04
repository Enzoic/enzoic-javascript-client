var crypto = require('crypto');
var bcrypt = require('bcrypt-nodejs');
var argon2 = require('argon2');
var crc32 = require('crc-32');
var xor = require('bitwise-xor');
var md5crypt = require('nano-md5');

Hashing = {
    md5: function(sToHash, bBinary) {
        if (bBinary === true)
            return crypto.createHash('md5').update(sToHash).digest();
        else
            return crypto.createHash('md5').update(sToHash).digest("hex");
    },

    sha1: function(sToHash) {
        return crypto.createHash('sha1').update(sToHash).digest("hex");
    },

    sha256: function(sToHash) {
        return crypto.createHash('sha256').update(sToHash).digest("hex");
    },

    sha512: function(sToHash, bBinary) {
        if (bBinary === true)
            return crypto.createHash('sha512').update(sToHash).digest('binary');
        else
            return crypto.createHash('sha512').update(sToHash).digest("hex");
    },

    whirlpool: function(sToHash, bBinary) {
        if (bBinary === true)
            return crypto.createHash('whirlpool').update(sToHash).digest('binary');
        else
            return crypto.createHash('whirlpool').update(sToHash).digest("hex");
    },

    ipb_mybb: function(sPassword, sSalt) {
        return this.md5(this.md5(sSalt) + this.md5(sPassword));
    },

    vBulletin: function(sPassword, sSalt) {
        return this.md5(this.md5(sPassword) + sSalt);
    },

    bcrypt: function(sPassword, sSalt, fnCallback) {
        var twoy = false;
        var processedSalt = sSalt;
        if (sSalt.substring(0, 3) === '$2y') {
            twoy = true;
            processedSalt = '$2a' + sSalt.substring(3);
        }

        return bcrypt.hash(sPassword, processedSalt, null, function(err, hash) {
            if (twoy === true) {
                fnCallback(err, '$2y' + hash.substring(3));
            }
            else {
                fnCallback(err, hash);
            }
        });
    },

    crc32: function(sToHash) {
        return this.intToHex(crc32.str(sToHash), 8);
    },

    phpbb3: function(sPassword, sSalt) {
        if (sSalt.substr(0, 3) != '$H$') {
            return "";
        }

        var itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        var count = Math.pow(2, itoa64.indexOf(sSalt[3]));
        var justsalt = sSalt.substr(4);
        var passwordBuffer = new Buffer(sPassword);

        var hash = Hashing.md5(justsalt + sPassword, true);
        while (count-- > 0) {
            hash = Hashing.md5(Buffer.concat([hash, passwordBuffer]), true);
        }

        var hashout = '';
        var i = 0;
        var count = 16;

        do
        {
            var value = hash[i++];
            hashout += itoa64[value & 0x3f];

            if (i < count)
            {
                value |= hash[i] << 8;
            }

            hashout += itoa64[(value >> 6) & 0x3f];

            if (i++ >= count)
            {
                break;
            }

            if (i < count)
            {
                value |= hash[i] << 16;
            }

            hashout += itoa64[(value >> 12) & 0x3f];

            if (i++ >= count)
            {
                break;
            }

            hashout += itoa64[(value >> 18) & 0x3f];
        }
        while (i < count);

        return sSalt + hashout;
    },

    customAlgorithm1: function(sPassword, sSalt) {
        var hash1 = Hashing.sha512(sPassword + sSalt, false);
        var hash2 = Hashing.whirlpool(sSalt + sPassword, false);
        return xor(new Buffer(hash1, 'hex'), new Buffer(hash2, 'hex')).toString('hex');
    },

    customAlgorithm2: function(sPassword, sSalt) {
        return Hashing.md5(sPassword + sSalt, false);
    },

    customAlgorithm4: function(sPassword, sSalt, fnCallback) {
        return Hashing.bcrypt(Hashing.md5(sPassword), sSalt, function(err, hash) {
            fnCallback(err, hash);
        });
    },

    customAlgorithm5: function(sPassword, sSalt, fnCallback) {
        fnCallback(null, Hashing.sha256(Hashing.md5(sPassword + sSalt)));
    },

    md5Crypt: function(sPassword, sSalt) {
        return md5crypt.crypt(sPassword, sSalt);
    },

    argon2: function(sToHash, sSalt, fnCallback) {

        var hashType = argon2.argon2d;
        var tCost = 3;
        var mCost = 10;
        var threads = 2;
        var hashLength = 20;
        var justSalt = sSalt;

        if (sSalt.indexOf("$argon2") === 0) {
            var saltComponents = sSalt.split('$');

            if (saltComponents.length === 5) {
                var justSalt = Buffer.from(saltComponents[4], "base64");

                if (saltComponents[1] === 'argon2i')
                    hashType = argon2.argon2i;

                var saltParams = saltComponents[3].split(',');
                for (var i = 0; i < saltParams.length; i++) {
                    var saltValues = saltParams[i].split('=');
                    var intValue = parseInt(saltValues[1]);

                    if (!isNaN(intValue)) {
                        switch (saltValues[0]) {
                            case 't':
                                tCost = intValue;
                                break;
                            case 'm':
                                mCost = Math.log2(intValue);
                                break;
                            case 'l':
                                hashLength = intValue;
                                break;
                            case 'p':
                                threads = intValue;
                                break;
                        }
                    }
                }
            }
        }

        argon2.hash(sToHash, justSalt, {
            type: hashType,
            hashLength: hashLength,
            timeCost: tCost,
            memoryCost: mCost,
            parallelism: threads
        }).then(hash => {
            fnCallback(null, hash);
        }).catch(err =>  {
            fnCallback(err, "");
        });
    },

    intToHex: function(d, padding) {
        var number = d;
        if (number < 0) {
            number = 0xffffffff + number + 1;
        }

        var hex = Number(number).toString(16);
        padding = typeof (padding) === "undefined" || padding === null ? padding = 2 : padding;

        while (hex.length < padding) {
            hex = "0" + hex;
        }

        return hex;
    }

}

module.exports = Hashing;
var crypto = require('crypto');
var bcrypt = require('bcrypt-nodejs');
var argon2 = require('argon2');
var crc32 = require('crc-32');
var xor = require('bitwise-xor');
var md5crypt = require('nano-md5');
var descrypt = require('./descrypt');
var b64_sha512crypt = require('sha512crypt-node').b64_sha512crypt;

Hashing = {
    md5: function(sToHash, bBinary) {
        if (bBinary === true)
            return crypto.createHash('md5').update(sToHash).digest();
        else
            return crypto.createHash('md5').update(sToHash).digest("hex");
    },

    sha1: function(sToHash, bBinary) {
        if (bBinary === true)
            return crypto.createHash('sha1').update(sToHash).digest("");
        else
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

    customAlgorithm5: function(sPassword, sSalt) {
        return this.sha256(this.md5(sPassword + sSalt));
    },

    osCommerce_AEF: function(sPassword, sSalt) {
        return this.md5(sSalt + sPassword);
    },

    desCrypt: function(sPassword, sSalt) {
        return descrypt(sPassword, sSalt);
    },

    md5Crypt: function(sPassword, sSalt) {
        return md5crypt.crypt(sPassword, sSalt);
    },

    mySqlPre4_1: function(sPassword) {
        var result1;
        var result2;
        var nr = 1345345333;
        var add = 7;
        var nr2 = 0x12345671;
        var tmp;

        for (var i = 0; i < sPassword.length; i++) {
            var c = sPassword.charCodeAt(i);
            if (c === ' ' || c === '\t') {
                continue;
            }

            tmp = c;
            nr = nr ^ ((((nr & 63) + add) * tmp) + ((nr << 8) >>> 0));
            nr2 += ((nr2 << 8) >>> 0) ^ nr;
            add += tmp;
        }

        result1 = nr & (((1<<31)>>>0) - 1);
        result2 = nr2 & (((1<<31)>>>0) - 1);

        return this.intToHex(result1) + this.intToHex(result2);
    },

    mySqlPost4_1: function(sPassword) {
        return "*" + this.sha1(this.sha1(sPassword, true));
    },

    peopleSoft: function(sPassword) {
        var buf = new ArrayBuffer(sPassword.length*2);
        var bufView = new Uint16Array(buf);
        for (var i=0, strLen=sPassword.length; i < strLen; i++) {
            bufView[i] = sPassword.charCodeAt(i);
        }

        return new Buffer(crypto.createHash('sha1').update(new Buffer(buf)).digest("")).toString("base64");
    },

    punBB: function(sPassword, sSalt) {
        return this.sha1(sSalt + this.sha1(sPassword));
    },

    customAlgorithm6: function(sPassword, sSalt) {
        return this.sha1(sPassword + sSalt);
    },

    ave_DataLife_Diferior: function(sPassword) {
        return this.md5(this.md5(sPassword));
    },

    djangoMD5: function(sPassword, sSalt) {
        return "md5$" + sSalt + "$" + this.md5(sSalt + sPassword);
    },

    djangoSHA1: function(sPassword, sSalt) {
        return "sha1$" + sSalt + "$" + this.sha1(sSalt + sPassword);
    },

    pliggCMS: function(sPassword, sSalt) {
        return sSalt + this.sha1(sSalt + sPassword);
    },

    runCMS_SMF1_1: function(sPassword, sSalt) {
        return this.sha1(sSalt + sPassword);
    },

    ntlm: function(sPassword) {
        var buf = new ArrayBuffer(sPassword.length*2);
        var bufView = new Uint16Array(buf);
        for (var i=0, strLen=sPassword.length; i < strLen; i++) {
            bufView[i] = sPassword.charCodeAt(i);
        }
        return new Buffer(crypto.createHash('md4').update(new Buffer(buf)).digest("")).toString("hex");
    },

    sha384: function(sPassword) {
        return crypto.createHash('sha384').update(sPassword).digest("hex");
    },

    customAlgorithm7: function(sPassword, sSalt) {
        const derivedSalt = this.sha1(sSalt);
        const hmac = crypto.createHmac("sha256", "d2e1a4c569e7018cc142e9cce755a964bd9b193d2d31f02d80bb589c959afd7e");
        return hmac.update(derivedSalt + sPassword).digest("hex");
    },

    customAlgorithm9: function(sPassword, sSalt) {
        let result = this.sha512(sPassword + sSalt);
        for (let i = 0; i < 11; i++) {
            result = this.sha512(result);
        }
        return result;
    },

    sha512Crypt: function(sPassword, sSalt) {
        return b64_sha512crypt(sPassword, sSalt.substring(3));
    },

    customAlgorithm10: function(sPassword, sSalt) {
        return this.sha512(sPassword + ":" + sSalt);
    },

    argon2: function(sToHash, sSalt, fnCallback) {
        var hashType = argon2.argon2d;
        var tCost = 3;
        var mCost = 1024;
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
                                mCost = intValue;
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

        argon2.hash(sToHash, {
            salt: Buffer.from(justSalt),
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
    },

    aes256Encrypt: function(sToEncrypt, sKey, fnCallback) {
        try {
            crypto.randomBytes(8, (err, buf) => {
                if (err) {
                    fnCallback(err);
                }
                else {
                    var iv = buf.toString('hex');
                    var cipher = crypto.createCipheriv('aes256', sKey, iv);
                    var encrypted = cipher.update(sToEncrypt, 'utf8', 'hex');
                    encrypted += cipher.final('hex');

                    fnCallback(null, iv + encrypted);
                }
            });
        }
        catch (err) {
            fnCallback(err);
        }
    }
};

module.exports = Hashing;
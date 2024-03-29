const crypto = require('crypto');
const bcrypt = require('bcrypt-nodejs');
const argon2 = require('argon2');
const crc32 = require('crc-32');
const xor = require('bitwise-xor');
const md5crypt = require('nano-md5');
const descrypt = require('./descrypt');
const unixcrypt = require("unixcrypt");

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

    bcrypt: async function(sPassword, sSalt) {
        let twoy = false;
        let processedSalt = sSalt;
        if (sSalt.substring(0, 3) === '$2y') {
            twoy = true;
            processedSalt = '$2a' + sSalt.substring(3);
        }

        return new Promise((resolve, reject) => {
            bcrypt.hash(sPassword, processedSalt, null, function(err, hash) {
                if (err) {
                    reject(err);
                }
                else if (twoy === true) {
                    resolve("$2y" + hash.substring(3));
                }
                else {
                    resolve(hash);
                }
            });
        });
    },

    crc32: function(sToHash) {
        return this.intToHex(crc32.str(sToHash), 8);
    },

    phpbb3: function(sPassword, sSalt) {
        if (sSalt.substr(0, 3) !== '$H$') {
            return "";
        }

        const itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        let count = Math.pow(2, itoa64.indexOf(sSalt[3]));
        let justsalt = sSalt.substr(4);
        let passwordBuffer = new Buffer(sPassword);

        let hash = Hashing.md5(justsalt + sPassword, true);
        while (count-- > 0) {
            hash = Hashing.md5(Buffer.concat([hash, passwordBuffer]), true);
        }

        let hashout = '';
        let i = 0;
        count = 16;

        do
        {
            let value = hash[i++];
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
        const hash1 = Hashing.sha512(sPassword + sSalt, false);
        const hash2 = Hashing.whirlpool(sSalt + sPassword, false);
        return xor(new Buffer(hash1, 'hex'), new Buffer(hash2, 'hex')).toString('hex');
    },

    customAlgorithm2: function(sPassword, sSalt) {
        return Hashing.md5(sPassword + sSalt, false);
    },

    customAlgorithm4: function(sPassword, sSalt) {
        return Hashing.bcrypt(Hashing.md5(sPassword), sSalt);
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
        let result1;
        let result2;
        let nr = 1345345333;
        let add = 7;
        let nr2 = 0x12345671;
        let tmp;

        for (let i = 0; i < sPassword.length; i++) {
            let c = sPassword.charCodeAt(i);
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
        let buf = new ArrayBuffer(sPassword.length*2);
        let bufView = new Uint16Array(buf);
        for (let i=0, strLen=sPassword.length; i < strLen; i++) {
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
        let buf = new ArrayBuffer(sPassword.length*2);
        let bufView = new Uint16Array(buf);
        for (let i = 0, strLen=sPassword.length; i < strLen; i++) {
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

    sha256Crypt: function(sPassword, sSalt) {
        return unixcrypt.encrypt(sPassword, sSalt);
    },

    sha512Crypt: function(sPassword, sSalt) {
        return unixcrypt.encrypt(sPassword, sSalt);
    },

    customAlgorithm10: function(sPassword, sSalt) {
        return this.sha512(sPassword + ":" + sSalt);
    },

    authMeSHA256: function(sPassword, sSalt) {
        return "$SHA$" + sSalt + "$" + this.sha256(this.sha256(sPassword) + sSalt);
    },

    hmacSha1SaltAsKey: function(sPassword, sSalt) {
        return crypto.createHmac("sha1", sSalt).update(sPassword).digest("hex");
    },

    argon2: async function(sToHash, sSalt) {
        let hashType = argon2.argon2d;
        let tCost = 3;
        let mCost = 1024;
        let threads = 2;
        let hashLength = 20;
        let justSalt = sSalt;

        if (sSalt.indexOf("$argon2") === 0) {
            const saltComponents = sSalt.split('$');

            if (saltComponents.length === 5) {
                justSalt = Buffer.from(saltComponents[4], "base64");

                if (saltComponents[1] === 'argon2i')
                    hashType = argon2.argon2i;

                const saltParams = saltComponents[3].split(',');
                for (let i = 0; i < saltParams.length; i++) {
                    const saltValues = saltParams[i].split('=');
                    const intValue = parseInt(saltValues[1]);

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

        return argon2.hash(sToHash, {
            salt: Buffer.from(justSalt),
            type: hashType,
            hashLength: hashLength,
            timeCost: tCost,
            memoryCost: mCost,
            parallelism: threads
        });
    },

    intToHex: function(d, padding) {
        let number = d;
        if (number < 0) {
            number = 0xffffffff + number + 1;
        }

        let hex = Number(number).toString(16);
        padding = typeof (padding) === "undefined" || padding === null ? padding = 2 : padding;

        while (hex.length < padding) {
            hex = "0" + hex;
        }

        return hex;
    },

    aes256Encrypt: async function(sToEncrypt, sKey) {
        const buf = await crypto.randomBytes(8);
        const iv = buf.toString('hex');
        const cipher = crypto.createCipheriv('aes256', sKey, iv);
        let encrypted = cipher.update(sToEncrypt, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        return iv + encrypted;
    }
};

module.exports = Hashing;

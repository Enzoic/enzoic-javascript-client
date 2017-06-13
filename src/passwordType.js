PasswordType = {
    Plaintext: 0,
    MD5: 1,
    SHA1: 2,
    SHA256: 3,
    TripleDES: 4,
    IPBoard_MyBB: 5,
    VBulletinPre3_8_5: 6,
    VBulletinPost3_8_5: 7,
    BCrypt: 8,
    CRC32: 9,
    PHPBB3: 10,
    CustomAlgorithm1: 11,
    SCrypt: 12,
    CustomAlgorithm2: 13,
    SHA512: 14,
    MD5Crypt: 16,
    CustomAlgorithm4: 17,
    Unknown: 97,
    UnusablePassword: 98,
    None: 99
};

module.exports = PasswordType;
const EnzoicTest = require("../enzoic.js");
const PasswordType = require("../src/passwordtype.js");
const Hashing = require("../src/hashing.js");

//
// These are actually live tests and require a valid API key and Secret to be set in your environment variables.
// Set an env var for PP_API_KEY and PP_API_SECRET with the respective values prior to running the tests.
//
describe("Enzoic", function () {
    beforeEach(() => {
        this.enzoic = getEnzoic();
    });

    describe("constructor", () => {
        it("throws exception on missing API key and Secret", () => {
            let error = false;
            try {
                new EnzoicTest();
            }
            catch (e) {
                error = true;
                expect(e).toBe("API key and Secret must be provided");
            }

            expect(error).toBe(true);
        });

        it("instantiates correctly", () => {
            const enzoic = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET);
            expect(enzoic).toBeInstanceOf(Object);
            expect(enzoic).toHaveProperty("apiKey");
            expect(enzoic).toHaveProperty("secret");
            expect(enzoic.apiKey).toBe(process.env.PP_API_KEY);
            expect(enzoic.secret).toBe(process.env.PP_API_SECRET);
            expect(enzoic.host).toBe("api.enzoic.com");
        });

        it("works with alternate base API host", () => {
            const enzoic = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "api-alt.enzoic.com");
            expect(enzoic.host).toBe("api-alt.enzoic.com");
        });
    });

    describe("#checkPassword()", () => {
        it("gets correct positive result", async () => {
            const result = await this.enzoic.checkPassword("123456");
            expect(result).toBe(true);
        });

        it("gets correct negative result", async () => {
            const result = await this.enzoic.checkPassword("kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd");
            expect(result).toBe(false);
        });

        it("handles errors properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.checkPassword("123456");
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#checkCredentials()", () => {
        it("gets correct positive results", async () => {
            const promises = [];
            for (let i = 1; i <= 40; i++) {
                if ([4, 9, 12, 15].indexOf(i) < 0) {
                    promises.push(this.enzoic.checkCredentials("eicar_" + i + "@enzoic.com", "123456"));
                }
            }

            // make sure results were all positive
            const results = await Promise.all(promises);
            for (let i = 0; i < results.length; i++) expect(results[i]).toBe(true);
        });

        it("gets correct negative result", async () => {
            const promises = [];
            for (let i = 1; i <= 32; i++) {
                if ([4, 9, 12, 15].indexOf(i) < 0) {
                    promises.push(this.enzoic.checkCredentials("eicar_" + i + "@enzoic.com", "1234561212"));
                }
            }

            // make sure results were all negative
            const results = await Promise.all(promises);
            for (let i = 0; i < results.length; i++) expect(results[i]).toBe(false);
        });

        it("handles errors properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.checkCredentials("eicar_1@enzoic.com", "123456");
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#checkCredentialsEx()", () => {
        it("gets correct positive result with no options", async () => {
            const result = await this.enzoic.checkCredentialsEx("testpwdpng445", "testpwdpng4452", {});
            expect(result).toBe(true);
        });

        it("gets correct negative result with no options", async () => {
            const result = await this.enzoic.checkCredentialsEx("testpwdpng445", "123456122", {});
            expect(result).toBe(false);
        });

        it("handles errors properly with no options", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.checkCredentialsEx("testpwdpng445", "123456", {});
            }
            catch (ex) {
                expect(ex).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });

        it("gets correct result with hash exclusion", async () => {
            // exclude the only hash type on this result
            const result = await this.enzoic.checkCredentialsEx("testpwdpng445", "testpwdpng4452", {
                excludeHashAlgorithms: [7]
            });
            expect(result).toBe(false);
        });

        it("gets correct result with last check date", async () => {
            const result = await this.enzoic.checkCredentialsEx("testpwdpng445", "testpwdpng4452", {
                lastCheckDate: new Date("2018-03-01")
            });
            expect(result).toBe(false);
        });

        it("gets correct result with last check date with different creds", async () => {
            const result = await this.enzoic.checkCredentialsEx("test@passwordping.com", "123456", {
                lastCheckDate: new Date()
            });
            expect(result).toBe(false);
        });

        it("gets correct result with include exposures flag set", async () => {
            const result = await this.enzoic.checkCredentialsEx("test@passwordping.com", "123456", {
                includeExposures: true
            });
            expect(result).toEqual({
                "exposures": [
                    "5c13f5a31d75b80f60b76533"
                ]
            });
        });
    });

    describe("#getExposuresForUser()", () => {
        it("gets correct result", async () => {
            const result = await this.enzoic.getExposuresForUser("eicar_0@enzoic.com");
            expect(result.count).toBe(5);
            expect(result.exposures.length).toBe(5);
            expect(result.exposures).toEqual(["634908d06715cc1b5b201a1a", "634908d0e0513eb0788aa0b5",
                "634908d26715cc1b5b201a1d", "634908d2e0513eb0788aa0b9", "63490990e0513eb0788aa0d1"]);
        });

        it("handles negative result correctly", async () => {
            const result = await this.enzoic.getExposuresForUser("@@bogus-username@@");
            expect(result.count).toBe(0);
            expect(result.exposures.length).toBe(0);
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.getExposuresForUser("eicar");
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#getExposedUsersForDomain()", () => {
        let pagingToken = null;

        it("gets correct result", async () => {
            const result = await this.enzoic.getExposedUsersForDomain("email.tst", 2, null);
            expect(result.count).toBe(12);
            expect(result.users.length).toBe(2);
            expect(result.users).toStrictEqual([
                {
                    "username": "sample@email.tst",
                    "exposures": [
                        "57dc11964d6db21300991b78",
                        "57ffcf3c1395c80b30dd4429",
                        "5805029914f33808dc802ff7",
                        "598e5b844eb6d82ea07c5783",
                        "59bbf691e5017d2dc8a96eab",
                        "59bc2016e5017d2dc8bdc36a",
                        "59bebae9e5017d2dc85fc2ab",
                        "59f36f8c4eb6d85ba0bee09c",
                        "5bcf9af3e5017d07201e2149",
                        "5c4f818bd3cef70e983dda1e"
                    ]
                },
                {
                    "username": "xxxxxxxxxx@email.tst",
                    "exposures": [
                        "5805029914f33808dc802ff7"
                    ]
                }
            ]);
            expect(result.pagingToken).not.toBeNull();
            pagingToken = result.pagingToken;
        });

        it("gets correct result for subsequent page", async () => {
            expect(pagingToken).not.toBeNull();

            const result = await this.enzoic.getExposedUsersForDomain("email.tst", 2, pagingToken);
            expect(result.count).toBe(12);
            expect(result.users.length).toBe(2);
            expect(result.users).toEqual([
                {
                    "username": "cbeiqvf@email.tst",
                    "exposures": [
                        "5805029914f33808dc802ff7"
                    ]
                },
                {
                    "username": "yjybey@email.tst",
                    "exposures": [
                        "5805029914f33808dc802ff7"
                    ]
                }
            ]);
        });

        it("handles negative result correctly", async () => {
            const result = await this.enzoic.getExposedUsersForDomain("@@bogus-domain@@", 2, null);
            expect(result.count).toBe(0);
            expect(result.users.length).toBe(0);
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.getExposedUsersForDomain("email.tst", 2, null);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#getExposuresForDomain()", () => {
        it("gets correct result for no details", async () => {
            const result = await this.enzoic.getExposuresForDomain("email.tst", false);
            expect(result.count).toBe(10);
            expect(result.exposures.length).toBe(10);
            expect(result.exposures.sort()).toEqual([
                "57ffcf3c1395c80b30dd4429",
                "57dc11964d6db21300991b78",
                "5805029914f33808dc802ff7",
                "598e5b844eb6d82ea07c5783",
                "59bbf691e5017d2dc8a96eab",
                "59bc2016e5017d2dc8bdc36a",
                "59bebae9e5017d2dc85fc2ab",
                "59f36f8c4eb6d85ba0bee09c",
                "5bcf9af3e5017d07201e2149",
                "5c4f818bd3cef70e983dda1e"
            ].sort());
        });

        it("gets correct result for include details", async () => {
            const result = await this.enzoic.getExposuresForDomain("email.tst", true);
            expect(result.count).toBe(10);
            expect(result.exposures.length).toBe(10);
            expect(result.exposures[0]).toEqual(
                {
                    "id": "57dc11964d6db21300991b78",
                    "title": "funsurveys.net",
                    "entries": 5123,
                    "date": "2015-05-01T00:00:00.000Z",
                    "category": "Marketing",
                    "passwordType": "Cleartext",
                    "exposedData": [
                        "Emails",
                        "Passwords"
                    ],
                    "dateAdded": "2016-09-16T15:36:54.000Z",
                    "sourceURLs": [],
                    "domainsAffected": 683,
                    "source": "Unspecified",
                    "sourceFileCount": 1
                }
            );
        });

        it("handles negative result correctly", async () => {
            const result = await this.enzoic.getExposuresForDomain("@@bogus-domain@@", false);
            expect(result.count).toBe(0);
            expect(result.exposures.length).toBe(0);
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.getExposuresForDomain("email.tst", false);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#getExposuresForDomainEx()", () => {
        it("gets correct result for no details", async () => {
            const result = await this.enzoic.getExposuresForDomainEx("email.tst", false, 2, null);
            expect(result.count).toBe(10);
            expect(result.exposures.length).toBe(2);
            expect(result.pagingToken).not.toBeNull();
            expect(result.exposures.sort()).toEqual([
                "57ffcf3c1395c80b30dd4429",
                "57dc11964d6db21300991b78",
            ].sort());
        });

        it("gets correct result for include details", async () => {
            const result = await this.enzoic.getExposuresForDomain("email.tst", true);
            expect(result.count).toBe(10);
            expect(result.exposures.length).toBe(10);
            expect(result.exposures[0]).toEqual(
                {
                    "id": "57dc11964d6db21300991b78",
                    "title": "funsurveys.net",
                    "entries": 5123,
                    "date": "2015-05-01T00:00:00.000Z",
                    "category": "Marketing",
                    "passwordType": "Cleartext",
                    "exposedData": [
                        "Emails",
                        "Passwords"
                    ],
                    "dateAdded": "2016-09-16T15:36:54.000Z",
                    "sourceURLs": [],
                    "domainsAffected": 683,
                    "source": "Unspecified",
                    "sourceFileCount": 1
                }
            );
        });

        it("handles negative result correctly", async () => {
            const result = await this.enzoic.getExposuresForDomain("@@bogus-domain@@", false);
            expect(result.count).toBe(0);
            expect(result.exposures.length).toBe(0);
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.getExposuresForDomain("email.tst", false);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#getExposureDetails()", () => {
        it("gets correct result", async () => {
            const result = await this.enzoic.getExposureDetails("5820469ffdb8780510b329cc");
            expect(result).toEqual({
                id: "5820469ffdb8780510b329cc",
                title: "last.fm",
                category: "Music",
                date: "2012-03-01T00:00:00.000Z",
                dateAdded: "2016-11-07T09:17:19.000Z",
                passwordType: "MD5",
                exposedData: ["Emails", "Passwords", "Usernames", "Website Activity"],
                entries: 81967007,
                domainsAffected: 1219053,
                sourceURLs: [],
                source: "Unspecified",
                sourceFileCount: 1
            });
        });

        it("handles negative result correctly", async () => {
            const result = await this.enzoic.getExposureDetails("111111111111111111111111");
            expect(result).toBe(null);
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.getExposureDetails("5820469ffdb8780510b329cc");
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#addUserAlertSubscriptions()", () => {
        beforeEach(() => {
            this.testUsers = [
                "eicar_0@enzoic.com",
                "eicar_1@enzoic.com"
            ];
        });

        it("cleans up previous test data", async () => {
            const result = await this.enzoic.deleteUserAlertSubscriptions(this.testUsers);
            expect(result.deleted).toBeGreaterThan(-1);
            expect(result.notFound).toBeGreaterThan(-1);
        });

        it("gets correct result", async () => {
            const result = await this.enzoic.addUserAlertSubscriptions(this.testUsers);
            expect(result).toEqual({
                added: 2,
                alreadyExisted: 0
            });
        });

        it("gets correct repeated result", async () => {
            const result = await this.enzoic.addUserAlertSubscriptions(this.testUsers);
            expect(result).toEqual({
                added: 0,
                alreadyExisted: 2
            });
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.addUserAlertSubscriptions(this.testUsers);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#addUserAlertSubscriptionsWithCustomData()", () => {
        beforeEach(() => {
            this.testUsers = [
                "eicar_0@enzoic.com",
                "eicar_1@enzoic.com"
            ];
            this.testCustomData = "123456";
            this.testCustomData2 = "1234567";
        })

        it("cleans up previous test data", async () => {
            const result = await this.enzoic.deleteUserAlertSubscriptionsByCustomData(this.testCustomData);
            expect(result.deleted).toBeGreaterThan(-1);
            expect(result.notFound).toBeGreaterThan(-1);
        });

        // it('cleans up previous hash test data', function(done) {
        //     enzoic.deleteUserAlertSubscriptions(testUserHashes,
        //         function (err, result) {
        //             expect(err).toBe(null);
        //             expect(result.deleted)..toBeGreaterThan(-1);
        //             expect(result.notFound)..toBeGreaterThan(-1);
        //             done();
        //         }
        //     );
        // });

        it("cleans up previous alt test data", async () => {
            const result = await this.enzoic.deleteUserAlertSubscriptionsByCustomData(this.testCustomData2);
            expect(result.deleted).toBeGreaterThan(-1);
            expect(result.notFound).toBeGreaterThan(-1);
        });

        it("gets correct result", async () => {
            const result = await this.enzoic.addUserAlertSubscriptions(this.testUsers, this.testCustomData);
            expect(result).toEqual({
                added: 2,
                alreadyExisted: 0
            });
        });

        it("gets correct repeated result", async () => {
            const result = await this.enzoic.addUserAlertSubscriptions(this.testUsers, this.testCustomData);
            expect(result).toEqual({
                added: 0,
                alreadyExisted: 2
            });
        });

        it("allows same hashes with different custom data", async () => {
            const result = await this.enzoic.addUserAlertSubscriptions(this.testUsers, this.testCustomData2);
            expect(result).toEqual({
                added: 2,
                alreadyExisted: 0
            });
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.addUserAlertSubscriptions(this.testUsers, this.testCustomData);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#deleteUserAlertSubscriptions()", () => {
        beforeEach(async () => {
            this.testUsers = [
                "eicar_0@enzoic.com",
                "eicar_1@enzoic.com"
            ];
            await this.enzoic.deleteUserAlertSubscriptions(this.testUsers);

            // add test data
            const addResult = await this.enzoic.addUserAlertSubscriptions(this.testUsers);
            expect(addResult.added).toBe(2);
            expect(addResult.alreadyExisted).toBe(0);
        });

        it("gets correct result", async () => {
            const result = await this.enzoic.deleteUserAlertSubscriptions(this.testUsers);
            expect(result).toEqual({
                deleted: 2,
                notFound: 0
            });
        });

        it("gets correct result when nothing to delete", async () => {
            // delete test data
            await this.enzoic.deleteUserAlertSubscriptions(this.testUsers);

            const result = await this.enzoic.deleteUserAlertSubscriptions(this.testUsers);
            expect(result).toEqual({
                deleted: 0,
                notFound: 2
            });
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.deleteUserAlertSubscriptions(this.testUsers);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#deleteUserAlertSubscriptionsByCustomData()", () => {
        beforeEach(() => {
            this.testUsers = [
                "eicar_0@enzoic.com",
                "eicar_1@enzoic.com"
            ];
            this.testCustomData = "123456";
        });

        it("cleans up previous test data", async () => {
            const result = await this.enzoic.deleteUserAlertSubscriptionsByCustomData(this.testCustomData);
            expect(result.deleted).toBeGreaterThan(-1);
            expect(result.notFound).toBeGreaterThan(-1);
        });

        it("adds test data", async () => {
            const result = await this.enzoic.addUserAlertSubscriptions(this.testUsers, this.testCustomData);
            expect(result.added).toBeGreaterThan(-1);
            expect(result.alreadyExisted).toBeGreaterThan(-1);
        });

        it("gets correct result", async () => {
            const result = await this.enzoic.deleteUserAlertSubscriptionsByCustomData(this.testCustomData);
            expect(result).toEqual({
                deleted: 2,
                notFound: 0
            });
        });

        it("gets correct repeated result", async () => {
            const result = await this.enzoic.deleteUserAlertSubscriptionsByCustomData(this.testCustomData);
            expect(result).toEqual({
                deleted: 0,
                notFound: 1
            });
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.deleteUserAlertSubscriptionsByCustomData(this.testCustomData);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#isUserSubscribedForAlerts()", () => {
        beforeEach(() => {
            this.testUser = "eicar_0@enzoic.com";
        });

        it("adds test data", async () => {
            const result = await this.enzoic.addUserAlertSubscriptions(this.testUser);
            expect(result.added).toBeGreaterThan(-1);
            expect(result.alreadyExisted).toBeGreaterThan(-1);
        });

        it("gets correct result when exists", async () => {
            const result = await this.enzoic.isUserSubscribedForAlerts(this.testUser);
            expect(result).toBe(true);
        });

        it("delete test data", async () => {
            const result = await this.enzoic.deleteUserAlertSubscriptions(this.testUser);
            expect(result.deleted).toBeGreaterThan(-1);
            expect(result.notFound).toBeGreaterThan(-1);
        });

        it("gets correct result when not exists", async () => {
            const result = await this.enzoic.isUserSubscribedForAlerts(this.testUser);
            expect(result).toBe(false);
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.isUserSubscribedForAlerts(this.testUser);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#getUserAlertSubscriptions()", () => {
        beforeEach(() => {
            this.testUserHashes = [
                "eicar_0@enzoic.com",
                "eicar_1@enzoic.com",
                "eicar_2@enzoic.com",
                "eicar_3@enzoic.com",
                "eicar_4@enzoic.com",
                "eicar_5@enzoic.com",
                "eicar_6@enzoic.com",
                "eicar_7@enzoic.com",
                "eicar_8@enzoic.com",
                "eicar_9@enzoic.com",
                "eicar_10@enzoic.com",
                "eicar_11@enzoic.com",
                "eicar_12@enzoic.com",
                "eicar_13@enzoic.com",
            ];
        });

        it("adds test data", async () => {
            const result = await this.enzoic.addUserAlertSubscriptions(this.testUserHashes);
            expect(result.added).toBeGreaterThan(-1);
            expect(result.alreadyExisted).toBeGreaterThan(-1);
        });

        let response1;

        it("gets correct result", async () => {
            const result = await this.enzoic.getUserAlertSubscriptions(4, null);
            expect(result.count).toBeGreaterThan(13);
            expect(result.usernameHashes.length).toBe(4);
            expect(result.pagingToken).not.toBeNull();

            // save off result for next call
            response1 = result;

        });

        it("gets correct result for next page", async () => {
            const result = await this.enzoic.getUserAlertSubscriptions(4, response1.pagingToken);
            expect(result.count).toBeGreaterThan(13);
            expect(result.usernameHashes.length).toBe(4);
            expect(result.pagingToken).not.toBeNull();
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.getUserAlertSubscriptions(4, null);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#addDomainAlertSubscriptions()", () => {
        beforeEach(() => {
            this.testDomains = [
                "testadddomain1.com",
                "testadddomain2.com"
            ];
        });

        it("cleans up previous test data", async () => {
            const result = await this.enzoic.deleteDomainAlertSubscriptions(this.testDomains);
            expect(result.deleted).toBeGreaterThan(-1);
            expect(result.notFound).toBeGreaterThan(-1);
        });

        it("gets correct result", async () => {
            const result = await this.enzoic.addDomainAlertSubscriptions(this.testDomains);
            expect(result).toEqual({
                added: 2,
                alreadyExisted: 0
            });
        });

        it("gets correct repeated result", async () => {
            const result = await this.enzoic.addDomainAlertSubscriptions(this.testDomains);
            expect(result).toEqual({
                added: 0,
                alreadyExisted: 2
            });
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.addDomainAlertSubscriptions(this.testDomains);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#deleteDomainAlertSubscriptions()", () => {
        beforeEach(() => {
            this.testDomains = [
                "testdeletedomain1.com",
                "testdeletedomain2.com"
            ];
        });

        it("adds test data", async () => {
            const result = await this.enzoic.addDomainAlertSubscriptions(this.testDomains);
            expect(result.added).toBeGreaterThan(-1);
            expect(result.alreadyExisted).toBeGreaterThan(-1);
        });

        it("gets correct result", async () => {
            const result = await this.enzoic.deleteDomainAlertSubscriptions(this.testDomains);
            expect(result).toEqual({
                deleted: 2,
                notFound: 0
            });
        });

        it("gets correct repeated result", async () => {
            const result = await this.enzoic.deleteDomainAlertSubscriptions(this.testDomains);
            expect(result).toEqual({
                deleted: 0,
                notFound: 2
            });
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.deleteDomainAlertSubscriptions(this.testDomains);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#isDomainSubscribedForAlerts()", () => {
        beforeEach(() => {
            this.testDomain = "testtestdomain1.com";
        });

        it("adds test data", async () => {
            const result = await this.enzoic.addDomainAlertSubscriptions(this.testDomain);
            expect(result.added).toBeGreaterThan(-1);
            expect(result.alreadyExisted).toBeGreaterThan(-1);
        });

        it("gets correct result when exists", async () => {
            const result = await this.enzoic.isDomainSubscribedForAlerts(this.testDomain);
            expect(result).toBe(true);
        });

        it("delete test data", async () => {
            const result = await this.enzoic.deleteDomainAlertSubscriptions(this.testDomain);
            expect(result.deleted).toBeGreaterThan(-1);
            expect(result.notFound).toBeGreaterThan(-1);
        });

        it("gets correct result when not exists", async () => {
            const result = await this.enzoic.isDomainSubscribedForAlerts(this.testDomain);
            expect(result).toBe(false);
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.isDomainSubscribedForAlerts(this.testDomain);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#getDomainAlertSubscriptions()", () => {
        const testDomains = [
            "testgetdomain1.com",
            "testgetdomain2.com",
            "testgetdomain3.com",
            "testgetdomain4.com",
            "testgetdomain5.com",
            "testgetdomain6.com",
            "testgetdomain7.com",
            "testgetdomain8.com",
            "testgetdomain9.com",
            "testgetdomain10.com",
            "testgetdomain11.com",
            "testgetdomain12.com",
            "testgetdomain13.com",
            "testgetdomain14.com"
        ];

        it("adds test data", async () => {
            const result = await this.enzoic.addDomainAlertSubscriptions(testDomains);
            expect(result.added).toBeGreaterThan(-1);
            expect(result.alreadyExisted).toBeGreaterThan(-1);
        });

        let response1;

        it("gets correct result", async () => {
            const result = await this.enzoic.getDomainAlertSubscriptions(4, null);
            expect(result.count).toBeGreaterThan(13);
            expect(result.domains.length).toBe(4);
            expect(result.pagingToken).not.toBeNull();

            // save off result for next call
            response1 = result;

        });

        it("gets correct result for next page", async () => {
            const result = await this.enzoic.getDomainAlertSubscriptions(4, response1.pagingToken);
            expect(result.count).toBeGreaterThan(13);
            expect(result.domains.length).toBe(4);
            expect(result.pagingToken).not.toBeNull();
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.getDomainAlertSubscriptions(4, null);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#getUserPasswords()", () => {
        const enzoic = getEnzoic();

        it("gets correct result", async () => {
            const result = await this.enzoic.getUserPasswords("eicar_0@enzoic.com");
            expect(result.passwords.length).toBe(4);
            expect(result.lastBreachDate).toBe("2022-10-14T07:02:40.000Z");
            expect(result.passwords).toEqual([
                {
                    "hashType": 0,
                    "salt": "",
                    "password": "password123",
                    "exposures": [
                        "634908d06715cc1b5b201a1a",
                        "634908d2e0513eb0788aa0b9",
                    ]
                },
                {
                    "hashType": 0,
                    "salt": "",
                    "password": "g0oD_on3",
                    "exposures": [
                        "634908d2e0513eb0788aa0b9"
                    ]
                },
                {
                    "hashType": 0,
                    "salt": "",
                    "password": "Easy2no",
                    "exposures": [
                        "634908d26715cc1b5b201a1d"
                    ]
                },
                {
                    "hashType": 0,
                    "salt": "",
                    "password": "123456",
                    "exposures": [
                        "634908d0e0513eb0788aa0b5",
                        "63490990e0513eb0788aa0d1",
                    ]
                }
            ]);
        });

        it("handles negative result correctly", async () => {
            const result = await this.enzoic.getUserPasswords("@@bogus-user@@");
            expect(result).toBe(false);
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.getUserPasswords("eicar_0@enzoic.com");
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#getUserPasswordsEx()", () => {
        const enzoic = getEnzoic();
        const pagingToken = null;

        it("gets correct result", async () => {
            const result = await this.enzoic.getUserPasswordsEx("eicar_0@enzoic.com", true);
            expect(result.passwords.length).toBe(4);
            expect(result.lastBreachDate).toBe("2022-10-14T07:02:40.000Z");
            expect(result.passwords).toEqual([
                {
                    "hashType": 0,
                    "salt": "",
                    "password": "password123",
                    "exposures": [
                        {
                            "category": "Testing Ignore",
                            "date": null,
                            "dateAdded": "2022-10-14T06:59:28.000Z",
                            "domainsAffected": 1,
                            "entries": 5,
                            "exposedData": [
                                "Emails",
                                "Passwords"
                            ],
                            "id": "634908d06715cc1b5b201a1a",
                            "passwordType": "MD5",
                            "source": "Testing - Ignore",
                            "sourceFileCount": 1,
                            "sourceURLs": [],
                            "title": "enzoic test breach 1",
                        },
                        {
                            "category": "Testing Ignore",
                            "date": null,
                            "dateAdded": "2022-10-14T06:59:30.000Z",
                            "domainsAffected": 1,
                            "entries": 2,
                            "exposedData": [
                                "Emails",
                                "Passwords"
                            ],
                            "id": "634908d2e0513eb0788aa0b9",
                            "passwordType": "Cleartext",
                            "source": "Testing - Ignore",
                            "sourceFileCount": 1,
                            "sourceURLs": [],
                            "title": "enzoic test breach 5"
                        }]
                },
                {
                    "hashType": 0,
                    "salt": "",
                    "password": "g0oD_on3",
                    "exposures": [
                        {
                            "category": "Testing Ignore",
                            "date": null,
                            "dateAdded": "2022-10-14T06:59:30.000Z",
                            "domainsAffected": 1,
                            "entries": 2,
                            "exposedData": [
                                "Emails",
                                "Passwords"
                            ],
                            "id": "634908d2e0513eb0788aa0b9",
                            "passwordType": "Cleartext",
                            "source": "Testing - Ignore",
                            "sourceFileCount": 1,
                            "sourceURLs": [],
                            "title": "enzoic test breach 5"
                        }
                    ]
                },
                {
                    "hashType": 0,
                    "salt": "",
                    "password": "Easy2no",
                    "exposures": [
                        {
                            "category": "Testing Ignore",
                            "date": null,
                            "dateAdded": "2022-10-14T06:59:30.000Z",
                            "domainsAffected": 1,
                            "entries": 4,
                            "exposedData": [
                                "Emails",
                                "Passwords"
                            ],
                            "id": "634908d26715cc1b5b201a1d",
                            "passwordType": "MD5",
                            "source": "Testing - Ignore",
                            "sourceFileCount": 1,
                            "sourceURLs": [],
                            "title": "enzoic test breach 4"
                        }
                    ]
                },
                {
                    "hashType": 0,
                    "salt": "",
                    "password": "123456",
                    "exposures": [
                        {
                            "category": "Testing Ignore",
                            "date": null,
                            "dateAdded": "2022-10-14T06:59:28.000Z",
                            "domainsAffected": 1,
                            "entries": 5,
                            "exposedData": [
                                "Emails",
                                "Passwords"
                            ],
                            "id": "634908d0e0513eb0788aa0b5",
                            "passwordType": "MD5",
                            "source": "Testing - Ignore",
                            "sourceFileCount": 1,
                            "sourceURLs": [],
                            "title": "enzoic test breach 2"
                        },
                        {
                            "category": "Testing Ignore",
                            "date": null,
                            "dateAdded": "2022-10-14T07:02:40.000Z",
                            "domainsAffected": 1,
                            "entries": 3,
                            "exposedData": [
                                "Emails",
                                "Passwords"
                            ],
                            "id": "63490990e0513eb0788aa0d1",
                            "passwordType": "Cleartext",
                            "source": "Testing - Ignore",
                            "sourceFileCount": 1,
                            "sourceURLs": [],
                            "title": "enzoic test breach 3",
                        }]
                }
            ]);
        });

        it("handles negative result correctly", async () => {
            const result = await this.enzoic.getUserPasswordsEx("@@bogus-user@@", true);
            expect(result).toBe(false);
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com");

            try {
                const result = await bogusServer.getUserPasswordsEx("eicar_0@enzoic.com", true);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#calcPasswordHash()", () => {
        it("MD5 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.MD5, "123456", null);
            expect(result).toBe("e10adc3949ba59abbe56e057f20f883e");
        });

        it("SHA1 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.SHA1, "123456", null);
            expect(result).toBe("7c4a8d09ca3762af61e59520943dc26494f8941b");
        });

        it("SHA256 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.SHA256, "123456", null);
            expect(result).toBe("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92");
        });

        it("IPBoard_MyBB works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.IPBoard_MyBB, "123456", ";;!_X");
            expect(result).toBe("2e705e174e9df3e2c8aaa30297aa6d74");
        });

        it("VBulletin works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.VBulletinPost3_8_5, "123456789", "]G@");
            expect(result).toBe("57ce303cdf1ad28944d43454cea38d7a");
        });

        it("BCrypt works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.BCrypt, "12345", "$2a$12$2bULeXwv2H34SXkT1giCZe");
            expect(result).toBe("$2a$12$2bULeXwv2H34SXkT1giCZeJW7A6Q0Yfas09wOCxoIC44fDTYq44Mm");
        });

        it("CRC32 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.CRC32, "123456", null);
            expect(result).toBe("0972d361");
        });

        it("PHPBB3 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.PHPBB3, "123456789", "$H$993WP3hbz");
            expect(result).toBe("$H$993WP3hbzy0N22X06wxrCc3800D2p41");
        });

        it("CustomAlgorithm1 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.CustomAlgorithm1, "123456", "00new00");
            expect(result).toBe("cee66db36504915f48b2d545803a4494bb1b76b6e9d8ba8c0e6083ff9b281abdef31f6172548fdcde4000e903c5a98a1178c414f7dbf44cffc001aee8e1fe206");
        });

        it("CustomAlgorithm2 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.CustomAlgorithm2, "123456", "123");
            expect(result).toBe("579d9ec9d0c3d687aaa91289ac2854e4");
        });

        it("SHA512 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.SHA512, "test", null);
            expect(result).toBe("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff");
        });

        it("MD5Crypt works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.MD5Crypt, "123456", "$1$4d3c09ea");
            expect(result).toBe("$1$4d3c09ea$hPwyka2ToWFbLTOq.yFjf.");
        });

        it("CustomAlgorithm4 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.CustomAlgorithm4, "1234", "$2y$12$Yjk3YjIzYWIxNDg0YWMzZO");
            expect(result).toBe("$2y$12$Yjk3YjIzYWIxNDg0YWMzZOpp/eAMuWCD3UwX1oYgRlC1ci4Al970W");
        });

        it("CustomAlgorithm5 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.CustomAlgorithm5, "password", "123456");
            expect(result).toBe("69e7ade919a318d8ecf6fd540bad9f169bce40df4cae4ac1fb6be2c48c514163");
        });

        it("DESCrypt works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.DESCrypt, "password", "X.");
            expect(result).toBe("X.OPW8uuoq5N.");
        });

        it("MySQLPre4_1 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.MySQLPre4_1, "password", null);
            expect(result).toBe("5d2e19393cc5ef67");
        });

        it("MySQLPost4_1 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.MySQLPost4_1, "test", null);
            expect(result).toBe("*94bdcebe19083ce2a1f959fd02f964c7af4cfc29");
        });

        it("PeopleSoft works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.PeopleSoft, "TESTING", null);
            expect(result).toBe("3weP/BR8RHPLP2459h003IgJxyU=");
        });

        it("PunBB works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.PunBB, "password", "123");
            expect(result).toBe("0c9a0dc3dd0b067c016209fd46749c281879069e");
        });

        it("CustomAlgorithm6 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.CustomAlgorithm6, "password", "123");
            expect(result).toBe("cbfdac6008f9cab4083784cbd1874f76618d2a97");
        });

        it("PartialMD5_20 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.PartialMD5_20, "password", null);
            expect(result).toBe("5f4dcc3b5aa765d61d83");
        });

        it("AVE_DataLife_Diferior works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.AVE_DataLife_Diferior, "password", null);
            expect(result).toBe("696d29e0940a4957748fe3fc9efd22a3");
        });

        it("DjangoMD5 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.DjangoMD5, "password", "c6218");
            expect(result).toBe("md5$c6218$346abd81f2d88b4517446316222f4276");
        });

        it("DjangoSHA1 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.DjangoSHA1, "password", "c6218");
            expect(result).toBe("sha1$c6218$161d1ac8ab38979c5a31cbaba4a67378e7e60845");
        });

        it("PartialMD5_29 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.PartialMD5_29, "password", null);
            expect(result).toBe("5f4dcc3b5aa765d61d8327deb882c");
        });

        it("PliggCMS works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.PliggCMS, "password", "123");
            expect(result).toBe("1230de084f38ace8e3d82597f55cc6ad5d6001568e6");
        });

        it("RunCMS_SMF1_1 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.RunCMS_SMF1_1, "password", "123");
            expect(result).toBe("0de084f38ace8e3d82597f55cc6ad5d6001568e6");
        });

        it("NTLM works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.NTLM, "123456", null);
            expect(result).toBe("32ed87bdb5fdc5e9cba88547376818d4");
        });

        it("SHA1Dash works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.SHA1Dash, "123456", "478c8029d5efddc554bf2fe6bb2219d8c897d4a0");
            expect(result).toBe("55566a759b86fbbd979b579b232f4dd214d08068");
        });

        it("SHA384 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.SHA384, "123456", null);
            expect(result).toBe("0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454");
        });

        it("CustomAlgorithm7 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.CustomAlgorithm7, "123456", "123456");
            expect(result).toBe("a753d386613efd6d4a534cec97e73890f8ec960fe6634db6dbfb9b2aab207982");
        });

        it("CustomAlgorithm8 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.CustomAlgorithm8, "matthew", "Dn");
            expect(result).toBe("9fc389447b7eb88aff45a1069bf89fbeff89b8fb7d11a6f450583fa4c9c70503");
        });

        it("CustomAlgorithm9 works", async () => {
            const result = await this.enzoic.calcPasswordHash(PasswordType.CustomAlgorithm9, "0rangepeel", "6kpcxVSjagLgsNCUCr-D");
            expect(result).toBe("07c691fa8b022b52ac1c44cab3e056b344a7945b6eb9db727e3842b28d94fe18c17fe5b47b1b9a29d8149acbd7b3f73866cc12f0a8a8b7ab4ac9470885e052dc");
        });
    });

    describe("#addCredentialsAlertSubscription()", () => {
        beforeEach(async () => {
            this.username = "UNIT_TEST_addCredentialsAlertSubscription@passwordping.com";
            this.password = "unittesttest";
            this.customData = "UNIT_TEST_addCredentialsAlertSubscription";

            await this.enzoic.deleteCredentialsAlertSubscriptionByCustomData(this.customData);
        });

        it("cleans up previous test data", async () => {
            const result = await this.enzoic.deleteCredentialsAlertSubscriptionByCustomData(this.customData);
        });

        it("gets correct result", async () => {
            const result = await this.enzoic.addCredentialsAlertSubscription(this.username, this.password, this.customData);
            expect(typeof (result.monitoredCredentialsID)).toBe("string");
            expect(result.monitoredCredentialsID.length).toBe(24);
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com", process.env.PP_ENC_KEY);

            try {
                const result = await bogusServer.addCredentialsAlertSubscription(this.username, this.password, this.customData);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#deleteCredentialsAlertSubscriptions()", () => {
        beforeEach(async () => {
            this.username = "UNIT_TEST_deleteCredentialsAlertSubscriptions@passwordping.com";
            this.password = "unittesttest";
            this.customData = "UNIT_TEST_deleteCredentialsAlertSubscriptions";
        });

        let newID;
        it("adds test data", async () => {
            await this.enzoic.deleteCredentialsAlertSubscriptionByCustomData(this.customData);

            const result = await this.enzoic.addCredentialsAlertSubscription(this.username, this.password, this.customData);
            expect(typeof (result.monitoredCredentialsID)).toBe("string");
            expect(result.monitoredCredentialsID.length).toBe(24);
            newID = result.monitoredCredentialsID;
        });

        it("gets correct result", async () => {
            const result = await this.enzoic.deleteCredentialsAlertSubscription(newID);
            expect(result).toEqual({
                deleted: 1,
                notFound: 0
            });
        });

        it("gets correct repeated result", async () => {
            const result = await this.enzoic.deleteCredentialsAlertSubscription(newID);
            expect(result).toEqual({
                deleted: 0,
                notFound: 1
            });
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com", process.env.PP_ENC_KEY);

            try {
                const result = await bogusServer.deleteCredentialsAlertSubscription(newID);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#getCredentialsAlertSubscriptions()", () => {
        beforeEach(async () => {
            this.username = "UNIT_TEST_getCredentialsAlertSubscriptions@passwordping.com";
            this.password = "unittesttest";
            this.customData = "UNIT_TEST_getCredentialsAlertSubscriptions";
        });

        it("adds test data", async () => {
            await this.enzoic.deleteCredentialsAlertSubscriptionByCustomData(this.customData);

            const result = await this.enzoic.addCredentialsAlertSubscription(this.username, this.password, this.customData);
            expect(typeof (result.monitoredCredentialsID)).toBe("string");
            expect(result.monitoredCredentialsID.length).toBe(24);
        });

        let response1;

        it("gets correct result", async () => {
            const result = await this.enzoic.getCredentialsAlertSubscriptions(4, null);
            expect(result.count).toBeGreaterThan(1);
            expect(result.monitoredCredentials.length).toBe(result.count);
            expect(result.pagingToken).not.toBeNull();

            // save off result for next call
            response1 = result;
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com", process.env.PP_ENC_KEY);

            try {
                const result = await bogusServer.getCredentialsAlertSubscriptions(4, null);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });

    describe("#getCredentialsAlertSubscriptionsForUser()", () => {
        beforeEach(async () => {
            this.username = "UNIT_TEST_getCredentialsAlertSubscriptionsForUser@passwordping.com";
            this.password = "unittesttest";
            this.customData = "UNIT_TEST_getCredentialsAlertSubscriptionsForUser";
        });

        it("adds test data", async () => {
            // delete all test data instances
            await this.enzoic.deleteCredentialsAlertSubscriptionByCustomData(this.customData);

            const result = await this.enzoic.addCredentialsAlertSubscription(this.username, this.password, this.customData);
            expect(typeof (result.monitoredCredentialsID)).toBe("string");
            expect(result.monitoredCredentialsID.length).toBe(24);
        });

        it("gets correct result", async () => {
            const result = await this.enzoic.getCredentialsAlertSubscriptionsForUser(this.username);
            expect(result.count).toBe(1);
            expect(result.monitoredCredentials.length).toBe(result.count);
            expect(result.monitoredCredentials[0].usernameHash).toBe(Hashing.sha256(this.username.toLowerCase()));
            expect(result.monitoredCredentials[0].customData).toBe(this.customData);
        });

        it("handles error properly", async () => {
            const bogusServer = new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, "bogus.enzoic.com", process.env.PP_ENC_KEY);

            try {
                const result = await bogusServer.getCredentialsAlertSubscriptionsForUser(this.username);
            }
            catch (err) {
                expect(err).toContain("Unexpected error calling Enzoic API: getaddrinfo ENOTFOUND bogus.enzoic.com");
            }
        });
    });
});

function getEnzoic() {
    return new EnzoicTest(process.env.PP_API_KEY, process.env.PP_API_SECRET, null, process.env.PP_ENC_KEY);
}

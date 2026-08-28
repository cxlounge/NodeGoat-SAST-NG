"use strict";

/**
 * Unit tests for ContributionsHandler.handleContributionsUpdate
 *
 * These tests verify that the Server-Side JavaScript (SSJS) injection
 * vulnerability (CWE-94) has been remediated: user-controlled contribution
 * values are now parsed with parseInt() instead of eval(), so arbitrary
 * code payloads cannot be executed on the server.
 */

var assert = require("assert");

// ---------------------------------------------------------------------------
// Fake MongoDB collection that satisfies both ContributionsDAO and UserDAO
// ---------------------------------------------------------------------------

/**
 * Returns a fake db object whose collection() always returns the same
 * stub collection.  The stub handles:
 *   - update(query, doc, opts, cb)  — used by ContributionsDAO.update()
 *   - findOne(query, cb)            — used by UserDAO.getUserById() and
 *                                     ContributionsDAO.getByUserId()
 */
function makeFakeDb() {
    var fakeCollection = {
        // MongoDB collection.update(selector, doc, opts, cb)
        update: function(selector, doc, opts, cb) {
            // Simulate a successful upsert — no error
            cb(null);
        },
        // MongoDB collection.findOne(query, cb)
        findOne: function(query, cb) {
            // Return a fake user when called by UserDAO.getUserById()
            // and a fake contributions document when called by ContributionsDAO.getByUserId()
            cb(null, {
                _id: 1,
                userName: "testUser",
                firstName: "Test",
                lastName: "User",
                preTax: 5,
                afterTax: 5,
                roth: 5
            });
        }
    };

    return {
        collection: function() {
            return fakeCollection;
        }
    };
}

// ---------------------------------------------------------------------------
// Express mock builder
// ---------------------------------------------------------------------------

/**
 * Build a req/res/next triple that mimics Express objects.
 *
 * @param {object} body     - req.body values supplied by the caller
 * @param {number} [userId] - session user id (defaults to 1)
 */
function makeExpressMocks(body, userId) {
    var rendered = null;
    var nextError = null;

    var req = {
        body: body,
        session: { userId: userId || 1 }
    };

    var res = {
        getRendered: function() { return rendered; },
        render: function(view, data) {
            rendered = { view: view, data: data };
        }
    };

    var next = function(err) {
        nextError = err;
    };

    return {
        req: req,
        res: res,
        next: next,
        getNextError: function() { return nextError; }
    };
}

// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------

var ContributionsHandler = require("../../app/routes/contributions");

function makeHandler() {
    return new ContributionsHandler(makeFakeDb());
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe("ContributionsHandler.handleContributionsUpdate — SSJS injection fix", function() {

    // -----------------------------------------------------------------------
    // Positive cases: legitimate numeric input should work correctly
    // -----------------------------------------------------------------------

    describe("Legitimate numeric input", function() {

        it("should accept valid integer contribution values and render success", function(done) {
            var handler = makeHandler();
            var mocks = makeExpressMocks({ preTax: "10", afterTax: "5", roth: "5" });

            handler.handleContributionsUpdate(mocks.req, mocks.res, mocks.next);

            // ContributionsDAO.update() is async; setImmediate gives it a tick
            setImmediate(function() {
                var rendered = mocks.res.getRendered();
                assert.ok(rendered, "res.render should have been called");
                assert.strictEqual(rendered.view, "contributions",
                    "should render the contributions view");
                assert.ok(rendered.data.updateSuccess,
                    "updateSuccess flag should be set on a valid update");
                done();
            });
        });

        it("should correctly parse plain integer strings", function(done) {
            var handler = makeHandler();
            var mocks = makeExpressMocks({ preTax: "8", afterTax: "7", roth: "5" });

            handler.handleContributionsUpdate(mocks.req, mocks.res, mocks.next);

            setImmediate(function() {
                var rendered = mocks.res.getRendered();
                assert.ok(rendered, "res.render should have been called");
                assert.ok(rendered.data.updateSuccess,
                    "valid inputs within 30 percent limit should succeed");
                done();
            });
        });

        it("should accept zero values for all fields", function(done) {
            var handler = makeHandler();
            var mocks = makeExpressMocks({ preTax: "0", afterTax: "0", roth: "0" });

            handler.handleContributionsUpdate(mocks.req, mocks.res, mocks.next);

            setImmediate(function() {
                var rendered = mocks.res.getRendered();
                assert.ok(rendered, "res.render should have been called");
                assert.ok(rendered.data.updateSuccess,
                    "zero contributions should be a valid update");
                done();
            });
        });

    });

    // -----------------------------------------------------------------------
    // Negative cases: attack payloads must be rejected as NaN by parseInt()
    // and must NOT execute arbitrary code
    // -----------------------------------------------------------------------

    describe("Code injection payloads (CWE-94 regression)", function() {

        /**
         * Assert that a request body with an injection payload is rejected with
         * a validation error ("Invalid contribution percentages") rather than
         * being evaluated as code.
         *
         * With eval() these payloads could execute arbitrary server-side code.
         * With parseInt() they produce NaN and are caught by the isNaN() guard.
         */
        function assertRejectedAsInvalid(body, label, done) {
            var handler = makeHandler();
            var mocks = makeExpressMocks(body);

            handler.handleContributionsUpdate(mocks.req, mocks.res, mocks.next);

            setImmediate(function() {
                var rendered = mocks.res.getRendered();
                assert.ok(rendered,
                    "res.render should have been called for: " + label);
                assert.ok(rendered.data.updateError,
                    "updateError should be set for invalid input: " + label);
                assert.strictEqual(rendered.data.updateError,
                    "Invalid contribution percentages",
                    "should report 'Invalid contribution percentages' for: " + label);
                done();
            });
        }

        it("should reject a JS arithmetic expression in preTax ('1+1')", function(done) {
            // eval('1+1') === 2, but parseInt('1+1') === NaN → rejected
            assertRejectedAsInvalid(
                { preTax: "1+1", afterTax: "5", roth: "5" },
                "arithmetic expression in preTax",
                done
            );
        });

        it("should reject a JS arithmetic expression in afterTax ('2*3')", function(done) {
            assertRejectedAsInvalid(
                { preTax: "5", afterTax: "2*3", roth: "5" },
                "arithmetic expression in afterTax",
                done
            );
        });

        it("should reject a JS expression in roth — the SAST-reported sink (CWE-94, line 34)", function(done) {
            // This targets the exact sink reported: req.body.roth at line 34
            // eval('1+1') === 2 (bypasses 30% cap), parseInt('1+1') === NaN → rejected
            assertRejectedAsInvalid(
                { preTax: "5", afterTax: "5", roth: "1+1" },
                "arithmetic expression in roth (SAST sink)",
                done
            );
        });

        it("should reject a function-call payload in roth", function(done) {
            // eval('process.exit(1)') would crash the server; parseInt() returns NaN
            assertRejectedAsInvalid(
                { preTax: "5", afterTax: "5", roth: "process.exit(1)" },
                "process.exit() call in roth",
                done
            );
        });

        it("should reject a require() call payload in roth", function(done) {
            // eval("require('os').platform()") would execute; parseInt() returns NaN
            assertRejectedAsInvalid(
                { preTax: "5", afterTax: "5", roth: "require('os').platform()" },
                "require() call in roth",
                done
            );
        });

        it("should reject a string concatenation expression in preTax", function(done) {
            assertRejectedAsInvalid(
                { preTax: "'a'+'b'", afterTax: "5", roth: "5" },
                "string concatenation in preTax",
                done
            );
        });

        it("should reject undefined body fields", function(done) {
            // parseInt(undefined) === NaN → rejected gracefully (no crash)
            assertRejectedAsInvalid(
                { preTax: undefined, afterTax: "5", roth: "5" },
                "undefined preTax field",
                done
            );
        });

        it("should reject an empty string", function(done) {
            // parseInt('') === NaN
            assertRejectedAsInvalid(
                { preTax: "", afterTax: "5", roth: "5" },
                "empty string for preTax",
                done
            );
        });

        it("should reject alphabetic input", function(done) {
            // parseInt('abc') === NaN
            assertRejectedAsInvalid(
                { preTax: "abc", afterTax: "5", roth: "5" },
                "alphabetic string for preTax",
                done
            );
        });

        it("should reject a JSON object string", function(done) {
            // eval('{}') was valid in older engines; parseInt('{}') === NaN
            assertRejectedAsInvalid(
                { preTax: "{}", afterTax: "5", roth: "5" },
                "JSON object string for preTax",
                done
            );
        });

    });

    // -----------------------------------------------------------------------
    // Domain validation boundaries
    // -----------------------------------------------------------------------

    describe("Domain validation boundaries", function() {

        it("should reject a negative preTax value", function(done) {
            var handler = makeHandler();
            var mocks = makeExpressMocks({ preTax: "-1", afterTax: "5", roth: "5" });

            handler.handleContributionsUpdate(mocks.req, mocks.res, mocks.next);

            setImmediate(function() {
                var rendered = mocks.res.getRendered();
                assert.ok(rendered.data.updateError,
                    "negative preTax should produce a validation error");
                done();
            });
        });

        it("should reject a negative roth value", function(done) {
            var handler = makeHandler();
            var mocks = makeExpressMocks({ preTax: "5", afterTax: "5", roth: "-1" });

            handler.handleContributionsUpdate(mocks.req, mocks.res, mocks.next);

            setImmediate(function() {
                var rendered = mocks.res.getRendered();
                assert.ok(rendered.data.updateError,
                    "negative roth should produce a validation error");
                done();
            });
        });

        it("should reject total contributions exceeding 30 percent", function(done) {
            var handler = makeHandler();
            var mocks = makeExpressMocks({ preTax: "15", afterTax: "10", roth: "10" });

            handler.handleContributionsUpdate(mocks.req, mocks.res, mocks.next);

            setImmediate(function() {
                var rendered = mocks.res.getRendered();
                assert.ok(rendered.data.updateError,
                    "total > 30% should produce an updateError");
                assert.strictEqual(rendered.data.updateError,
                    "Contribution percentages cannot exceed 30 %");
                done();
            });
        });

        it("should accept contributions that sum to exactly 30 percent", function(done) {
            var handler = makeHandler();
            var mocks = makeExpressMocks({ preTax: "10", afterTax: "10", roth: "10" });

            handler.handleContributionsUpdate(mocks.req, mocks.res, mocks.next);

            setImmediate(function() {
                var rendered = mocks.res.getRendered();
                assert.ok(rendered.data.updateSuccess,
                    "contributions summing to exactly 30% should be accepted");
                done();
            });
        });

    });

});

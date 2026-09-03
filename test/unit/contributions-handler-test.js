"use strict";

/**
 * Unit tests for ContributionsHandler.handleContributionsUpdate
 *
 * These tests verify that:
 *  1. Valid numeric contribution values are accepted and persisted.
 *  2. Server-Side JavaScript Injection payloads (previously exploitable via
 *     eval()) are now rejected as invalid input (parseInt returns NaN for
 *     code payloads, triggering the "Invalid contribution percentages" error).
 *  3. Negative values are rejected.
 *  4. Contributions that exceed 30 % in total are rejected.
 */

var assert = require("assert");

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/**
 * Build a minimal fake ContributionsDAO whose update() method records calls
 * and invokes the callback with the supplied contribution data.
 */
function makeFakeDAO(contributions) {
    return {
        getByUserId: function(userId, cb) {
            cb(null, contributions || { preTax: 5, afterTax: 5, roth: 5 });
        },
        update: function(userId, preTax, afterTax, roth, cb) {
            cb(null, { userId: userId, preTax: preTax, afterTax: afterTax, roth: roth });
        }
    };
}

/**
 * Build a minimal fake db object.  The handler itself never calls db directly
 * — ContributionsDAO does — so we only need the collection stub here so that
 * the DAO constructor does not throw.
 */
function makeFakeDb(dao) {
    return {
        collection: function() {
            return {
                update: function(query, doc, opts, cb) { cb(null); },
                findOne: function(query, cb) { cb(null, null); }
            };
        }
    };
}

/**
 * Build a fake request object with the given body and session.
 */
function makeReq(body, userId) {
    return {
        body: body || {},
        session: { userId: userId || "42" }
    };
}

/**
 * Build a fake response object that records calls to render().
 */
function makeRes() {
    var res = {
        _rendered: null,
        render: function(view, data) {
            res._rendered = { view: view, data: data };
        }
    };
    return res;
}

// ---------------------------------------------------------------------------
// Bootstrap: load ContributionsHandler with its DAO dependency stubbed out.
//
// ContributionsHandler requires "../data/contributions-dao" which in turn
// needs a real MongoDB collection.  We resolve the module path and monkey-
// patch require so the DAO constructor returns our controllable fake.
// ---------------------------------------------------------------------------

var Module = require("module");
var path = require("path");

// Resolve the absolute path that contributions.js would resolve to
var daoModulePath = path.resolve(
    __dirname,
    "../../app/data/contributions-dao"
);

// Keep a reference to the fakeDAO we inject so tests can swap it
var currentFakeDAO = makeFakeDAO();

// Override Module._resolveFilename so require() inside contributions.js
// returns our stub instead of the real DAO module
var originalResolve = Module._resolveFilename;
Module._resolveFilename = function(request, parent, isMain, options) {
    var resolved = originalResolve.call(this, request, parent, isMain, options);
    return resolved;
};

// Inject the stub into the module cache before loading the handler
require.cache[require.resolve("../../app/data/contributions-dao")] = {
    id: require.resolve("../../app/data/contributions-dao"),
    filename: require.resolve("../../app/data/contributions-dao"),
    loaded: true,
    exports: {
        ContributionsDAO: function FakeContributionsDAO(db) {
            return currentFakeDAO;
        }
    }
};

// Stub config/config to avoid pulling in unrelated dependencies
var configModulePath = path.resolve(__dirname, "../../config/config");
if (!require.cache[require.resolve("../../config/config")]) {
    require.cache[require.resolve("../../config/config")] = {
        id: require.resolve("../../config/config"),
        filename: require.resolve("../../config/config"),
        loaded: true,
        exports: { environmentalScripts: [] }
    };
}

// Now load the handler under test
var ContributionsHandler = require("../../app/routes/contributions");

// ---------------------------------------------------------------------------
// Helper: create a handler instance wired to currentFakeDAO
// ---------------------------------------------------------------------------
function makeHandler() {
    // Pass a dummy db — our cache stub ignores it
    return new ContributionsHandler({});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ContributionsHandler — handleContributionsUpdate", function() {

    // -----------------------------------------------------------------------
    // Happy path
    // -----------------------------------------------------------------------

    it("accepts valid integer string inputs and calls DAO.update", function(done) {
        var updateCalled = false;
        currentFakeDAO = {
            getByUserId: function(userId, cb) { cb(null, {}); },
            update: function(userId, preTax, afterTax, roth, cb) {
                updateCalled = true;
                assert.strictEqual(preTax, 5);
                assert.strictEqual(afterTax, 10);
                assert.strictEqual(roth, 3);
                cb(null, { userId: userId, preTax: preTax, afterTax: afterTax, roth: roth });
            }
        };

        var handler = makeHandler();
        var req = makeReq({ preTax: "5", afterTax: "10", roth: "3" });
        var res = makeRes();
        var next = function(err) { throw err; };

        handler.handleContributionsUpdate(req, res, next);

        // DAO.update is called synchronously in our fake
        assert.ok(updateCalled, "DAO.update should have been called");
        assert.ok(res._rendered, "res.render should have been called");
        assert.strictEqual(res._rendered.view, "contributions");
        assert.ok(res._rendered.data.updateSuccess, "should render with updateSuccess flag");
        done();
    });

    it("accepts zero values for all fields", function(done) {
        currentFakeDAO = {
            getByUserId: function(userId, cb) { cb(null, {}); },
            update: function(userId, preTax, afterTax, roth, cb) {
                assert.strictEqual(preTax, 0);
                assert.strictEqual(afterTax, 0);
                assert.strictEqual(roth, 0);
                cb(null, { userId: userId, preTax: 0, afterTax: 0, roth: 0 });
            }
        };

        var handler = makeHandler();
        var req = makeReq({ preTax: "0", afterTax: "0", roth: "0" });
        var res = makeRes();

        handler.handleContributionsUpdate(req, res, function(err) { throw err; });

        assert.ok(res._rendered, "res.render should have been called");
        assert.ok(res._rendered.data.updateSuccess);
        done();
    });

    // -----------------------------------------------------------------------
    // Code injection — the primary security regression tests
    //
    // When eval() was used, payloads like "process.exit(1)" or
    // "require('child_process').execSync('id')" would execute arbitrary code.
    // With parseInt() these strings all yield NaN, so the handler renders an
    // "Invalid contribution percentages" error instead.
    // -----------------------------------------------------------------------

    it("rejects a process.exit() injection payload as invalid input", function(done) {
        var updateCalled = false;
        currentFakeDAO = {
            getByUserId: function(userId, cb) { cb(null, {}); },
            update: function() { updateCalled = true; }
        };

        var handler = makeHandler();
        var req = makeReq({
            preTax: "process.exit(1)",
            afterTax: "10",
            roth: "5"
        });
        var res = makeRes();

        handler.handleContributionsUpdate(req, res, function(err) { throw err; });

        assert.ok(!updateCalled, "DAO.update must NOT be called with an injection payload");
        assert.ok(res._rendered, "res.render should have been called");
        assert.strictEqual(res._rendered.view, "contributions");
        assert.ok(res._rendered.data.updateError, "an error message should be present");
        assert.strictEqual(
            res._rendered.data.updateError,
            "Invalid contribution percentages"
        );
        done();
    });

    it("rejects a require() injection payload as invalid input", function(done) {
        var updateCalled = false;
        currentFakeDAO = {
            getByUserId: function(userId, cb) { cb(null, {}); },
            update: function() { updateCalled = true; }
        };

        var handler = makeHandler();
        var req = makeReq({
            preTax: "require('child_process').execSync('id')",
            afterTax: "5",
            roth: "5"
        });
        var res = makeRes();

        handler.handleContributionsUpdate(req, res, function(err) { throw err; });

        assert.ok(!updateCalled, "DAO.update must NOT be called with a require() payload");
        assert.ok(res._rendered.data.updateError);
        assert.strictEqual(res._rendered.data.updateError, "Invalid contribution percentages");
        done();
    });

    it("rejects an expression injection payload (arithmetic with side-effects) as invalid input", function(done) {
        var updateCalled = false;
        currentFakeDAO = {
            getByUserId: function(userId, cb) { cb(null, {}); },
            update: function() { updateCalled = true; }
        };

        var handler = makeHandler();
        // A value like "5; process.exit(1)" — parseInt stops at the first
        // non-numeric character after the leading digits, so it returns 5 and
        // does NOT execute the rest.  But to guard against purely non-numeric
        // payloads we also test a string that starts with code.
        var req = makeReq({
            preTax: "eval('bad')",
            afterTax: "5",
            roth: "5"
        });
        var res = makeRes();

        handler.handleContributionsUpdate(req, res, function(err) { throw err; });

        assert.ok(!updateCalled, "DAO.update must NOT be called");
        assert.ok(res._rendered.data.updateError);
        done();
    });

    it("rejects a function-call injection payload as invalid input", function(done) {
        var updateCalled = false;
        currentFakeDAO = {
            getByUserId: function(userId, cb) { cb(null, {}); },
            update: function() { updateCalled = true; }
        };

        var handler = makeHandler();
        var req = makeReq({
            preTax: "(function(){return 1})()",
            afterTax: "5",
            roth: "5"
        });
        var res = makeRes();

        handler.handleContributionsUpdate(req, res, function(err) { throw err; });

        assert.ok(!updateCalled, "DAO.update must NOT be called");
        assert.ok(res._rendered.data.updateError);
        assert.strictEqual(res._rendered.data.updateError, "Invalid contribution percentages");
        done();
    });

    // -----------------------------------------------------------------------
    // Input validation edge cases
    // -----------------------------------------------------------------------

    it("rejects negative preTax values", function(done) {
        currentFakeDAO = {
            getByUserId: function(userId, cb) { cb(null, {}); },
            update: function() { assert.fail("DAO.update must not be called"); }
        };

        var handler = makeHandler();
        var req = makeReq({ preTax: "-1", afterTax: "5", roth: "5" });
        var res = makeRes();

        handler.handleContributionsUpdate(req, res, function(err) { throw err; });

        assert.strictEqual(res._rendered.data.updateError, "Invalid contribution percentages");
        done();
    });

    it("rejects negative afterTax values", function(done) {
        currentFakeDAO = {
            getByUserId: function(userId, cb) { cb(null, {}); },
            update: function() { assert.fail("DAO.update must not be called"); }
        };

        var handler = makeHandler();
        var req = makeReq({ preTax: "5", afterTax: "-5", roth: "5" });
        var res = makeRes();

        handler.handleContributionsUpdate(req, res, function(err) { throw err; });

        assert.strictEqual(res._rendered.data.updateError, "Invalid contribution percentages");
        done();
    });

    it("rejects negative roth values", function(done) {
        currentFakeDAO = {
            getByUserId: function(userId, cb) { cb(null, {}); },
            update: function() { assert.fail("DAO.update must not be called"); }
        };

        var handler = makeHandler();
        var req = makeReq({ preTax: "5", afterTax: "5", roth: "-1" });
        var res = makeRes();

        handler.handleContributionsUpdate(req, res, function(err) { throw err; });

        assert.strictEqual(res._rendered.data.updateError, "Invalid contribution percentages");
        done();
    });

    it("rejects total contributions exceeding 30 percent", function(done) {
        var updateCalled = false;
        currentFakeDAO = {
            getByUserId: function(userId, cb) { cb(null, {}); },
            update: function() { updateCalled = true; }
        };

        var handler = makeHandler();
        var req = makeReq({ preTax: "15", afterTax: "10", roth: "10" }); // total = 35
        var res = makeRes();

        handler.handleContributionsUpdate(req, res, function(err) { throw err; });

        assert.ok(!updateCalled, "DAO.update must NOT be called");
        assert.strictEqual(res._rendered.data.updateError, "Contribution percentages cannot exceed 30 %");
        done();
    });

    it("accepts contributions totalling exactly 30 percent", function(done) {
        currentFakeDAO = {
            getByUserId: function(userId, cb) { cb(null, {}); },
            update: function(userId, preTax, afterTax, roth, cb) {
                cb(null, { userId: userId, preTax: preTax, afterTax: afterTax, roth: roth });
            }
        };

        var handler = makeHandler();
        var req = makeReq({ preTax: "10", afterTax: "10", roth: "10" }); // total = 30 exactly
        var res = makeRes();

        handler.handleContributionsUpdate(req, res, function(err) { throw err; });

        assert.ok(!res._rendered.data.updateError, "no error expected at exactly 30%");
        assert.ok(res._rendered.data.updateSuccess);
        done();
    });

    it("rejects empty string inputs", function(done) {
        currentFakeDAO = {
            getByUserId: function(userId, cb) { cb(null, {}); },
            update: function() { assert.fail("DAO.update must not be called"); }
        };

        var handler = makeHandler();
        var req = makeReq({ preTax: "", afterTax: "5", roth: "5" });
        var res = makeRes();

        handler.handleContributionsUpdate(req, res, function(err) { throw err; });

        assert.strictEqual(res._rendered.data.updateError, "Invalid contribution percentages");
        done();
    });

    it("rejects undefined / missing fields", function(done) {
        currentFakeDAO = {
            getByUserId: function(userId, cb) { cb(null, {}); },
            update: function() { assert.fail("DAO.update must not be called"); }
        };

        var handler = makeHandler();
        var req = makeReq({}); // no body fields
        var res = makeRes();

        handler.handleContributionsUpdate(req, res, function(err) { throw err; });

        assert.strictEqual(res._rendered.data.updateError, "Invalid contribution percentages");
        done();
    });

    it("rejects floating-point strings (non-integer)", function(done) {
        // parseInt("3.5") === 3, which is still valid — but a string like
        // "abc3.5" returns NaN and must be rejected.
        currentFakeDAO = {
            getByUserId: function(userId, cb) { cb(null, {}); },
            update: function() { assert.fail("DAO.update must not be called"); }
        };

        var handler = makeHandler();
        var req = makeReq({ preTax: "abc3.5", afterTax: "5", roth: "5" });
        var res = makeRes();

        handler.handleContributionsUpdate(req, res, function(err) { throw err; });

        assert.strictEqual(res._rendered.data.updateError, "Invalid contribution percentages");
        done();
    });

});

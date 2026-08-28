/// <reference types="Cypress" />

describe("/research behaviour", () => {
  "use strict";

  afterEach(() => {
    cy.visitPage("/logout");
  });

  it("Should redirect if the user has not logged in", () => {
    cy.visitPage("/research");
    cy.url().should("include", "login");
  });

  it("Should be accesible for a logged user", () => {
    cy.userSignIn();
    cy.visitPage("/research");
    cy.url().should("include", "research");
  });

  it("Should be a form with an input", () => {
    cy.userSignIn();
    cy.visitPage("/research");
    cy.get("form[role='search']")
      .find("input");
  });

  it("Should have an input text as a valid stock symbol", () => {
    const stockSymbol = "AAPL";
    cy.userSignIn();
    cy.visitPage("/research");
    cy.get(".form-control")
      .clear()
      .type(stockSymbol);

    cy.get("form")
      .should("have.attr", "action", "/research")
      .invoke("attr", "action", "/skip");

    cy.get("button[type='submit']")
      .first()
      .click();

    cy.url().should("include", "https%3A%2F%2Ffinance.yahoo.com%2Fquote%2F&symbol=AAPL");
  });
});

// SSRF remediation security tests — these exercise the server-side allowlist
// validation added to prevent Server-Side Request Forgery (CWE-918).
// All requests are made with cy.request() so they hit the route handler
// directly and can assert on HTTP status codes without browser navigation.
describe("/research SSRF protection", () => {
  "use strict";

  // The route requires an authenticated session; obtain a cookie once per suite.
  before(() => {
    cy.request("POST", "/login", {
      userName: "user1",
      password: "User1_123"
    });
  });

  after(() => {
    cy.visitPage("/logout");
  });

  it("Should reject a request whose url targets an internal loopback address (127.0.0.1)", () => {
    // An attacker might attempt to reach internal services via loopback.
    cy.request({
      url: "/research",
      qs: {
        url: "http://127.0.0.1/",
        symbol: "AAPL"
      },
      failOnStatusCode: false
    }).then((response) => {
      expect(response.status).to.eq(400);
    });
  });

  it("Should reject a request whose url targets an internal loopback address (localhost)", () => {
    cy.request({
      url: "/research",
      qs: {
        url: "http://localhost/",
        symbol: "AAPL"
      },
      failOnStatusCode: false
    }).then((response) => {
      expect(response.status).to.eq(400);
    });
  });

  it("Should reject a request whose url targets a cloud metadata endpoint (169.254.169.254)", () => {
    // AWS/GCP/Azure instance metadata services are a common SSRF target.
    cy.request({
      url: "/research",
      qs: {
        url: "http://169.254.169.254/latest/meta-data/",
        symbol: "AAPL"
      },
      failOnStatusCode: false
    }).then((response) => {
      expect(response.status).to.eq(400);
    });
  });

  it("Should reject a request whose url targets an arbitrary external host", () => {
    // Attackers may attempt to route requests to their own servers to
    // exfiltrate credentials or pivot through the application.
    cy.request({
      url: "/research",
      qs: {
        url: "http://evil.example.com/",
        symbol: "AAPL"
      },
      failOnStatusCode: false
    }).then((response) => {
      expect(response.status).to.eq(400);
    });
  });

  it("Should reject a request with a file:// scheme URL", () => {
    // file:// URLs would allow reading local filesystem resources.
    cy.request({
      url: "/research",
      qs: {
        url: "file:///etc/passwd",
        symbol: "AAPL"
      },
      failOnStatusCode: false
    }).then((response) => {
      expect(response.status).to.eq(400);
    });
  });

  it("Should reject a request with a malformed / non-parseable URL", () => {
    // new URL() will throw for completely invalid input; the handler must return 400.
    cy.request({
      url: "/research",
      qs: {
        url: "not-a-valid-url",
        symbol: "AAPL"
      },
      failOnStatusCode: false
    }).then((response) => {
      expect(response.status).to.eq(400);
    });
  });

  it("Should reject a URL that embeds a forbidden host via URL credentials (SSRF bypass attempt)", () => {
    // e.g. http://finance.yahoo.com@127.0.0.1/ — the real host is 127.0.0.1 but
    // naive string checks might see "finance.yahoo.com" first.
    // new URL() resolves the hostname to "127.0.0.1", so the allowlist correctly rejects it.
    cy.request({
      url: "/research",
      qs: {
        url: "http://finance.yahoo.com@127.0.0.1/",
        symbol: "AAPL"
      },
      failOnStatusCode: false
    }).then((response) => {
      expect(response.status).to.eq(400);
    });
  });

  it("Should reject a URL that uses an allowed hostname as a subdomain of a different host", () => {
    // e.g. http://finance.yahoo.com.evil.com/ — hostname contains the allowed
    // domain as a prefix but is not actually finance.yahoo.com.
    cy.request({
      url: "/research",
      qs: {
        url: "http://finance.yahoo.com.evil.com/",
        symbol: "AAPL"
      },
      failOnStatusCode: false
    }).then((response) => {
      expect(response.status).to.eq(400);
    });
  });

  it("Should allow a request with the permitted host (finance.yahoo.com)", () => {
    // The legitimate use case must still work after the fix. A request to the
    // allowlisted host should not be blocked at the validation layer (it may fail
    // for other reasons such as network unavailability, which is acceptable here).
    cy.request({
      url: "/research",
      qs: {
        url: "https://finance.yahoo.com/quote/",
        symbol: "AAPL"
      },
      failOnStatusCode: false
    }).then((response) => {
      // 400 is specifically the SSRF-protection rejection code; any other status
      // (200, 5xx from upstream, etc.) means the allowlist check was passed.
      expect(response.status).to.not.eq(400);
    });
  });
});

/// <reference types="Cypress" />

describe("/login behaviour", () => {
  "use strict";

  before(() => {
    cy.dbReset();
  });

  afterEach(() => {
    cy.visitPage("/logout");
  });

  beforeEach(() => {
    cy.visitPage("/login");
  });

  it("should have tutorial Guide link", () => {
    cy.get("a[href='/tutorial']")
      .should("have.attr", "target", "_blank")
      .and("be.visible");
  });

  it("Should open the tutorial in another tab", () => {
    cy.get("a[href='/tutorial']").then(function ($a) {
      const href =
      $a.prop("href");
      cy.visit(href);
      cy.url().should("include", "tutorial");
    });
  });

  it("should have admin user able to login", () => {
    cy.fixture("users/admin.json").as("admin");
    cy.get("@admin").then(admin => {
      cy.get("#userName").type(admin.user);
      cy.get("#password").type(admin.pass);
      cy.get("[type='submit']").click();
      cy.url().should("include", "benefits");
    });
  });

  it("should have non-admin user able to login", () => {
    cy.fixture("users/user.json").as("user");
    cy.get("@user").then(user => {
      cy.get("#userName").type(user.user);
      cy.get("#password").type(user.pass);
      cy.get("[type='submit']").click();
      cy.url().should("include", "dashboard");
    });
  });

  it("should reject wrong password", () => {
    cy.fixture("users/user.json").as("user");
    cy.get("@user").then(user => {
      cy.get("#userName").type(user.user);
      cy.get("#password").type("TO BE REJECTED");
      cy.get("[type='submit']").click();

      cy.url().should("include", "login");

      cy.get(".alert-danger")
        .contains("Invalid password")
        .and("be.visible");
    });
  });

  it("should reject wrong username", () => {
    cy.fixture("users/user.json").as("user");
    cy.get("@user").then(user => {
      cy.get("#userName").type("INVENTED");
      cy.get("#password").type(user.pass);
      cy.get("[type='submit']").click();

      cy.url().should("include", "login");

      cy.get(".alert-danger")
        .contains("Invalid username")
        .and("be.visible");
    });
  });

  it("should have new user/ sign up link", () => {
    cy.get("a[href='/signup']")
      .and("be.visible");
  });

  it("Should redirect to the signup", () => {
    cy.get("a[href='/signup']").click();
    cy.url().should("include", "signup");
  });

  // Security regression tests: Reflected XSS via userName (CWE-79)
  // Verifies that user-supplied userName values are HTML-encoded before
  // being reflected back in the login page response (e.g. on invalid login).
  // Swig autoescape must be enabled for these to pass.

  it("should not reflect a script tag XSS payload in the userName field", () => {
    // Attempt to inject a script tag via the userName field.
    // On invalid-user error the server re-renders the login page with userName.
    // If autoescape is off, the raw payload would appear in the HTML source,
    // potentially executing as JavaScript. With autoescape on it must be encoded.
    const xssPayload = "<script>document.title='XSS'</script>";
    cy.get("#userName").type(xssPayload);
    cy.get("#password").type("anypassword");
    cy.get("[type='submit']").click();

    cy.url().should("include", "login");

    // The reflected value in the userName input must be the encoded form,
    // NOT the raw script tag.
    cy.get("#userName").then($input => {
      const reflectedValue = $input.val();
      // The reflected value should equal the literal typed string —
      // the browser decodes HTML entities in attribute values, so the
      // DOM property gives back the original text. What matters is that
      // the browser did NOT execute a script (page title unchanged).
      expect(reflectedValue).to.equal(xssPayload);
    });

    // If the script had executed it would have changed document.title.
    cy.title().should("not.equal", "XSS");
  });

  it("should not reflect an onerror attribute XSS payload in the userName field", () => {
    // Attempt attribute-injection XSS: close the value attribute early then
    // inject an onerror handler.
    const xssPayload = '"><img src=x onerror="document.title=\'XSS\'">';
    cy.get("#userName").type(xssPayload);
    cy.get("#password").type("anypassword");
    cy.get("[type='submit']").click();

    cy.url().should("include", "login");

    // With autoescape enabled, the " and < characters in the payload are
    // HTML-encoded so the injected attribute cannot break out of the
    // value="..." context. The page title must remain unchanged.
    cy.title().should("not.equal", "XSS");
  });

  it("should HTML-encode angle brackets in the userName field on reflection", () => {
    // Verify that < and > are encoded in the reflected response source.
    // Typing a non-existent user name with angle brackets triggers the
    // invalid-user error path that re-renders the login template with userName.
    const payloadUser = "user<b>bold</b>";
    cy.get("#userName").type(payloadUser);
    cy.get("#password").type("anypassword");
    cy.get("[type='submit']").click();

    cy.url().should("include", "login");

    // The raw HTML source of the page must NOT contain the unencoded payload.
    // Cypress's cy.document() lets us inspect the serialised HTML.
    cy.document().then(doc => {
      const html = doc.documentElement.innerHTML;
      // Raw unencoded angle brackets from the payload must not appear
      // inside an attribute value context on the login page.
      expect(html).to.not.include('value="user<b>bold</b>"');
    });
  });
});

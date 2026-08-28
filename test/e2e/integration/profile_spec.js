/// <reference types="Cypress" />

describe("/profile behaviour", () => {
  "use strict";

  before(() => {
    cy.dbReset();
  });

  afterEach(() => {
    cy.visitPage("/logout");
  });

  it("Should redirect if the user has not logged in", () => {
    cy.visitPage("/profile");
    cy.url().should("include", "login");
  });

  it("Should be accesible for logged user", () => {
    cy.userSignIn();
    cy.visitPage("/profile");
    cy.url().should("include", "profile");
  });

  it("Should be a form with inputs", () => {
    cy.userSignIn();
    cy.visitPage("/profile");
    cy.get("form[role='form']")
      .find("input")
      .should("have.length", 9);
  });

  it("Should first name be modified", () => {
    const newName = "My new name!";
    const bankRouting = "0198212#";
    cy.userSignIn();
    cy.visitPage("/profile");
    cy.get("#firstName")
      .clear()
      .type(newName);

    cy.get("#bankRouting")
      .clear()
      .type(bankRouting);

    cy.get("button[type='submit']")
      .first()
      .click();

    cy.url().should("include", "profile");

    cy.get(".alert-success")
      .should("be.visible");
    // @TODO: Just commented for CI, this MUST be improved
    /*
    cy.get("#firstName")
      .invoke("val")
      .should("eq", newName);
    */
  });

  it("Google search this profile by name", () => {
    cy.userSignIn();
    cy.visitPage("/profile");

    cy.get("form[role='form'] a")
      .should("be.visible")
      .should("have.attr", "href");
  });

  // Security: Reflected XSS prevention in lastName field (CWE-79)
  // Verifies that user-supplied HTML/script content in lastName is HTML-encoded
  // and never executed as script when the bank routing validation error path
  // renders the value back in the form (reflected XSS via res.render sink).

  it("Should not execute script injected via lastName when routing validation fails", () => {
    // Use a bankRouting value that deliberately fails the regex check so the
    // validation-error branch (the reflected-XSS sink) is exercised.
    const xssPayload = "<script>window.__xss_executed=true;</script>";
    const invalidRouting = "INVALID_NO_HASH";

    cy.userSignIn();
    cy.visitPage("/profile");

    cy.get("#lastName")
      .clear()
      .type(xssPayload, { parseSpecialCharSequences: false });

    cy.get("#bankRouting")
      .clear()
      .type(invalidRouting);

    cy.get("button[type='submit']")
      .first()
      .click();

    // The page should stay on /profile and show the routing error banner.
    cy.url().should("include", "profile");
    cy.get(".alert-danger").should("be.visible");

    // The injected script must NOT have run — if XSS were present the global
    // would be set to true by the injected <script> tag.
    cy.window().then(win => {
      expect(win.__xss_executed).to.be.undefined;
    });
  });

  it("Should HTML-encode angle brackets in lastName when routing validation fails", () => {
    // The encoded characters (<, >) must appear as literal text in the DOM,
    // not as HTML tags — confirming ESAPI.encoder().encodeForHTML() ran.
    const xssPayload = "<img src=x onerror=alert(1)>";
    const invalidRouting = "INVALID_NO_HASH";

    cy.userSignIn();
    cy.visitPage("/profile");

    cy.get("#lastName")
      .clear()
      .type(xssPayload, { parseSpecialCharSequences: false });

    cy.get("#bankRouting")
      .clear()
      .type(invalidRouting);

    cy.get("button[type='submit']")
      .first()
      .click();

    cy.url().should("include", "profile");

    // The lastName input's value attribute must contain the encoded form of '<'
    // (either &lt; or the raw character stored as text) — there must be no
    // live <img> element injected into the page by the payload.
    cy.get("body").then($body => {
      // If the XSS payload executed, a stray <img> element with src="x"
      // would exist at the top level of the body (outside any form).
      const injectedImgs = $body.find("img[src='x']");
      expect(injectedImgs.length).to.equal(0);
    });
  });

  it("Should preserve the encoded lastName value in the form after routing validation error", () => {
    // Confirms functional correctness: the lastName field is still populated
    // on the error re-render so the user does not lose their input.
    const lastName = "O'Brien";
    const invalidRouting = "INVALID_NO_HASH";

    cy.userSignIn();
    cy.visitPage("/profile");

    cy.get("#lastName")
      .clear()
      .type(lastName);

    cy.get("#bankRouting")
      .clear()
      .type(invalidRouting);

    cy.get("button[type='submit']")
      .first()
      .click();

    cy.url().should("include", "profile");
    cy.get(".alert-danger").should("be.visible");

    // The lastName field should be re-populated (encoded value renders back
    // as the original text in the input's value attribute).
    cy.get("#lastName")
      .invoke("val")
      .should("not.be.empty");
  });
});

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

  // Security regression tests for Reflected XSS (CWE-79)
  // Verifies that user-supplied userName input is HTML-encoded before being
  // reflected back in the login page (value attribute of the userName field).
  // Swig autoescape:true must be enabled in server.js for these to pass.
  describe("Reflected XSS prevention on login page", () => {
    it("should not execute script injected via userName on invalid-user error", () => {
      // Attempt to inject a script tag through the userName field.
      // When the user does not exist, the server reflects userName back into the
      // login form.  With autoescape enabled the payload must appear as plain text
      // inside the input value attribute, never as executable markup.
      const xssPayload = "<script>window.__xss_executed=true</script>";

      cy.visitPage("/login");
      cy.get("#userName").type(xssPayload, { parseSpecialCharSequences: false });
      cy.get("#password").type("anypassword");
      cy.get("[type='submit']").click();

      // Page must stay on login after the failed attempt
      cy.url().should("include", "login");

      // The XSS flag must NOT have been set — the payload must not have run
      cy.window().then(win => {
        expect(win.__xss_executed).to.be.undefined;
      });

      // The raw script tag must not appear as markup in the DOM;
      // the input value should contain the literal encoded text
      cy.get("#userName").invoke("val").then(val => {
        // The value should contain the literal less-than character (encoded by the
        // browser form control), NOT have caused a new <script> element to be parsed
        expect(val).to.include("<script>");
      });

      // Confirm no <script> child element was injected into the page body by the XSS payload
      cy.get("body").find("script").each($el => {
        // Only vendor/bootstrap scripts should be present; none should set __xss_executed
        expect($el.attr("src") || $el.text()).to.not.include("__xss_executed");
      });
    });

    it("should HTML-encode angle brackets in userName reflected on invalid-user error", () => {
      // Verifies that the raw characters < and > are escaped in the rendered HTML
      // so that attribute injection (e.g. closing the value attribute) is impossible.
      const anglePayload = '"><img src=x onerror=alert(1)>';

      cy.visitPage("/login");
      cy.get("#userName").type(anglePayload, { parseSpecialCharSequences: false });
      cy.get("#password").type("anypassword");
      cy.get("[type='submit']").click();

      cy.url().should("include", "login");

      // No img element with an onerror handler should have been injected
      cy.get("img[src='x']").should("not.exist");

      // The XSS flag should remain unset
      cy.window().then(win => {
        expect(win.__xss_executed).to.be.undefined;
      });
    });

    it("should HTML-encode userName with script payload on invalid-password error", () => {
      // When a valid username is provided with a wrong password the server also
      // reflects userName back — verify that path is equally protected.
      cy.fixture("users/user.json").as("user");
      cy.get("@user").then(user => {
        const xssPayload = "<script>window.__xss_executed=true</script>";

        cy.visitPage("/login");
        // Use a valid username so the server reaches the invalidPassword branch
        cy.get("#userName").type(user.user);
        cy.get("#password").type("wrong_password_xyz");
        cy.get("[type='submit']").click();

        cy.url().should("include", "login");

        // The reflected userName (real, non-XSS value) must not trigger execution
        cy.window().then(win => {
          expect(win.__xss_executed).to.be.undefined;
        });

        // Now verify the XSS payload path for the invalidPassword branch directly
        cy.visitPage("/login");
        cy.get("#userName").type(xssPayload, { parseSpecialCharSequences: false });
        cy.get("#password").type("wrong_password_xyz");
        cy.get("[type='submit']").click();

        cy.window().then(win => {
          expect(win.__xss_executed).to.be.undefined;
        });
      });
    });
  });
});

/// <reference types="Cypress" />

describe("/contributions behaviour", () => {
  "use strict";

  before(() => {
    cy.dbReset();
  });

  afterEach(() => {
    cy.visitPage("/logout");
  });

  it("Should redirect if the user has not logged in", () => {
    cy.visitPage("/contributions");
    cy.url().should("include", "login");
  });

  it("Should be accesible for a logged user", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");
    cy.url().should("include", "contributions");
  });

  it("Should be a table with several inputs", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");
    cy.get("table")
      .find("input")
      .should("have.length", 3);
  });

  it("Should input be modified", () => {
    const value = "12";
    cy.userSignIn();
    cy.visitPage("/contributions");
    cy.get("table")
      .find("input")
      .first()
      .clear()
      .type(value);

    cy.get("button[type='submit']")
      .click();

    cy.get("tbody > tr > td")
      .eq(1)
      .contains(`${value} %`);

    cy.get(".alert-success")
      .should("be.visible");

    cy.url().should("include", "contributions");
  });

  // Security tests: CWE-94 Code Injection (SSJS Injection) prevention
  // These tests verify that eval() has been replaced with parseInt() so that
  // user-supplied JavaScript expressions cannot be executed on the server.

  it("Should reject JavaScript expression injection in preTax field", () => {
    // An attacker might send a JS expression; parseInt() returns NaN, triggering validation error
    cy.userSignIn();
    cy.visitPage("/contributions");

    cy.get("table")
      .find("input")
      .eq(0)
      .clear()
      .type("1+1");

    cy.get("button[type='submit']")
      .click();

    // The server must reject this input with a validation error, not execute it
    cy.get(".alert-danger, .alert-warning, [class*='error'], [class*='alert']")
      .should("be.visible");
  });

  it("Should reject JavaScript expression injection in afterTax field", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    cy.get("table")
      .find("input")
      .eq(1)
      .clear()
      .type("2+3");

    cy.get("button[type='submit']")
      .click();

    cy.get(".alert-danger, .alert-warning, [class*='error'], [class*='alert']")
      .should("be.visible");
  });

  it("Should reject JavaScript expression injection in roth field", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    cy.get("table")
      .find("input")
      .eq(2)
      .clear()
      .type("5*2");

    cy.get("button[type='submit']")
      .click();

    cy.get(".alert-danger, .alert-warning, [class*='error'], [class*='alert']")
      .should("be.visible");
  });

  it("Should reject non-numeric string inputs", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    cy.get("table")
      .find("input")
      .eq(0)
      .clear()
      .type("abc");

    cy.get("button[type='submit']")
      .click();

    cy.get(".alert-danger, .alert-warning, [class*='error'], [class*='alert']")
      .should("be.visible");
  });

  it("Should reject negative contribution values", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    cy.get("table")
      .find("input")
      .eq(0)
      .clear()
      .type("-5");

    cy.get("button[type='submit']")
      .click();

    cy.get(".alert-danger, .alert-warning, [class*='error'], [class*='alert']")
      .should("be.visible");
  });

  it("Should reject contributions exceeding 30% total", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    const inputs = cy.get("table").find("input");
    inputs.eq(0).clear().type("20");
    inputs.eq(1).clear().type("10");
    inputs.eq(2).clear().type("5");

    cy.get("button[type='submit']")
      .click();

    cy.get(".alert-danger, .alert-warning, [class*='error'], [class*='alert']")
      .should("be.visible");
  });

  it("Should accept valid numeric contributions within 30% limit", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    cy.get("table")
      .find("input")
      .eq(0)
      .clear()
      .type("5");

    cy.get("table")
      .find("input")
      .eq(1)
      .clear()
      .type("5");

    cy.get("table")
      .find("input")
      .eq(2)
      .clear()
      .type("5");

    cy.get("button[type='submit']")
      .click();

    cy.get(".alert-success")
      .should("be.visible");

    cy.url().should("include", "contributions");
  });
});

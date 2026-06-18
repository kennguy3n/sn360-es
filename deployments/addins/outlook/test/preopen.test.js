/*
 * Outlook pre-open add-in test harness (WS-7b)
 *
 * Exercises preopen.js's presentWarning()/presentationForTier()/t():
 * the tier → plain-language mapping, and the unknown-tier fallback that
 * must render a localized "flagged" line (never a hardcoded English
 * literal, never an empty strip). Mirrors the Gmail pre-open fallback.
 *
 * Uses Node's built-in test runner (node --test) with a hand-crafted
 * Office.js mock — the package's load()/sync() helpers target the
 * Excel/Word document model and don't fit the Outlook event-handler API.
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

function makeMockOffice(opts) {
  opts = opts || {};
  const locale = opts.locale || "en-US";
  const notifications = [];
  return {
    AsyncResultStatus: { Succeeded: "succeeded", Failed: "failed" },
    MailboxEnums: {
      ItemNotificationMessageType: {
        ErrorMessage: "errorMessage",
        InformationalMessage: "informationalMessage",
      },
    },
    actions: { associate: function () {} },
    context: {
      displayLanguage: locale,
      mailbox: {
        item: {
          notificationMessages: {
            replaceAsync: function (id, msg, cb) {
              notifications.push({ id: id, msg: msg });
              if (cb) cb({ status: "succeeded", value: undefined });
            },
          },
        },
      },
    },
    _notifications: notifications,
  };
}

function loadPreopen(office) {
  global.Office = office;
  const modulePath = require.resolve(path.resolve(__dirname, "../src/preopen.js"));
  delete require.cache[modulePath];
  return require("../src/preopen.js");
}

// === Tier mapping =======================================================

test("presentationForTier maps the SN360 vocabulary to the shared ramp", function () {
  const preopen = loadPreopen(makeMockOffice());
  assert.equal(preopen.presentationForTier("blocked").dangerous, true);
  assert.equal(preopen.presentationForTier("high").dangerous, true);
  assert.equal(preopen.presentationForTier("warning").dangerous, false);
  assert.equal(preopen.presentationForTier("caution").dangerous, false);
  // Anything outside the vocabulary is unknown → null (caller falls back).
  assert.equal(preopen.presentationForTier("totally-unknown"), null);
  assert.equal(preopen.presentationForTier(""), null);
});

// === Localized fallback =================================================

test("t('open_generic_flagged') resolves to the localized line, never empty", function () {
  let preopen = loadPreopen(makeMockOffice({ locale: "en-US" }));
  assert.equal(
    preopen.t("open_generic_flagged"),
    "This message was flagged — open it with care."
  );
  // German locale returns its own translation.
  preopen = loadPreopen(makeMockOffice({ locale: "de-DE" }));
  assert.match(preopen.t("open_generic_flagged"), /Diese Nachricht wurde markiert/);
  // Unknown locale falls back to English (never empty).
  preopen = loadPreopen(makeMockOffice({ locale: "zz-ZZ" }));
  assert.equal(
    preopen.t("open_generic_flagged"),
    "This message was flagged — open it with care."
  );
});

test("presentWarning: unknown tier + empty server message uses the localized fallback", function () {
  const office = makeMockOffice({ locale: "en-US" });
  const preopen = loadPreopen(office);

  let done = false;
  preopen.presentWarning(
    { completed: function () { done = true; } },
    { show_warning: true, message: "" },
    "totally-unknown-tier"
  );

  assert.equal(done, true, "event must always be completed");
  assert.equal(office._notifications.length, 1, "a notification strip must be shown");
  const strip = office._notifications[0].msg.message;
  assert.notEqual(
    strip.indexOf("This message was flagged"),
    -1,
    "unknown tier must surface the localized flagged line, not an empty/English-only literal"
  );
  // Unknown tier is treated as dangerous → ErrorMessage (no icon/persistent).
  assert.equal(office._notifications[0].msg.type, "errorMessage");
});

test("presentWarning: unknown tier respects the active locale", function () {
  const office = makeMockOffice({ locale: "de-DE" });
  const preopen = loadPreopen(office);

  preopen.presentWarning(
    { completed: function () {} },
    { show_warning: true, message: "" },
    "totally-unknown-tier"
  );

  const strip = office._notifications[0].msg.message;
  assert.match(strip, /Diese Nachricht wurde markiert/);
});

test("presentWarning: a server message still wins over the generic fallback", function () {
  const office = makeMockOffice({ locale: "en-US" });
  const preopen = loadPreopen(office);

  preopen.presentWarning(
    { completed: function () {} },
    { show_warning: true, message: "Quarantined by your admin." },
    "totally-unknown-tier"
  );

  const strip = office._notifications[0].msg.message;
  assert.notEqual(strip.indexOf("Quarantined by your admin."), -1);
  assert.equal(
    strip.indexOf("This message was flagged"),
    -1,
    "server-supplied message must take precedence over the generic fallback"
  );
});

test("presentWarning: a known tier uses the tier copy, not the fallback", function () {
  const office = makeMockOffice({ locale: "en-US" });
  const preopen = loadPreopen(office);

  preopen.presentWarning(
    { completed: function () {} },
    { show_warning: true, message: "" },
    "blocked"
  );

  const strip = office._notifications[0].msg.message;
  assert.equal(
    strip.indexOf("This message was flagged"),
    -1,
    "a recognised tier must not fall back to the generic flagged line"
  );
  assert.notEqual(strip.indexOf("ShieldNet 360"), -1, "the brand must lead the strip");
});

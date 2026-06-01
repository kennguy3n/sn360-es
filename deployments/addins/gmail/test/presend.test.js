/*
 * Gmail Apps Script pre-send trigger test harness (WS-7b)
 *
 * Apps Script's runtime isn't available in Node, so we exercise the
 * pure JS in presend.gs by loading the source file via `vm.runInContext`
 * with hand-stubbed globals (Session, Utilities, UrlFetchApp, GmailApp,
 * Gmail, CardService, CacheService). The .gs file is plain JavaScript
 * — Apps Script's V8 runtime accepts the same surface — so once the
 * globals are stubbed the script's pure functions are testable in
 * isolation.
 *
 * The spec also mentions `clasp` + a real Apps Script runtime as one
 * option; running a real runtime in CI requires a Google service
 * account, billable quota, and network egress to script.googleapis.com,
 * so per the spec's "or fall back to a Node harness that mocks GmailApp
 * / CardService" clause we use this Node harness — the same approach
 * used by Google's own quickstart samples that need offline tests.
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");

// === Stubs ==============================================================

function makeStubs(opts) {
  opts = opts || {};
  const sender = opts.sender || "alice@acme.com";
  const locale = opts.locale || "en-US";
  const cache = Object.assign({}, opts.initialCache || {});
  const fetchResponses = opts.fetchResponses || [];
  const threadResponse = opts.thread || null;
  const fetchCalls = [];

  const Session = {
    getActiveUser: function () {
      return {
        getEmail: function () {
          return sender;
        },
      };
    },
    getActiveUserLocale: function () {
      return locale;
    },
  };

  const Utilities = {
    DigestAlgorithm: { SHA_256: "SHA_256" },
    Charset: { UTF_8: "UTF_8" },
    computeDigest: function (algo, value, charset) {
      // SHA-256 of UTF-8 bytes returned as a signed-byte array, matching
      // Apps Script's Utilities.computeDigest contract.
      const buf = Buffer.from(String(value), "utf8");
      const digest = crypto.createHash("sha256").update(buf).digest();
      const out = new Array(digest.length);
      for (let i = 0; i < digest.length; i++) {
        // Apps Script returns signed bytes (-128..127). We don't actually
        // need signed values here because the script's sha256Hex_ helper
        // masks with 0xff before formatting; we keep the unsigned values
        // and the masking pass turns them into the right hex.
        out[i] = digest[i];
      }
      return out;
    },
  };

  const UrlFetchApp = {
    fetch: function (url, params) {
      let body = null;
      try {
        body = params && params.payload ? JSON.parse(params.payload) : null;
      } catch (_) {
        body = null;
      }
      fetchCalls.push({ url: url, body: body, params: params });
      const next = fetchResponses.shift();
      if (!next) {
        // Default: success with empty warnings.
        return {
          getResponseCode: function () {
            return 200;
          },
          getContentText: function () {
            return JSON.stringify({ overall_level: 0, warnings: [] });
          },
        };
      }
      if (next === "throw") throw new Error("simulated network error");
      return {
        getResponseCode: function () {
          return next.status || 200;
        },
        getContentText: function () {
          return JSON.stringify(next.json || { overall_level: 0, warnings: [] });
        },
      };
    },
  };

  const GmailApp = {
    setCurrentMessageAccessToken: function () {
      /* no-op */
    },
  };

  const Gmail = {
    Users: {
      Threads: {
        get: function () {
          return threadResponse || { messages: [] };
        },
      },
    },
  };

  const CardService = makeCardServiceStub();

  const CacheService = {
    getUserCache: function () {
      return {
        get: function (key) {
          return Object.prototype.hasOwnProperty.call(cache, key) ? cache[key] : null;
        },
        put: function (key, value /* , ttl */) {
          cache[key] = value;
        },
        remove: function (key) {
          delete cache[key];
        },
      };
    },
  };

  return {
    globals: {
      Session: Session,
      Utilities: Utilities,
      UrlFetchApp: UrlFetchApp,
      GmailApp: GmailApp,
      Gmail: Gmail,
      CardService: CardService,
      CacheService: CacheService,
    },
    state: {
      cache: cache,
      fetchCalls: fetchCalls,
    },
  };
}

// CardService stub: minimal builder API that records widget structure
// for assertions.
function makeCardServiceStub() {
  function builder(type, props) {
    const node = { _type: type, _props: Object.assign({}, props || {}), _children: [] };
    function chain(method, propKey) {
      node[method] = function (v) {
        node._props[propKey || method] = v;
        return node;
      };
    }
    return node;
  }
  function buildableSection() {
    const s = builder("section");
    s.addWidget = function (w) {
      s._children.push(w);
      return s;
    };
    return s;
  }
  function buildableCard() {
    const c = builder("card");
    c.setHeader = function (h) {
      c._props.header = h;
      return c;
    };
    c.addSection = function (sec) {
      c._children.push(sec);
      return c;
    };
    c.build = function () {
      return c;
    };
    return c;
  }
  function textParagraph() {
    const w = builder("textParagraph");
    w.setText = function (t) {
      w._props.text = t;
      return w;
    };
    return w;
  }
  function cardHeader() {
    const h = builder("cardHeader");
    h.setTitle = function (t) {
      h._props.title = t;
      return h;
    };
    return h;
  }
  function action() {
    const a = builder("action");
    a.setFunctionName = function (n) {
      a._props.functionName = n;
      return a;
    };
    return a;
  }
  function textButton() {
    const b = builder("textButton");
    b.setText = function (t) {
      b._props.text = t;
      return b;
    };
    b.setOnClickAction = function (act) {
      b._props.onClickAction = act;
      return b;
    };
    return b;
  }
  function notification() {
    const n = builder("notification");
    n.setText = function (t) {
      n._props.text = t;
      return n;
    };
    return n;
  }
  function actionResponseBuilder() {
    const r = builder("actionResponse");
    r.setNotification = function (n) {
      r._props.notification = n;
      return r;
    };
    r.build = function () {
      return r;
    };
    return r;
  }
  return {
    newCardBuilder: buildableCard,
    newCardSection: buildableSection,
    newCardHeader: cardHeader,
    newTextParagraph: textParagraph,
    newTextButton: textButton,
    newAction: action,
    newNotification: notification,
    newActionResponseBuilder: actionResponseBuilder,
  };
}

// === Loader ============================================================

function loadPresend(globals) {
  const source = fs.readFileSync(
    path.resolve(__dirname, "../src/presend.gs"),
    "utf8"
  );
  const sandbox = Object.assign({ module: { exports: {} } }, globals);
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox);
  return sandbox.module.exports;
}

// === Pure helpers ======================================================

test("damerauLevenshtein_ matches the canonical OSA distance", function () {
  const presend = loadPresend(makeStubs().globals);
  assert.equal(presend.damerauLevenshtein_("hello", "hello"), 0);
  assert.equal(presend.damerauLevenshtein_("hello", ""), 5);
  assert.equal(presend.damerauLevenshtein_("acme.com", "acm3.com"), 1);
  assert.equal(presend.damerauLevenshtein_("gmail.com", "gmial.com"), 1);
  assert.equal(presend.damerauLevenshtein_("gmail.com", "gmaill.com"), 1);
  assert.equal(presend.damerauLevenshtein_("gmail.com", "gmal.com"), 1);
  assert.equal(presend.damerauLevenshtein_("acme.com", "axxx.com"), 3);
});

test("findLookalike_ returns the closest match within threshold", function () {
  const presend = loadPresend(makeStubs().globals);
  assert.equal(presend.findLookalike_("acme.com", ["acme.com"]), null);
  assert.equal(presend.findLookalike_("acm3.com", ["acme.com"]), "acme.com");
  assert.equal(presend.findLookalike_("gmial.com", ["gmail.com"]), "gmail.com");
  assert.equal(presend.findLookalike_("evil.example.org", ["acme.com"]), null);
});

test("allInternal_ reflects every-domain-matches-sender", function () {
  const presend = loadPresend(makeStubs().globals);
  assert.equal(presend.allInternal_([], "acme.com"), false);
  assert.equal(presend.allInternal_(["acme.com"], "acme.com"), true);
  assert.equal(presend.allInternal_(["acme.com", "x.com"], "acme.com"), false);
  assert.equal(presend.allInternal_(["acme.com"], ""), false);
});

test("parseAddresses_ handles display names, angle brackets, and bare addrs", function () {
  const presend = loadPresend(makeStubs().globals);
  const a = presend.parseAddresses_('"Bob" <bob@acme.com>, carol@partner.com');
  assert.equal(a.length, 2);
  assert.equal(a[0], "bob@acme.com");
  assert.equal(a[1], "carol@partner.com");
  const b = presend.parseAddresses_("Alice <alice@acme.com>");
  assert.equal(b.length, 1);
  assert.equal(b[0], "alice@acme.com");
  assert.equal(presend.parseAddresses_("").length, 0);
  assert.equal(presend.parseAddresses_("no-at-sign").length, 0);
  // Quoted commas inside display names must NOT split the list.
  const c = presend.parseAddresses_('"Doe, John" <john@x.com>, jane@y.com');
  assert.equal(c.length, 2);
  assert.equal(c[0], "john@x.com");
  assert.equal(c[1], "jane@y.com");
});

test("domainOf_ tolerates display-name wrappers and bare emails", function () {
  const presend = loadPresend(makeStubs().globals);
  assert.equal(presend.domainOf_("alice@acme.com"), "acme.com");
  assert.equal(presend.domainOf_("Alice <alice@acme.com>"), "acme.com");
  assert.equal(presend.domainOf_(""), "");
  assert.equal(presend.domainOf_("nope"), "");
});

test("sha256Hex_ produces canonical lowercase hex", function () {
  const presend = loadPresend(makeStubs().globals);
  const got = presend.sha256Hex_("hello");
  assert.equal(
    got,
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
  );
});

test("combineWarnings_ unions warnings and takes max level", function () {
  const presend = loadPresend(makeStubs().globals);
  const out = presend.combineWarnings_(
    { overall_level: 2, warnings: [{ level: 2, code: "a", message: "a" }] },
    [{ level: 4, code: "b", message: "b" }]
  );
  assert.equal(out.overall_level, 4);
  assert.equal(out.warnings.length, 2);
});

test("localizedMessage_ falls back to English for unknown locales", function () {
  const presend = loadPresend(makeStubs().globals);
  assert.match(
    presend.localizedMessage_("lookalike_recipient", "fr-FR", {
      domain: "acm3.com",
      ref: "acme.com",
    }),
    /acm3\.com.*acme\.com/
  );
});

// === Full flow: pre-send trigger ======================================

function composeEvent(opts) {
  opts = opts || {};
  const draft = {
    toRecipients: opts.to || [],
    ccRecipients: opts.cc || [],
    bccRecipients: opts.bcc || [],
  };
  const evt = {
    draftMetadata: draft,
    commonEventObject: { userLocale: opts.locale || "en-US" },
  };
  if (opts.threadId) {
    evt.gmail = {
      threadId: opts.threadId,
      accessToken: opts.accessToken || "tok",
    };
  }
  return evt;
}

test("Flow 1: empty recipient list returns no card", function () {
  const stubs = makeStubs();
  const presend = loadPresend(stubs.globals);
  const out = presend.sn360PreSendTrigger(composeEvent({}));
  assert.equal(out.length, 0);
});

test("Flow 1: low-risk API response returns no card", function () {
  const stubs = makeStubs({
    fetchResponses: [{ status: 200, json: { overall_level: 0, warnings: [] } }],
  });
  const presend = loadPresend(stubs.globals);
  const out = presend.sn360PreSendTrigger(
    composeEvent({ to: ["bob@partner.com"] })
  );
  assert.equal(out.length, 0);
});

test("Flow 1: high-risk API response returns a warning card", function () {
  const stubs = makeStubs({
    fetchResponses: [
      {
        status: 200,
        json: {
          overall_level: 4,
          warnings: [
            {
              user_hash: "h1",
              level: 4,
              code: "lookalike_recipient",
              message: "Recipient domain partner.com looks similar to partner.io.",
            },
          ],
        },
      },
    ],
  });
  const presend = loadPresend(stubs.globals);
  const out = presend.sn360PreSendTrigger(
    composeEvent({ to: ["bob@partner.com"] })
  );
  assert.equal(out.length, 1);
  assert.equal(out[0]._type, "card");
});

test("Flow 1: Bcc recipients are included in the API call", function () {
  const stubs = makeStubs({
    fetchResponses: [{ status: 200, json: { overall_level: 0, warnings: [] } }],
  });
  const presend = loadPresend(stubs.globals);
  presend.sn360PreSendTrigger(
    composeEvent({ bcc: ["dave@evil.example.org"] })
  );
  assert.equal(stubs.state.fetchCalls.length, 1);
  assert.equal(stubs.state.fetchCalls[0].body.recipients.length, 1);
  assert.equal(
    stubs.state.fetchCalls[0].body.recipients[0].domain,
    "evil.example.org"
  );
});

test("Flow 1: API network error fails open (no card)", function () {
  const stubs = makeStubs({ fetchResponses: ["throw"] });
  const presend = loadPresend(stubs.globals);
  const out = presend.sn360PreSendTrigger(
    composeEvent({ to: ["bob@partner.com"] })
  );
  assert.equal(out.length, 0);
});

// === Flow 2: client-side lookalike ====================================

test("Flow 2: client-side lookalike fires against the seeded known-domain set", function () {
  // Pre-seed the known-domain cache with acme.com (and the sender's
  // own domain is auto-seeded). The recipient acm3.com is a distance-1
  // lookalike of acme.com.
  const stubs = makeStubs({
    fetchResponses: [{ status: 200, json: { overall_level: 0, warnings: [] } }],
  });
  const presend = loadPresend(stubs.globals);
  const out = presend.sn360PreSendTrigger(
    composeEvent({ to: ["bob@acm3.com"] })
  );
  assert.equal(out.length, 1, "client-side lookalike must produce a card");
});

test("Flow 2: exact-match domain does NOT trigger lookalike", function () {
  const stubs = makeStubs({
    fetchResponses: [{ status: 200, json: { overall_level: 0, warnings: [] } }],
  });
  const presend = loadPresend(stubs.globals);
  const out = presend.sn360PreSendTrigger(
    composeEvent({ to: ["bob@acme.com"] })
  );
  assert.equal(out.length, 0);
});

// === Flow 3: external-thread-going-external ============================

test("Flow 3: warns when an internal-only thread gains an external recipient", function () {
  // Thread has previous messages all from @acme.com — internal only.
  // Current draft has a new external recipient.
  const thread = {
    messages: [
      {
        payload: {
          headers: [
            { name: "From", value: "alice@acme.com" },
            { name: "To", value: "bob@acme.com" },
            { name: "Cc", value: "" },
          ],
        },
      },
    ],
  };
  const stubs = makeStubs({
    thread: thread,
    fetchResponses: [{ status: 200, json: { overall_level: 0, warnings: [] } }],
  });
  const presend = loadPresend(stubs.globals);
  const out = presend.sn360PreSendTrigger(
    composeEvent({
      to: ["bob@acme.com", "carol@partner.com"],
      threadId: "t1",
    })
  );
  assert.equal(out.length, 1, "external-on-internal-thread must produce a card");
  // The request should reflect thread_is_internal: true.
  assert.equal(stubs.state.fetchCalls.length, 1);
  assert.equal(stubs.state.fetchCalls[0].body.thread_is_internal, true);
});

test("Flow 3: thread with existing external participants does NOT warn", function () {
  const thread = {
    messages: [
      {
        payload: {
          headers: [
            { name: "From", value: "vendor@partner.com" },
            { name: "To", value: "alice@acme.com" },
          ],
        },
      },
    ],
  };
  const stubs = makeStubs({
    thread: thread,
    fetchResponses: [{ status: 200, json: { overall_level: 0, warnings: [] } }],
  });
  const presend = loadPresend(stubs.globals);
  presend.sn360PreSendTrigger(
    composeEvent({
      to: ["alice@acme.com", "vendor@partner.com"],
      threadId: "t1",
    })
  );
  // thread_is_internal should be false because the baseline already
  // contains partner.com.
  assert.equal(stubs.state.fetchCalls[0].body.thread_is_internal, false);
});

// === Caching ==========================================================

test("predict cache: identical request body ⇒ one fetch across two trigger invocations", function () {
  const stubs = makeStubs({
    fetchResponses: [
      { status: 200, json: { overall_level: 0, warnings: [] } },
      { status: 200, json: { overall_level: 0, warnings: [] } },
    ],
  });
  const presend = loadPresend(stubs.globals);
  const evt = composeEvent({ to: ["bob@partner.com"] });
  presend.sn360PreSendTrigger(evt);
  presend.sn360PreSendTrigger(evt);
  assert.equal(stubs.state.fetchCalls.length, 1, "second invocation must hit the cache");
});

// === Privacy =========================================================

test("privacy: raw email addresses never appear in the predict request body", function () {
  const stubs = makeStubs({
    fetchResponses: [{ status: 200, json: { overall_level: 0, warnings: [] } }],
  });
  const presend = loadPresend(stubs.globals);
  presend.sn360PreSendTrigger(
    composeEvent({
      to: ["bob@partner.com"],
      bcc: ["dave@evil.example.org"],
    })
  );
  const sent = JSON.stringify(stubs.state.fetchCalls[0].body);
  assert.equal(sent.indexOf("alice@acme.com"), -1, "sender email leaked");
  assert.equal(sent.indexOf("bob@partner.com"), -1, "to recipient leaked");
  assert.equal(sent.indexOf("dave@evil.example.org"), -1, "bcc recipient leaked");
  // Domains ARE sent (not PII).
  assert.notEqual(sent.indexOf("partner.com"), -1);
  assert.notEqual(sent.indexOf("evil.example.org"), -1);
});

// === Card rendering ==================================================

test("buildSendWarningCard_ renders one paragraph per warning and an acknowledge button", function () {
  const stubs = makeStubs();
  const presend = loadPresend(stubs.globals);
  const card = presend.buildSendWarningCard_(
    {
      overall_level: 4,
      warnings: [
        { code: "lookalike_recipient", message: "X", suggestion: "Y" },
        { code: "external_on_internal_thread", message: "Z" },
      ],
    },
    "en"
  );
  assert.equal(card._type, "card");
  const sec = card._children[0];
  assert.equal(sec._type, "section");
  // 2 warnings × (paragraph + optional did-you-mean paragraph for the
  // one with a suggestion) + 1 acknowledge button = 4 widgets.
  assert.equal(sec._children.length, 4);
  const button = sec._children[sec._children.length - 1];
  assert.equal(button._type, "textButton");
  assert.equal(button._props.onClickAction._props.functionName, "sn360AcknowledgeWarning");
});

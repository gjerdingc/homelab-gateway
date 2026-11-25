// Path rule builder on the app form: one row per rule with dropdowns, kept in sync with the
// path_rules text box, which is still what the form posts (and what you paste into in text mode).
// The words are the ones validate.parse_path_rules reads; the server checks everything again.
(function () {
  var root = document.querySelector("[data-rule-builder]");
  if (!root) return;
  var textarea = document.getElementById("path_rules");
  var rowsBox = root.querySelector("[data-rule-rows]");
  var emptyNote = root.querySelector("[data-rule-empty]");
  var builder = root.querySelector("[data-rule-ui]");
  var textBox = root.querySelector("[data-rule-text]");
  var toggle = root.querySelector("[data-rule-toggle]");
  var parseNote = root.querySelector("[data-rule-parse-error]");
  var lists = JSON.parse(root.dataset.lists || "[]");

  var ACCESS = [
    ["open", "Open: no sign-in"],
    ["optional", "Open, and pass on who is signed in"],
    ["sign-in", "Sign in with Google"],
    ["sign-in=401", "Must be signed in, else 401 (APIs)"],
    ["redirect", "Must be signed in, else send to a page"],
    ["deny", "Block (403)"]
  ];
  var EXAMPLES = [
    ["Public pages anyone can open", function () { return [rule(["/public"], [], "open")]; }],
    ["Admin pages only from an IP list, with sign-in", function () {
      var from = lists.length ? [lists[0].value] : [];
      return [rule(["/admin"], from, "sign-in"), rule(["/admin"], [], "deny")];
    }],
    ["API answers 401 instead of the sign-in page", function () { return [rule(["/api/"], [], "sign-in=401")]; }],
    ["Block a path for everyone", function () { return [rule(["/admin"], [], "deny")]; }],
    ["Everything read-only, sign-in optional", function () { return [rule(["/"], [], "optional", false, true)]; }]
  ];

  function rule(paths, from, access, target, readOnly) {
    return { paths: paths, from: from, access: access, target: target || "", readOnly: !!readOnly };
  }

  // ---- text <-> rules -------------------------------------------------------

  // Returns {rules} or {error}. Only checks what the builder needs; the server reports the rest.
  function parse(text) {
    var rules = [];
    var lines = (text || "").split("\n");
    for (var n = 0; n < lines.length; n++) {
      var line = lines[n].trim();
      if (!line) continue;
      if (line.charAt(0) === "#") return { error: "Line " + (n + 1) + " is a comment, which the builder would drop." };
      var r = rule([], [], null), words = line.split(/\s+/);
      for (var i = 0; i < words.length; i++) {
        var w = words[i], low = w.toLowerCase();
        if (w.charAt(0) === "/") { if (r.paths.indexOf(w) === -1) r.paths.push(w); }
        else if (low.indexOf("from=") === 0) low.slice(5).split(",").forEach(function (x) { if (x && r.from.indexOf(x) === -1) r.from.push(x); });
        else if (low === "read-only") r.readOnly = true;
        else if (!r.access && (low === "open" || low === "optional" || low === "deny" || low === "sign-in" || low === "sign-in=401")) r.access = low;
        else if (!r.access && low.indexOf("sign-in=/") === 0) { r.access = "redirect"; r.target = w.slice(8); }
        else return { error: "Line " + (n + 1) + ": " + JSON.stringify(w) + " is not understood." };
      }
      if (!r.paths.length || !r.access) return { error: "Line " + (n + 1) + " needs both paths and what to do." };
      rules.push(r);
    }
    return { rules: rules };
  }

  function format(r) {
    var words = r.paths.slice();
    if (r.from.length) words.push("from=" + r.from.join(","));
    words.push(r.access === "redirect" ? "sign-in=" + (r.target || "/") : r.access);
    if (r.readOnly) words.push("read-only");
    return words.join(" ");
  }

  // ---- plain-language summary -----------------------------------------------

  function describePath(p) {
    if (p === "/") return "any page";
    if (p.charAt(p.length - 1) === "/") return "anything under " + p;
    return p + " and everything under it";
  }
  function joinOr(items) {
    if (items.length < 2) return items.join("");
    return items.slice(0, -1).join(", ") + " or " + items[items.length - 1];
  }
  function describe(r) {
    if (!r.paths.length) return "Type at least one path, e.g. /admin.";
    var who = r.from.length ? "Clients in " + joinOr(r.from) : "Everyone";
    var what = {
      "open": "get in without signing in",
      "optional": "get in without signing in; if they are signed in, the app is told who they are",
      "sign-in": "must sign in with Google first",
      "sign-in=401": "must already be signed in; others get a 401 error (for APIs and scripts)",
      "redirect": "must be signed in; others are sent to " + (r.target || "/"),
      "deny": "are blocked (403)"
    }[r.access];
    var s = who + " opening " + joinOr(r.paths.map(describePath)) + " " + what + ".";
    if (r.readOnly && r.access !== "deny") s += " They can only read (GET and HEAD); saving or changing anything is refused.";
    if (r.from.length) s += " Other clients go on to the next rule.";
    return s;
  }

  // ---- the rows ---------------------------------------------------------------

  var rules = [];

  function el(tag, attrs, children) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") e.textContent = attrs[k];
      else if (k === "className") e.className = attrs[k];
      else e.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { if (c) e.append(c); });
    return e;
  }

  function sync() {
    textarea.value = rules.map(format).join("\n");
  }

  function render(focusIndex) {
    rowsBox.textContent = "";
    emptyNote.hidden = rules.length > 0;
    rules.forEach(function (r, i) { rowsBox.append(row(r, i)); });
    sync();
    if (focusIndex != null) {
      var input = rowsBox.querySelectorAll("[data-paths]")[focusIndex];
      if (input) input.focus();
    }
  }

  function row(r, i) {
    var id = "rule-" + i;
    var summary = el("p", { className: "rule-summary", text: describe(r) });
    function changed() { summary.textContent = describe(r); sync(); }

    var paths = el("input", { type: "text", id: id + "-paths", className: "mono", "data-paths": "",
                              autocapitalize: "none", spellcheck: "false", autocomplete: "off", placeholder: "/admin /api/admin/" });
    paths.value = r.paths.join(" ");
    paths.addEventListener("input", function () {
      r.paths = paths.value.split(/[\s,]+/).filter(Boolean).map(function (p) { return p.charAt(0) === "/" ? p : "/" + p; });
      changed();
    });

    var access = el("select", { id: id + "-access" });
    ACCESS.forEach(function (a) { access.append(el("option", { value: a[0], text: a[1] })); });
    access.value = r.access;
    var target = el("input", { type: "text", className: "mono", "aria-label": "Page to send visitors to",
                               autocapitalize: "none", spellcheck: "false", autocomplete: "off", placeholder: "/games" });
    target.value = r.target;
    var targetWrap = el("label", { className: "rule-target" }, [document.createTextNode("Send to "), target]);
    targetWrap.hidden = r.access !== "redirect";
    access.addEventListener("change", function () {
      r.access = access.value;
      targetWrap.hidden = r.access !== "redirect";
      if (r.access === "redirect" && !r.target) { r.target = "/"; target.value = "/"; target.focus(); }
      changed();
    });
    target.addEventListener("input", function () { r.target = target.value.trim(); changed(); });

    var who = el("div", { className: "rule-who" });
    var known = lists.map(function (l) { return l.value; });
    var names = known.concat(r.from.filter(function (f) { return known.indexOf(f) === -1; }));
    if (!names.length) who.append(el("span", { className: "help", text: "Everyone (make IP lists to limit a rule to some clients)" }));
    names.forEach(function (name) {
      var box = el("input", { type: "checkbox", value: name });
      box.checked = r.from.indexOf(name) !== -1;
      box.addEventListener("change", function () {
        r.from = names.filter(function (n) { return who.querySelector('input[value="' + n + '"]').checked; });
        changed();
      });
      var label = el("label", {}, [box, el("span", { className: "mono", text: name })]);
      if (known.indexOf(name) === -1) label.append(el("span", { className: "badge badge-err", text: "missing" }));
      who.append(label);
    });

    var ro = el("input", { type: "checkbox" });
    ro.checked = r.readOnly;
    ro.addEventListener("change", function () { r.readOnly = ro.checked; changed(); });

    function move(delta) { var j = i + delta; rules.splice(j, 0, rules.splice(i, 1)[0]); render(); }
    var up = el("button", { type: "button", className: "btn btn-small", text: "↑", "aria-label": "Move rule " + (i + 1) + " up", title: "Move up" });
    var down = el("button", { type: "button", className: "btn btn-small", text: "↓", "aria-label": "Move rule " + (i + 1) + " down", title: "Move down" });
    var del = el("button", { type: "button", className: "btn btn-small", text: "Remove" });
    up.disabled = i === 0;
    down.disabled = i === rules.length - 1;
    up.addEventListener("click", function () { move(-1); });
    down.addEventListener("click", function () { move(1); });
    del.addEventListener("click", function () { rules.splice(i, 1); render(); });

    return el("li", { className: "rule-row" }, [
      el("div", { className: "rule-head" }, [el("strong", { text: "Rule " + (i + 1) }), el("span", { className: "rule-buttons" }, [up, down, del])]),
      el("div", { className: "rule-grid" }, [
        el("label", { for: id + "-paths", text: "Paths" }),
        paths,
        el("span", { className: "rule-label", text: "Only for" }),
        who,
        el("label", { for: id + "-access", text: "Then" }),
        el("div", { className: "rule-access" }, [access, targetWrap]),
        el("span", {}),
        el("label", { className: "rule-ro" }, [ro, document.createTextNode(" Read-only (refuse everything but GET and HEAD)")])
      ]),
      summary
    ]);
  }

  // ---- modes and buttons --------------------------------------------------------

  function showText(text) {
    builder.hidden = true; textBox.hidden = false;
    toggle.textContent = "Use the rule builder";
    if (text) { parseNote.textContent = text; parseNote.hidden = false; }
  }
  function showBuilder() {
    var parsed = parse(textarea.value);
    if (parsed.error) { showText(parsed.error + " Fix it here, or keep editing as text."); return false; }
    rules = parsed.rules;
    parseNote.hidden = true;
    builder.hidden = false; textBox.hidden = true;
    toggle.textContent = "Edit as text (copy or paste)";
    render();
    return true;
  }

  toggle.hidden = false;
  toggle.addEventListener("click", function () {
    if (builder.hidden) showBuilder(); else showText();
  });
  root.querySelector("[data-rule-add]").addEventListener("click", function () {
    rules.push(rule([], [], "sign-in"));
    render(rules.length - 1);
  });
  var examples = root.querySelector("[data-rule-example]");
  EXAMPLES.forEach(function (ex, i) { examples.append(el("option", { value: String(i), text: ex[0] })); });
  examples.addEventListener("change", function () {
    if (examples.value === "") return;
    rules = rules.concat(EXAMPLES[Number(examples.value)][1]());
    examples.value = "";
    render(rules.length - 1);
  });

  // A server error names text lines, so show the text it is about; otherwise start in the builder.
  if (root.dataset.hasError) showText(); else showBuilder();
})();

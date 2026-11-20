// The form protector: one script tag that puts the door's challenge in front of a plain HTML form. The door serves the
// script at FORM_SCRIPT_PATH, built from its `challenge` config (the provider and the public site key; never the
// secret). In the browser it renders the provider's widget in each same-origin POST form, and on submit sends the form
// with fetch, the widget's token in the door's challenge header, then follows the answer as a form post would. The
// door verifies the token with the provider and records the outcome as the arrival's `challenge` signal; the site's
// backend gets the request with the receipt id, or never hears of it.
import type { DoorConfig } from "./config.ts";

export const FORM_SCRIPT_PATH = "/.well-known/agent-custody-door/form.js";

type Challenge = NonNullable<DoorConfig["challenge"]>;

const PROVIDER_SCRIPT: Record<Challenge["provider"], string> = {
  turnstile: "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit",
  hcaptcha: "https://js.hcaptcha.com/1/api.js?render=explicit",
};

/** The browser script for a door's challenge config. Public: it carries the provider, the site key, the header, and the action. */
export function formScript(challenge: Challenge): string {
  const settings = { provider: challenge.provider, siteKey: challenge.siteKey, header: challenge.header, src: PROVIDER_SCRIPT[challenge.provider], ...(challenge.action ? { action: challenge.action } : {}) };
  return `// agent-custody door: form protector. <script src="${FORM_SCRIPT_PATH}" defer></script>; data-forms on the tag selects the forms.
(() => {
  "use strict";
  const settings = ${JSON.stringify(settings).replace(/</g, "\\u003c")};
  const tag = document.currentScript;
  const selector = (tag && tag.dataset.forms) || "form";
  // the widget's own copies of the token: the door reads it from the header, and a body field would reach the receipt
  const tokenFields = ["cf-turnstile-response", "h-captcha-response", "g-recaptcha-response"];
  const api = () => (settings.provider === "turnstile" ? window.turnstile : window.hcaptcha);

  const protect = (form) => {
    if ((form.getAttribute("method") || "get").toLowerCase() !== "post") return;
    const target = new URL(form.getAttribute("action") || location.href, location.href);
    if (target.origin !== location.origin) return;
    const box = document.createElement("div");
    box.className = "agent-custody-challenge";
    const note = document.createElement("p");
    note.className = "agent-custody-challenge-note";
    note.setAttribute("role", "status");
    const button = form.querySelector('[type="submit"], button:not([type])');
    if (button) button.before(box, note);
    else form.append(box, note);
    const options = { sitekey: settings.siteKey };
    if (settings.provider === "turnstile") {
      options["response-field"] = false;
      if (settings.action) options.action = settings.action;
    }
    const widget = api().render(box, options);
    let sending = false;
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (sending) return;
      const token = api().getResponse(widget);
      if (!token) {
        note.textContent = "Complete the check above, then send the form again.";
        return;
      }
      sending = true;
      note.textContent = "";
      const data = new FormData(form, event.submitter || undefined);
      for (const field of tokenFields) data.delete(field);
      const multipart = (form.getAttribute("enctype") || "").toLowerCase() === "multipart/form-data";
      try {
        const res = await fetch(target, { method: "POST", body: multipart ? data : new URLSearchParams(data), headers: { [settings.header]: token }, credentials: "same-origin", signal: AbortSignal.timeout(30000) });
        if (res.redirected) return location.assign(res.url);
        const type = res.headers.get("content-type") || "";
        if (res.status === 403 && type.includes("application/json")) {
          const refusal = await res.json().catch(() => ({}));
          note.textContent = refusal.challenge ? "The check did not pass. Complete it again, then send the form." : "This form was refused (receipt " + (refusal.receipt || "none") + ").";
          return;
        }
        const body = await res.text();
        if (type.includes("text/html")) {
          document.open();
          document.write(body);
          document.close();
          return;
        }
        note.textContent = res.ok ? "Sent." : "The form was not sent: HTTP " + res.status + ".";
      } catch (error) {
        note.textContent = "The form was not sent: the site could not be reached.";
      } finally {
        sending = false;
        // a token serves one request
        api().reset(widget);
      }
    });
  };

  const start = () => document.querySelectorAll(selector).forEach(protect);
  const loader = document.createElement("script");
  loader.src = settings.src;
  loader.async = true;
  loader.onload = () => (document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", start) : start());
  document.head.append(loader);
})();
`;
}

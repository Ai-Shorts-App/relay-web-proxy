import dns from "node:dns/promises";
import net from "node:net";
import crypto from "node:crypto";
import { Readable } from "node:stream";
import express from "express";
import * as cheerio from "cheerio";
import { Agent } from "undici";

const app = express();

const port = Number(process.env.PORT || 3000);

const maxBodySize = 12 * 1024 * 1024;
const requestWindowMs = 60_000;
const requestLimit = 600;
const sessionTtlMs = 30 * 60_000;
const cleanupIntervalMs = 5 * 60_000;

const requestCounts = new Map();
const sessions = new Map();
const clientOrigins = new Map();

// ---------------------------------------------------------
// PRIVATE / INTERNAL NETWORK PROTECTION
// ---------------------------------------------------------

function isPrivateIp(address) {
  const mapped = address.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);

  if (mapped) {
    address = mapped[1];
  }

  if (net.isIPv4(address)) {
    const [a, b] = address.split(".").map(Number);

    return (
      a === 10 ||
      a === 127 ||
      a === 0 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 198 && (b === 18 || b === 19))
    );
  }

  const normalized = address.toLowerCase();

  return (
    normalized === "::1" ||
    normalized === "::" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:")
  );
}

async function resolvePublicAddress(target) {
  if (!["http:", "https:"].includes(target.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported.");
  }

  if (!target.hostname || target.username || target.password) {
    throw new Error("This URL is not allowed.");
  }

  const records = net.isIP(target.hostname)
    ? [
        {
          address: target.hostname,
          family: net.isIP(target.hostname),
        },
      ]
    : await dns.lookup(target.hostname, { all: true });

  const safe = records.filter(({ address }) => !isPrivateIp(address));

  if (!safe.length) {
    throw new Error("Private and local network targets are blocked.");
  }

  return safe[0];
}

function pinnedDispatcher(address, family) {
  return new Agent({
    connect: {
      lookup: (_hostname, options, callback) => {
        if (options?.all) {
          callback(null, [{ address, family }]);
        } else {
          callback(null, address, family);
        }
      },
      timeout: 20_000,
    },
  });
}

// ---------------------------------------------------------
// RATE LIMITING
// ---------------------------------------------------------

function checkRateLimit(ip) {
  const now = Date.now();
  const current = requestCounts.get(ip);

  if (!current || now - current.startedAt > requestWindowMs) {
    requestCounts.set(ip, {
      startedAt: now,
      count: 1,
    });

    return true;
  }

  current.count += 1;

  return current.count <= requestLimit;
}

// Periodic cleanup
setInterval(() => {
  const cutoff = Date.now() - sessionTtlMs;

  for (const [key, value] of requestCounts) {
    if (value.startedAt < cutoff) {
      requestCounts.delete(key);
    }
  }

  for (const [key, value] of sessions) {
    if (value.seenAt < cutoff) {
      sessions.delete(key);
    }
  }

  for (const [key, value] of clientOrigins) {
    if (value.seenAt < cutoff) {
      clientOrigins.delete(key);
    }
  }
}, cleanupIntervalMs).unref();

// ---------------------------------------------------------
// REQUEST HEADERS
// ---------------------------------------------------------

function upstreamHeaders(req, target, pageOrigin = target.origin) {
  const headers = {
    "user-agent":
      req.get("user-agent") ||
      "RelayProxy/1.0 (authorized use)",

    accept:
      req.get("accept") ||
      "*/*",

    "accept-language":
      req.get("accept-language") ||
      "en-US,en;q=0.8",

    referer: pageOrigin + "/",
  };

  for (const [name, value] of Object.entries(req.headers)) {
    if (
      name.startsWith("x-") &&
      typeof value === "string"
    ) {
      headers[name] = value;
    }
  }

  for (const name of [
    "cookie",
    "range",
    "if-none-match",
    "if-modified-since",
  ]) {
    const value = req.get(name);

    if (value) {
      headers[name] = value;
    }
  }

  const contentType = req.get("content-type");

  if (contentType) {
    headers["content-type"] = contentType;
  }

  if (req.get("origin")) {
    headers.origin = pageOrigin;
  }

  return headers;
}

// ---------------------------------------------------------
// PROXY URL HELPERS
// ---------------------------------------------------------

function proxyUrl(url) {
  return `/proxy?url=${encodeURIComponent(url)}`;
}

function getSessionId(req, res) {
  const match = req
    .get("cookie")
    ?.match(/(?:^|;\s*)relay_session=([^;]+)/);

  const sessionId = match?.[1] || crypto.randomUUID();

  res.setHeader(
    "set-cookie",
    `relay_session=${sessionId}; Path=/; HttpOnly; SameSite=Lax`
  );

  return sessionId;
}

function clientKey(req) {
  return (
    req.ip ||
    req.socket.remoteAddress ||
    "local"
  );
}

function normalizeTarget(value) {
  const input = String(value || "").trim();

  if (!input) {
    throw new Error("Enter a URL to browse.");
  }

  return new URL(
    /^[a-z][a-z\d+.-]*:\/\//i.test(input)
      ? input
      : `https://${input}`
  );
}

// ---------------------------------------------------------
// RESOURCE REWRITING
// ---------------------------------------------------------

function isRewriteableResource(value) {
  return (
    value &&
    !value.startsWith("#") &&
    !value.startsWith("data:") &&
    !value.startsWith("blob:") &&
    !value.startsWith("mailto:") &&
    !value.startsWith("javascript:") &&
    !value.startsWith("tel:") &&
    !value.startsWith("about:") &&
    !value.startsWith("/proxy?url=")
  );
}

function rewriteResource(value, baseUrl) {
  if (!isRewriteableResource(value)) {
    return value;
  }

  try {
    const resolved = new URL(
      value.trim(),
      baseUrl
    );

    if (
      resolved.protocol !== "http:" &&
      resolved.protocol !== "https:"
    ) {
      return value;
    }

    return proxyUrl(resolved.href);
  } catch {
    return value;
  }
}

// ---------------------------------------------------------
// CSS REWRITING
// ---------------------------------------------------------

function rewriteCss(css, baseUrl) {
  const withImports = css.replace(
    /@import\s+(?:url\(\s*(['"]?)([^'")]+)\1\s*\)|(['"])([^'"]+)\3)/gi,
    (
      match,
      _q1,
      urlInParens,
      _q3,
      urlInQuotes
    ) => {
      const original =
        urlInParens || urlInQuotes;

      const rewritten = rewriteResource(
        original,
        baseUrl
      );

      return rewritten === original
        ? match
        : match.replace(
            original,
            rewritten
          );
    }
  );

  return withImports.replace(
    /url\(\s*(['"]?)([^'"\)]+)\1\s*\)/gi,
    (match, quote, value) => {
      const rewritten = rewriteResource(
        value,
        baseUrl
      );

      return rewritten === value
        ? match
        : `url(${quote}${rewritten}${quote})`;
    }
  );
}

// ---------------------------------------------------------
// CLIENT-SIDE NAVIGATION REWRITER
// ---------------------------------------------------------

function rewriteClientNavigation($, upstreamBase) {
  const script = `
(() => {
  "use strict";

  const UPSTREAM_BASE = ${JSON.stringify(upstreamBase)};

  function isInternal(value) {
    if (!value) return true;

    const stringValue = String(value);

    return (
      stringValue.startsWith("#") ||
      stringValue.startsWith("data:") ||
      stringValue.startsWith("blob:") ||
      stringValue.startsWith("javascript:") ||
      stringValue.startsWith("mailto:") ||
      stringValue.startsWith("tel:")
    );
  }

  function relay(value) {
    try {
      if (value == null) {
        return value;
      }

      const stringValue = String(value);

      if (isInternal(stringValue)) {
        return value;
      }

      if (
        stringValue.startsWith("/proxy?url=") ||
        stringValue.startsWith(location.origin + "/proxy?url=")
      ) {
        return value;
      }

      const url = new URL(
        stringValue,
        UPSTREAM_BASE || document.baseURI
      );

      if (
        url.protocol !== "http:" &&
        url.protocol !== "https:"
      ) {
        return value;
      }

      /*
       * If the destination is already this emulator,
       * don't wrap it again.
       */
      if (url.host === location.host) {
        return value;
      }

      return (
        "/proxy?url=" +
        encodeURIComponent(url.href)
      );
    } catch {
      return value;
    }
  }

  // -------------------------------------------------------
  // CLICK NAVIGATION
  // -------------------------------------------------------

  document.addEventListener(
    "click",
    (event) => {
      const link =
        event.target.closest?.("a[href]");

      if (
        !link ||
        event.defaultPrevented ||
        event.button !== 0 ||
        event.metaKey ||
        event.ctrlKey ||
        event.shiftKey ||
        event.altKey
      ) {
        return;
      }

      const next = relay(link.href);

      if (
        next &&
        next !== link.href
      ) {
        event.preventDefault();

        if (
          link.target &&
          link.target !== "_self"
        ) {
          window.open(
            next,
            link.target
          );
        } else {
          window.location.assign(next);
        }
      }
    },
    true
  );

  // -------------------------------------------------------
  // FORM SUBMISSIONS
  // -------------------------------------------------------

  document.addEventListener(
    "submit",
    (event) => {
      const form = event.target;

      if (!(form instanceof HTMLFormElement)) {
        return;
      }

      const next = relay(
        form.action || location.href
      );

      if (
        next &&
        next !== form.action
      ) {
        event.preventDefault();

        form.action = next;

        HTMLFormElement.prototype.submit.call(
          form
        );
      }
    },
    true
  );

  // -------------------------------------------------------
  // FETCH
  // -------------------------------------------------------

  const originalFetch =
    window.fetch;

  window.fetch = function(
    input,
    init
  ) {
    try {
      if (
        typeof input === "string" ||
        input instanceof URL
      ) {
        input = relay(String(input));
      } else if (
        input instanceof Request
      ) {
        input = new Request(
          relay(input.url),
          input
        );
      }
    } catch {}

    return originalFetch.call(
      this,
      input,
      init
    );
  };

  // -------------------------------------------------------
  // XMLHttpRequest
  // -------------------------------------------------------

  const originalXhrOpen =
    XMLHttpRequest.prototype.open;

  XMLHttpRequest.prototype.open =
    function(
      method,
      url,
      ...rest
    ) {
      return originalXhrOpen.call(
        this,
        method,
        relay(url),
        ...rest
      );
    };

  // -------------------------------------------------------
  // WINDOW.OPEN
  // -------------------------------------------------------

  const originalWindowOpen =
    window.open;

  window.open = function(
    url,
    target,
    features
  ) {
    return originalWindowOpen.call(
      window,
      relay(url),
      target,
      features
    );
  };

  // -------------------------------------------------------
  // LOCATION.ASSIGN
  // -------------------------------------------------------

  const originalAssign =
    Location.prototype.assign;

  Location.prototype.assign =
    function(url) {
      return originalAssign.call(
        this,
        relay(url)
      );
    };

  // -------------------------------------------------------
  // LOCATION.REPLACE
  // -------------------------------------------------------

  const originalReplace =
    Location.prototype.replace;

  Location.prototype.replace =
    function(url) {
      return originalReplace.call(
        this,
        relay(url)
      );
    };

  // -------------------------------------------------------
  // HISTORY API
  // -------------------------------------------------------

  const originalPushState =
    history.pushState;

  history.pushState =
    function(
      state,
      title,
      url
    ) {
      return originalPushState.call(
        this,
        state,
        title,
        url
          ? relay(url)
          : url
      );
    };

  const originalReplaceState =
    history.replaceState;

  history.replaceState =
    function(
      state,
      title,
      url
    ) {
      return originalReplaceState.call(
        this,
        state,
        title,
        url
          ? relay(url)
          : url
      );
    };

  // -------------------------------------------------------
  // DYNAMIC ELEMENT CREATION
  // -------------------------------------------------------

  const originalSetAttribute =
    Element.prototype.setAttribute;

  Element.prototype.setAttribute =
    function(name, value) {
      const lower =
        String(name).toLowerCase();

      if (
        lower === "href" ||
        lower === "src" ||
        lower === "action" ||
        lower === "poster"
      ) {
        value = relay(value);
      }

      return originalSetAttribute.call(
        this,
        name,
        value
      );
    };

  // -------------------------------------------------------
  // HTML INSERTION
  // -------------------------------------------------------

  const originalInsertAdjacentHTML =
    Element.prototype.insertAdjacentHTML;

  Element.prototype.insertAdjacentHTML =
    function(
      position,
      html
    ) {
      return originalInsertAdjacentHTML.call(
        this,
        position,
        html
      );
    };

  // -------------------------------------------------------
  // NAVIGATION OBSERVER
  // -------------------------------------------------------

  const observer =
    new MutationObserver(
      (mutations) => {
        for (const mutation of mutations) {
          for (const node of mutation.addedNodes) {
            if (
              node.nodeType !== Node.ELEMENT_NODE
            ) {
              continue;
            }

            const elements = [
              node,
              ...node.querySelectorAll?.(
                "[href],[src],[action],[poster]"
              ) || []
            ];

            for (const element of elements) {
              for (const attr of [
                "href",
                "src",
                "action",
                "poster"
              ]) {
                if (
                  element.hasAttribute?.(attr)
                ) {
                  const value =
                    element.getAttribute(attr);

                  const next =
                    relay(value);

                  if (
                    next &&
                    next !== value
                  ) {
                    element.setAttribute(
                      attr,
                      next
                    );
                  }
                }
              }
            }
          }
        }
      }
    );

  observer.observe(
    document.documentElement || document,
    {
      childList: true,
      subtree: true
    }
  );

  // -------------------------------------------------------
  // SERVICE-WORKER / WORKER URLS
  // -------------------------------------------------------

  try {
    if (
      navigator.serviceWorker &&
      navigator.serviceWorker.register
    ) {
      const originalRegister =
        navigator.serviceWorker.register.bind(
          navigator.serviceWorker
        );

      navigator.serviceWorker.register =
        function(scriptURL, options) {
          return originalRegister(
            relay(scriptURL),
            options
          );
        };
    }
  } catch {}

})();
`;

  $("head").prepend(
    `<script>${script}</script>`
  );
}

// ---------------------------------------------------------
// HTML REWRITING
// ---------------------------------------------------------

function rewriteHtml(html, baseUrl) {
  const $ = cheerio.load(html);

  // Remove upstream <base> tags because they can cause
  // subsequent links to escape the proxy.
  $("base").remove();

  const attributes = [
    ["a[href]", "href"],
    ["area[href]", "href"],
    ["form[action]", "action"],
    ["img[src]", "src"],
    ["script[src]", "src"],
    ["iframe[src]", "src"],
    ["source[src]", "src"],
    ["video[src]", "src"],
    ["audio[src]", "src"],
    ["track[src]", "src"],
    ["object[data]", "data"],
    ["embed[src]", "src"],
    ["link[href]", "href"],
  ];

  for (const [
    selector,
    attribute,
  ] of attributes) {
    $(selector).each(
      (_, element) => {
        const value =
          $(element).attr(attribute);

        if (
          !isRewriteableResource(value)
        ) {
          return;
        }

        $(element).attr(
          attribute,
          rewriteResource(
            value,
            baseUrl
          )
        );
      }
    );
  }

  // srcset
  $(
    "img[srcset], source[srcset]"
  ).each((_, element) => {
    const value =
      $(element).attr("srcset");

    if (!value) {
      return;
    }

    $(element).attr(
      "srcset",
      value
        .split(",")
        .map((candidate) => {
          const parts =
            candidate
              .trim()
              .split(/\s+/);

          parts[0] =
            rewriteResource(
              parts[0],
              baseUrl
            );

          return parts.join(" ");
        })
        .join(", ")
    );
  });

  // Inline styles
  $(
    "video[poster], [style]"
  ).each((_, element) => {
    for (const attribute of [
      "poster",
      "style",
    ]) {
      const value =
        $(element).attr(attribute);

      if (
        value &&
        attribute === "poster"
      ) {
        $(element).attr(
          attribute,
          rewriteResource(
            value,
            baseUrl
          )
        );
      }

      if (
        value &&
        attribute === "style"
      ) {
        $(element).attr(
          attribute,
          rewriteCss(
            value,
            baseUrl
          )
        );
      }
    }
  });

  // <style>
  $("style").each(
    (_, element) => {
      $(element).text(
        rewriteCss(
          $(element).text(),
          baseUrl
        )
      );
    }
  );

  // Remove upstream CSP because it may prevent
  // resources from loading through this origin.
  $(
    "meta[http-equiv='Content-Security-Policy'], meta[http-equiv='content-security-policy']"
  ).remove();

  // Meta refresh
  $("meta[http-equiv='refresh']").each(
    (_, element) => {
      const content =
        $(element).attr("content") ||
        "";

      const match =
        content.match(
          /^(\s*\d+\s*;\s*url=)(.*)$/i
        );

      if (!match) {
        return;
      }

      try {
        const destination =
          new URL(
            match[2],
            baseUrl
          ).href;

        $(element).attr(
          "content",
          `${match[1]}${proxyUrl(
            destination
          )}`
        );
      } catch {
        $(element).remove();
      }
    }
  );

  // Rewrite inline event-handler URLs where
  // reasonably safe.
  $("[onclick]").each(
    (_, element) => {
      let value =
        $(element).attr("onclick");

      if (!value) {
        return;
      }

      value = value
        .replace(
          /window\.open\s*\(\s*(['"])(https?:\/\/[^'"]+)\1/gi,
          (match, quote, url) => {
            return `window.open(${quote}${proxyUrl(
              url
            )}${quote}`;
          }
        )
        .replace(
          /location\.(assign|replace)\s*\(\s*(['"])(https?:\/\/[^'"]+)\2/gi,
          (
            match,
            method,
            quote,
            url
          ) => {
            return `location.${method}(${quote}${proxyUrl(
              url
            )}${quote}`;
          }
        );

      $(element).attr(
        "onclick",
        value
      );
    }
  );

  // Inject navigation interception
  // before the site's scripts execute.
  rewriteClientNavigation(
    $,
    baseUrl
  );

  return $.html();
}

// ---------------------------------------------------------
// UPSTREAM FETCH
// ---------------------------------------------------------

async function fetchResponse(
  url,
  options
) {
  const controller =
    new AbortController();

  const timeout =
    setTimeout(
      () => controller.abort(),
      20_000
    );

  try {
    return await fetch(
      url,
      {
        ...options,
        signal:
          controller.signal,
      }
    );
  } finally {
    clearTimeout(timeout);
  }
}

// ---------------------------------------------------------
// REQUEST BODY
// ---------------------------------------------------------

async function readRequestBody(req) {
  if (
    !["POST", "PUT", "PATCH"].includes(
      req.method
    )
  ) {
    return undefined;
  }

  const chunks = [];
  let size = 0;

  for await (const chunk of req) {
    size += chunk.length;

    if (
      size >
      2 * 1024 * 1024
    ) {
      throw new Error(
        "Request body is too large."
      );
    }

    chunks.push(chunk);
  }

  return Buffer.concat(chunks);
}

// ---------------------------------------------------------
// REDIRECT HANDLING
// ---------------------------------------------------------

async function fetchWithCheckedRedirects(
  startUrl,
  req,
  body,
  pageOrigin
) {
  let currentUrl = startUrl;
  let method = req.method;

  for (
    let redirect = 0;
    redirect <= 5;
    redirect += 1
  ) {
    const {
      address,
      family,
    } =
      await resolvePublicAddress(
        currentUrl
      );

    const dispatcher =
      pinnedDispatcher(
        address,
        family === 6
          ? 6
          : 4
      );

    const response =
      await fetchResponse(
        currentUrl,
        {
          redirect: "manual",
          method,
          headers:
            upstreamHeaders(
              req,
              currentUrl,
              pageOrigin
            ),
          body:
            method === "GET" ||
            method === "HEAD"
              ? undefined
              : body,
          dispatcher,
        }
      );

    if (
      ![
        301,
        302,
        303,
        307,
        308,
      ].includes(
        response.status
      )
    ) {
      return {
        response,
        finalUrl: currentUrl,
      };
    }

    const location =
      response.headers.get(
        "location"
      );

    if (!location) {
      return {
        response,
        finalUrl: currentUrl,
      };
    }

    if (
      response.status === 303 ||
      (
        (
          response.status === 301 ||
          response.status === 302
        ) &&
        method === "POST"
      )
    ) {
      method = "GET";
      body = undefined;
    }

    currentUrl =
      new URL(
        location,
        currentUrl
      );
  }

  throw new Error(
    "Too many redirects."
  );
}

// ---------------------------------------------------------
// PROXY RESPONSE
// ---------------------------------------------------------

async function serveProxyRequest(
  req,
  res,
  target
) {
  const sessionId =
    getSessionId(
      req,
      res
    );

  const body =
    await readRequestBody(
      req
    );

  const pageOrigin =
    sessions.get(
      sessionId
    )?.origin ||
    target.origin;

  const {
    response,
    finalUrl,
  } =
    await fetchWithCheckedRedirects(
      target,
      req,
      body,
      pageOrigin
    );

  const contentType =
    response.headers.get(
      "content-type"
    ) ||
    "application/octet-stream";

  if (
    contentType.includes(
      "text/html"
    )
  ) {
    sessions.set(
      sessionId,
      {
        origin:
          finalUrl.origin,
        seenAt:
          Date.now(),
      }
    );

    clientOrigins.set(
      clientKey(req),
      {
        origin:
          finalUrl.origin,
        seenAt:
          Date.now(),
      }
    );
  }

  res.setHeader(
    "content-type",
    contentType
  );

  res.status(
    response.status
  );

  res.setHeader(
    "cache-control",
    "no-store"
  );

  res.setHeader(
    "x-content-type-options",
    "nosniff"
  );

  if (
    contentType.includes(
      "text/html"
    )
  ) {
    /*
     * Keep navigation inside the emulator.
     */
    res.setHeader(
      "content-security-policy",
      [
        "default-src * data: blob: 'unsafe-inline' 'unsafe-eval'",
        "navigate-to 'self'",
        "form-action 'self'",
      ].join("; ")
    );
  }

  // Important response headers
  for (const name of [
    "accept-ranges",
    "etag",
    "last-modified",
  ]) {
    const value =
      response.headers.get(
        name
      );

    if (value) {
      res.setHeader(
        name,
        value
      );
    }
  }

  // Range responses
  if (
    response.status === 206
  ) {
    const contentRange =
      response.headers.get(
        "content-range"
      );

    const contentLength =
      response.headers.get(
        "content-length"
      );

    if (contentRange) {
      res.setHeader(
        "content-range",
        contentRange
      );
    }

    if (contentLength) {
      res.setHeader(
        "content-length",
        contentLength
      );
    }
  }

  // Cookies
  const setCookies =
    response.getSetCookie?.() ||
    [];

  if (
    setCookies.length
  ) {
    const relayCookie =
      `relay_session=${sessionId}; Path=/; HttpOnly; SameSite=Lax`;

    res.setHeader(
      "set-cookie",
      [
        relayCookie,
        ...setCookies.map(
          (cookie) =>
            cookie
              .replace(
                /;\s*domain=[^;]+/gi,
                ""
              )
              .replace(
                /;\s*secure/gi,
                ""
              )
              .replace(
                /;\s*samesite=[^;]+/gi,
                "; SameSite=Lax"
              )
        ),
      ]
    );
  }

  // -------------------------------------------------------
  // REDIRECT HEADER
  // -------------------------------------------------------

  const location =
    response.headers.get(
      "location"
    );

  if (location) {
    try {
      const absolute =
        new URL(
          location,
          finalUrl
        ).href;

      res.setHeader(
        "location",
        proxyUrl(
          absolute
        )
      );
    } catch {
      // Don't forward an invalid Location header.
    }
  }

  // -------------------------------------------------------
  // HTML
  // -------------------------------------------------------

  try {
    if (
      contentType.includes(
        "text/html"
      )
    ) {
      const text =
        await readBoundedText(
          response,
          maxBodySize
        );

      return res.send(
        rewriteHtml(
          text,
          finalUrl
        )
      );
    }

    // -----------------------------------------------------
    // CSS
    // -----------------------------------------------------

    if (
      contentType.includes(
        "text/css"
      )
    ) {
      const text =
        await readBoundedText(
          response,
          maxBodySize
        );

      return res.send(
        rewriteCss(
          text,
          finalUrl
        )
      );
    }
  } catch (error) {
    if (
      error.statusCode ===
      413
    ) {
      return res
        .status(413)
        .send(
          "The response is too large."
        );
    }

    throw error;
  }

  // -------------------------------------------------------
  // STREAM OTHER CONTENT
  // -------------------------------------------------------

  if (!response.body) {
    return res.end();
  }

  const stream =
    Readable.fromWeb(
      response.body
    );

  let streamed = 0;

  stream.on(
    "data",
    (chunk) => {
      streamed +=
        chunk.length;

      if (
        streamed >
        maxBodySize
      ) {
        stream.destroy();

        if (
          !res.headersSent
        ) {
          res.status(413);
        }

        res.end();
      }
    }
  );

  stream.on(
    "error",
    () => {
      if (
        res.headersSent
      ) {
        res.destroy();
      } else {
        res
          .status(502)
          .send(
            "The upstream stream failed."
          );
      }
    }
  );

  stream.pipe(res);
}

// ---------------------------------------------------------
// HEALTH
// ---------------------------------------------------------

app.get(
  "/health",
  (_req, res) => {
    res.json({
      ok: true,
    });
  }
);

// ---------------------------------------------------------
// MAIN PROXY ROUTE
// ---------------------------------------------------------

app.all(
  "/proxy",
  async (req, res) => {
    if (
      !checkRateLimit(
        req.ip
      )
    ) {
      return res
        .status(429)
        .send(
          "Rate limit exceeded. Try again shortly."
        );
    }

    let target;

    try {
      target =
        normalizeTarget(
          req.query.url
        );

      return await serveProxyRequest(
        req,
        res,
        target
      );
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Unable to fetch target.";

      res
        .status(400)
        .send(message);
    }
  }
);

// ---------------------------------------------------------
// FOLLOW-UP REQUESTS
// ---------------------------------------------------------

app.use(
  async (
    req,
    res,
    next
  ) => {
    if (
      ![
        "GET",
        "POST",
        "PUT",
        "PATCH",
      ].includes(req.method) ||
      req.path === "/" ||
      req.path.startsWith(
        "/proxy"
      ) ||
      req.path.startsWith(
        "/health"
      )
    ) {
      return next();
    }

    if (
      !checkRateLimit(
        req.ip
      )
    ) {
      return res
        .status(429)
        .send(
          "Rate limit exceeded. Try again shortly."
        );
    }

    const match =
      req
        .get("cookie")
        ?.match(
          /(?:^|;\s*)relay_session=([^;]+)/
        );

    const origin =
      sessions.get(
        match?.[1]
      )?.origin ||
      clientOrigins.get(
        clientKey(req)
      )?.origin;

    if (!origin) {
      return next();
    }

    try {
      const target =
        new URL(
          req.originalUrl,
          origin
        );

      await serveProxyRequest(
        req,
        res,
        target
      );
    } catch (error) {
      res
        .status(502)
        .send(
          error instanceof Error
            ? error.message
            : "Unable to fetch target."
        );
    }
  }
);

// ---------------------------------------------------------
// START
// ---------------------------------------------------------

app.listen(
  port,
  () => {
    console.log(
      `Relay Proxy running at http://localhost:${port}`
    );
  }
);
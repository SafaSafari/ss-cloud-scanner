(() => {
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __commonJS = (cb, mod) => function __require() {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  };

  // src/router.js
  var require_router = __commonJS({
    "src/router.js"(exports, module) {
      var Method = (method) => (req) => req.method.toLowerCase() === method.toLowerCase();
      var Connect = Method("connect");
      var Delete = Method("delete");
      var Get = Method("get");
      var Head = Method("head");
      var Options = Method("options");
      var Patch = Method("patch");
      var Post = Method("post");
      var Put = Method("put");
      var Trace = Method("trace");
      var Path = (regExp) => (req) => {
        const url = new URL(req.url);
        const path = url.pathname;
        const match = path.match(regExp) || [];
        return match[0] === path;
      };
      var Router = class {
        constructor() {
          this.routes = [];
        }
        handle(conditions, handler) {
          this.routes.push({
            conditions,
            handler
          });
          return this;
        }
        connect(url, handler) {
          return this.handle([Connect, Path(url)], handler);
        }
        delete(url, handler) {
          return this.handle([Delete, Path(url)], handler);
        }
        get(url, handler) {
          return this.handle([Get, Path(url)], handler);
        }
        head(url, handler) {
          return this.handle([Head, Path(url)], handler);
        }
        options(url, handler) {
          return this.handle([Options, Path(url)], handler);
        }
        patch(url, handler) {
          return this.handle([Patch, Path(url)], handler);
        }
        post(url, handler) {
          return this.handle([Post, Path(url)], handler);
        }
        put(url, handler) {
          return this.handle([Put, Path(url)], handler);
        }
        trace(url, handler) {
          return this.handle([Trace, Path(url)], handler);
        }
        all(handler) {
          return this.handle([], handler);
        }
        route(req) {
          const route = this.resolve(req);
          if (route) {
            return route.handler(req);
          }
          return new Response("resource not found", {
            status: 404,
            statusText: "not found",
            headers: {
              "content-type": "text/plain"
            }
          });
        }
        resolve(req) {
          return this.routes.find((r) => {
            if (!r.conditions || Array.isArray(r) && !r.conditions.length) {
              return true;
            }
            if (typeof r.conditions === "function") {
              return r.conditions(req);
            }
            return r.conditions.every((c) => c(req));
          });
        }
      };
      module.exports = Router;
    }
  });

  // src/down.js
  var require_down = __commonJS({
    "src/down.js"(exports, module) {
      var DEFAULT_NUM_BYTES = 0;
      var MAX_BYTES = 1e8;
      var getQs = (url) => {
        const sp = url.split("?");
        if (sp.length < 2) {
          return {};
        }
        const qs = sp[1];
        return Object.assign(
          {},
          ...qs.split("&").map((s) => {
            const sp2 = s.split("=");
            if (sp2.length !== 2) {
              return {};
            }
            return { [sp2[0]]: sp2[1] };
          })
        );
      };
      var genContent = (numBytes = 0) => "0".repeat(Math.max(0, numBytes));
      async function handleRequest2(request) {
        const reqTime = new Date();
        const qs = getQs(request.url);
        const numBytes = qs.hasOwnProperty("bytes") ? Math.min(MAX_BYTES, Math.abs(+qs.bytes)) : DEFAULT_NUM_BYTES;
        const res = new Response(genContent(numBytes));
        res.headers.set("access-control-allow-origin", "*");
        res.headers.set("timing-allow-origin", "*");
        res.headers.set("cache-control", "no-store");
        res.headers.set("content-type", "application/octet-stream");
        request.cf && request.cf.colo && res.headers.set("cf-meta-colo", request.cf.colo);
        res.headers.set("cf-meta-request-time", +reqTime);
        res.headers.set(
          "access-control-expose-headers",
          "cf-meta-colo, cf-meta-request-time"
        );
        return res;
      }
      module.exports = handleRequest2;
    }
  });

  // src/up.js
  var require_up = __commonJS({
    "src/up.js"(exports, module) {
      async function handleRequest2(request) {
        const reqTime = new Date();
        const res = new Response("ok");
        res.headers.set("access-control-allow-origin", "*");
        res.headers.set("timing-allow-origin", "*");
        request.cf && request.cf.colo && res.headers.set("cf-meta-colo", request.cf.colo);
        res.headers.set("cf-meta-request-time", +reqTime);
        res.headers.set(
          "access-control-expose-headers",
          "cf-meta-colo, cf-meta-request-time"
        );
        return res;
      }
      module.exports = handleRequest2;
    }
  });

  // src/index.js
  var require_src = __commonJS({
    "src/index.js"(exports, module) {
      var Router = require_router();
      var downHandler = require_down();
      var upHandler = require_up();
      async function handleRequest2(request) {
        const r = new Router();
        r.get(".*/down", downHandler);
        r.post(".*/up", upHandler);
        return await r.route(request);
      }
      module.exports = handleRequest2;
    }
  });

  // index.js
  var handleRequest = require_src();
  addEventListener("fetch", (event) => {
    event.respondWith(handleRequest(event.request));
  });
})();
//# sourceMappingURL=index.js.map

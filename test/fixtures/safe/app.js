(function () {
  "use strict";
  // Config is an own window property created before any untrusted markup runs.
  var APP_CONFIG = window.APP_CONFIG = Object.freeze({ cdn: "/assets/" });
  var s = document.createElement("script");
  s.src = APP_CONFIG.cdn + "app.js";
  document.head.appendChild(s);
}());

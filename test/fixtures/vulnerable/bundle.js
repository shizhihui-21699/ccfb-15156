/* Simulated product bundle. Minified-ish, IIFE-wrapped, aliasing through locals. */
!function(){
  "use strict";
  function boot(){
    var a = window.APP_CONFIG || {};
    var cdn = a.cdn || "/assets/";
    var s = document.createElement("script");
    s.src = cdn + "vendor.js";
    document.head.appendChild(s);
  }
  function track(){
    var t = document.cookie;
    navigator.sendBeacon("/collect", t);
  }
  function init(){ boot(); track(); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
}();

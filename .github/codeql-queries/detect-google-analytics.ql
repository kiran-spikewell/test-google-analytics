/**
 * @name Detect Google Tag Manager (gtag.js) in JavaScript/TypeScript
 * @description Identifies the inclusion of Google Tag Manager (`gtag.js`) and usage of the `gtag` function in JavaScript and TypeScript files.
 * @kind path-problem
 * @id js-ts/google-tag-manager
 * @tags tracking, javascript, typescript
 * @problem.severity critical
 * @problem.priority high
 * @precision medium
 */

import javascript
import typescript

/**
 * Predicate to detect if a script includes Google Tag Manager (`gtag.js`).
 * This checks for the presence of `gtag.js` in both JavaScript and TypeScript files.
 */
predicate isGoogleTagManager(Script s) {
  exists (string url |
    s.getAStringLiteral().getValue() = url and
    url = "https://www.googletagmanager.com/gtag/js?id=" or
    url.matches("https://www.googletagmanager.com/gtag/js\\?id=.*")
  )
}

/**
 * Predicate to detect usage of the `gtag` function in JavaScript and TypeScript.
 */
predicate isGtagFunctionCall(CallExpr call) {
  call.getCallee().(RefersTo).getAnIdentifier().getName() = "gtag"
}

/**
 * Detects `gtag.js` usage in both JavaScript and TypeScript files.
 */
from Script s, CallExpr call
where isGoogleTagManager(s) or isGtagFunctionCall(call)
select s, "This file includes Google Tag Manager (gtag.js) or uses the 'gtag' function."

/**
 * Additional detection for TypeScript files.
 */
from TypeScriptModule ts, CallExpr callTs
where isGtagFunctionCall(callTs)
select ts, "This TypeScript file includes the usage of the 'gtag' function."

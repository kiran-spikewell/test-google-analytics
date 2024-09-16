/**
 * @name Detect Google Tag Manager (gtag.js) and vue-gtag
 * @description Identifies the inclusion of Google Tag Manager (`gtag.js`) and usage of the `gtag` function in JavaScript and TypeScript files, including indirect usage via `vue-gtag`.
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
  exists(Identifier id |
    id = call.getCallee().(RefersTo).getAnIdentifier() and
    id.getName() = "gtag"
  )
}

/**
 * Predicate to detect import of `vue-gtag` module.
 */
predicate isVueGtagImport(Import i) {
  i.getImportedModule().getName() = "vue-gtag"
}

/**
 * Predicate to detect calls to functions from `vue-gtag`.
 */
predicate isVueGtagFunctionCall(CallExpr call) {
  exists(Import i |
    i.getImportedModule().getName() = "vue-gtag" and
    call.getCallee().(RefersTo).getAnIdentifier() in i.getImportedIdentifiers()
  )
}

/**
 * Detects `gtag.js` usage or `vue-gtag` imports in JavaScript and TypeScript files.
 */
from Script s, CallExpr call
where isGoogleTagManager(s) or isGtagFunctionCall(call) or isVueGtagImport(s) or isVueGtagFunctionCall(call)
select s, "This file includes Google Tag Manager (gtag.js), uses the 'gtag' function, or imports 'vue-gtag'."

/**
 * Detects `gtag` or `vue-gtag` usage specifically within TypeScript files.
 */
from TypeScriptModule ts, CallExpr callTs
where isGtagFunctionCall(callTs) or isVueGtagFunctionCall(callTs)
select ts, "This TypeScript file includes the usage of the 'gtag' function or imports 'vue-gtag'."

// Minimal `process` typing for the browser test-environment guard in crypto.ts.
// This file is intentionally small so it does not pull in all Node.js types.
declare const process: {
  env?: Record<string, string | undefined>;
} | undefined;

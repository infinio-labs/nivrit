# SDK protocol contract

All SDK adapters implement the same transport interface:

1. Join `base_url` and a path beginning with `/`.
2. Send `Authorization: Bearer <token>` on every request.
3. Send JSON and `Content-Type: application/json` when a body exists.
4. Accept any `2xx` response; decode JSON when a response body exists.
5. Convert non-`2xx` responses to an error containing status and response body.
6. Use a finite request timeout; never retry mutating requests implicitly.

The language-specific adapter owns native HTTP and error types. The contract is
deliberately smaller than a shared implementation so each SDK keeps its native
interface.

## Conformance cases

Adapters should cover these cases with their native test runner:

| Case | Expected |
| --- | --- |
| `GET /users/me` with token | bearer header, JSON decode |
| `POST /projects` with body | JSON content type and encoded body |
| `204` response | no decode failure |
| `401` response | status and body preserved in error |
| transport failure | native transport error preserved |

Changes to this contract require updating every adapter and its conformance
tests in the same change.

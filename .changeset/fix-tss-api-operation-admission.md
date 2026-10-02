---
'tss-api': patch
---

Serialize key-generation and signing admission, protect operation registries during concurrent access, and preserve operation ownership during cleanup. Return HTTP 409 when key-generation and signing reservations for the same protocol conflict.

## Opaque Pattern in C

### Overview

The **opaque pattern** (also known as the *opaque pointer* pattern) is a design technique used in C to **hide the internal representation of a data structure** from users of an API.  
This pattern enables **encapsulation**, **safer interfaces**, and **implementation flexibility**, even in a language without native object-oriented features.

In this project, the opaque pattern is used to model object-like components while preventing direct access to internal state.

---

### Core Idea

The opaque pattern enforces a clear separation between **interface** and **implementation**:

- The **header file (`.h`)** exposes only an *incomplete type* and public function prototypes.
- The **source file (`.c`)** contains the full structure definition and the implementation details.

Users interact with the object **only through functions**, never by accessing structure fields directly.

---

### Public Interface (Header)

```c
typedef struct foo foo_t;


Why Use the Opaque Pattern?

The opaque pattern provides several important advantages:

Encapsulation
Prevents direct access to internal state.

API and ABI Stability
Internal changes do not break user code.

Safety and Maintainability
Reduces the risk of misuse and accidental corruption.

Security
Particularly useful for sensitive data such as cryptographic keys or authentication state.

Clear Ownership Model
Creation and destruction of objects are explicitly managed by the API.

This pattern is widely used in system-level and embedded libraries, including:

ESP-IDF components

OpenSSL

mbedTLS

Standard C libraries (libc)
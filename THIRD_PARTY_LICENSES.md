# Third-Party Licenses

This project optionally integrates third-party libraries as external dependencies.
None of these libraries are bundled in this repository by default.
Each library is subject to its own license terms, independent of this project's
BSD 3-Clause license.

---

## wolfSSL

| Field       | Value |
|---|---|
| **Version** | 5.x (or as initialized via submodule) |
| **Website** | https://www.wolfssl.com |
| **Repository** | https://github.com/wolfSSL/wolfssl |
| **License** | GPLv3 (open source) OR Commercial |
| **License text** | https://www.wolfssl.com/license/ |
| **Used as** | Optional TLS backend (default build option) |
| **Included in repo** | ❌ No — optional git submodule, not initialized by default |

### License implications

wolfSSL is licensed under the **GNU General Public License v3.0 (GPLv3)**.

If you build this project with wolfSSL and distribute the resulting binary:
- Your binary must comply with the terms of GPLv3, including making
  source code available to recipients.
- Alternatively, you must obtain a **commercial license** from wolfSSL, Inc.
  See: https://www.wolfssl.com/license/

To initialize the wolfSSL submodule:
```bash
git submodule update --init external/wolfssl
```

---

## mbedTLS

| Field | Value |
| :--- | :--- |
| **Version** | 3.x (or as initialized via submodule) |
| **Website** | https://www.trustedfirmware.org/projects/mbed-tls/ |
| **Repository** | https://github.com/Mbed-TLS/mbedtls |
| **License** | Apache License 2.0 |
| **License text** | https://github.com/Mbed-TLS/mbedtls/blob/development/LICENSE |
| **Used as** | Optional TLS backend (alternative build option) |
| **Included in repo** | ❌ No — optional git submodule, not initialized by default |

### License implications

mbed TLS is licensed under the permissive **Apache License 2.0**.

If you build this project with mbed TLS and distribute the resulting binary:
* You must include a copy of the Apache 2.0 license and any applicable NOTICE files.
* Unlike GPLv3, this license is permissive and does not require you to make your own proprietary source code available.

To initialize the mbed TLS submodule:
```bash
git submodule update --init external/mbedtls
```
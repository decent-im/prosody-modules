---
summary: HTTP Strict Transport Security
---

# Introduction

This module implements [RFC 6797: HTTP Strict Transport Security] and
responds to all non-HTTPS requests with a `301 Moved Permanently`
redirect to the HTTPS equivalent of the path.

# Configuration

Add the module to the `modules_enabled` list and optionally configure
the specific header sent.

``` lua
modules_enabled = {
  ...
      "strict_https";
}
hsts_header = "max-age=31556952"
```

# Compatibility

  ------- -------------
  trunk   Should work
  0.12    Should work
  0.11    Should work
  ------- -------------

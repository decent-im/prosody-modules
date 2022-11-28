---
labels:
- Stage-Beta
summary: "XEP-0198 integration with SASL2"
rockspec:
  dependencies:
  - mod_sasl2
---

Add support for inlining stream management negotiation into the SASL2 process.

**Note: At the time of writing (November 2022), this module implements a
version of XEP-0198 that is still working its way through the XSF standards
process. For more information and current status, see [PR #1215](https://github.com/xsf/xeps/pull/1215).**

This module depends on [mod_sasl2] and [mod_sasl2_bind2]. It exposes no
configuration options.

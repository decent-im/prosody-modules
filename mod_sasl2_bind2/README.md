---
labels:
- Stage-Beta
summary: "Bind 2 integration with SASL2"
---

Add support for [XEP-0386: Bind 2], which is a new method for clients to bind
resources and establish sessions in XMPP, using SASL2. **Note: At the time of
writing (November 2022), this plugin implements a version of XEP-0386 that is
still working its way through the XSF standards process. See [PR #1217](https://github.com/xsf/xeps/pull/1217)
for more information and current status.**

This module depends on [mod_sasl2]. It exposes no configuration options.

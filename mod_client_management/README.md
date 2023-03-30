---
labels:
- Stage-Beta
summary: "Manage clients with access to your account"
rockspec:
  dependencies:
  - mod_sasl2_fast
---

This module allows a user to identify what currently has access to their
account.

This module depends on [mod_sasl2_fast] and mod_tokenauth (bundled with
Prosody). Both will be automatically loaded if this module is loaded.

## Configuration

| Name                      | Description                                            | Default         |
|---------------------------|--------------------------------------------------------|-----------------|
| enforce_client_ids        | Only allow SASL2-compatible clients                    | `false`         |

When `enforce_client_ids` is not enabled, the client listing may be less accurate due to legacy clients,
which can only be tracked by their resource, which is public information, not necessarily unique to a
client instance, and is also exposed to other XMPP entities the user communicates with.

When `enforce_client_ids` is enabled, clients that don't support SASL2 and provide a client id will be
denied access.

## Compatibility

Requires Prosody trunk (as of 2023-03-29). Not compatible with Prosody 0.12
and earlier.

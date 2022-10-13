---
labels:
- Stage-Alpha
summary: "XEP-0388: Extensible SASL Profile"
---

Experimental implementation of [XEP-0388: Extensible SASL Profile]

## Developers

mod_sasl2 provides some events you can hook to affect aspects of the
authentication process:

- `advertise-sasl-features`
- `sasl2/c2s/success`
  - Priority 1000: Session marked as authenticated, success response created (`event.success`)
  - Priority -1000: Success response sent to client
  - Priority -1500: Updated <stream-features/> sent to client
- `sasl2/c2s/failure`
- `sasl2/c2s/error`

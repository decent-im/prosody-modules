---
labels:
- 'Stage-Beta'
summary: 'Forward spam/abuse reports to a JID'
---

This module forwards spam/abuse reports (e.g. those submitted by users via
XEP-0377 via mod_spam_reporting) to one or more JIDs.

## Configuration

Install and enable the module the same as any other.

There is a single option, `spam_report_destinations` which accepts a list of
JIDs to send reports to.

For example:

```lua
modules_enabled = {
    ---
    "spam_reporting";
    "spam_report_forwarder";
    ---
}

spam_report_destinations = { "antispam.example.com" }
```

## Protocol

This section is intended for developers.

XEP-0377 assumes the report is embedded within another protocol such as
XEP-0191, and doesn't specify a format for communicating "standalone" reports.
This module transmits them inside a `<message>` stanza, and adds a `<jid/>`
element (borrowed from XEP-0268):

```xml
<message from="prosody.example" to="destination.example">
    <report xmlns="urn:xmpp:reporting:1" reason="urn:xmpp:reporting:spam">
        <jid xmlns="urn:xmpp:jid:0">spammer@bad.example</jid>
        <text>
          Never came trouble to my house like this.
        </text>
    </report>
</message>
```

---
labels:
- 'Stage-Beta'
summary: 'Import MUC membership info from a JSON file'
...

Introduction
============

This module allows you to import MUC membership information from an external
URL in JSON format.

Details
=======

If you have an organization or community and lots of members and/or channels,
it can be frustrating to manage MUC affiliations manually. This module will
fetch a JSON file from a configured URL, and use that to automatically set the
MUC affiliations.

It also supports hats/badges.

Configuration
=============

Add the module to the MUC host (not the global modules\_enabled):

        Component "conference.example.com" "muc"
            modules_enabled = { "muc_members_json" }

You can define (globally or per-MUC component) the following options:

  Name                  Description
  --------------------- --------------------------------------------------
  muc_members_json_url  The URL to the JSON file describing memberships
  muc_members_json_mucs The MUCs to manage, and their associated configuration

The `muc_members_json_mucs` setting determines which rooms will be managed by
the plugin, and how to map roles to hats (if desired).

```
muc_members_json_mucs = {
	myroom = {
		member_hat = {
			id = "urn:uuid:6a1b143a-1c5c-11ee-80aa-4ff1ce4867dc";
			title = "Cool Member";
		};
	};
}
```

JSON format
===========

``` json
{
  "members": [
    {
      "jids": [
        "user@example.com",
        "user2@example.com"
      ]
    },
    {
      "jids": ["user3@example.com"],
      "roles": ["janitor"]
    }
  ]
}
```

Each member must have a `jids` field, and optionally a `roles` field.

Compatibility
=============

  ------- ------------------
  trunk   Works
  0.12    Works
  ------- ------------------


---
summary: Seed MUC configuration from JSON REST API
---

# Introduction

This module fetches configuration for MUC rooms from an API when rooms
are created.

# Requirements

Should work with Prosody 0.11.

# Configuration

`muc_create_api_url`
:   URL template for the API endpoint to get settings. `{room.jid}` is
    replaced by the address of the room in question.

`muc_create_api_auth`
:   The value of the Authorization header to authenticate against the
    API. E.g. `"Bearer /rXU4tkQTYQMgdHfMLH6"`{.lua}

## Example

``` {.lua}
Component "channels.example.net" "muc"
modules_enabled = { "muc_http_defaults" }
muc_create_api_url = "https://api.example.net/muc/config?jid={room.jid}"
```

# API

A RESTful JSON API is used. Any error causes the room to be destroyed.

The returned JSON consists of two main parts, the room configuration and
the affiliations (member list).

## Schema

Here's a JSON Schema in YAML format describing the expected JSON
response data:

``` {.yaml}
---
type: object
properties:
  config:
    type: object
    properties:
      name: string
      description: string
      language: string
      persistent: boolean
      public: boolean
      members_only: boolean
      allow_member_invites: boolean
      public_jids: boolean
      subject: string
      changesubject: boolean
      historylength: integer
      moderated: boolean
      archiving: boolean
  affiliations:
    anyOf:
    - type: array
      items:
        type: object
        required:
        - jid
        - affiliation
        properties:
          jid:
            type: string
            pattern: ^[^@/]+@[^/]+$
          affiliation:
            ref: '#/definitions/affiliation'
          nick: string
    - type: object
      patternProperties:
        ^[^@/]+@[^/]+$: '#/definitions/affiliation'
definitions:
  affiliation:
    type: string
    enum:
    - owner
    - admin
    - member
    - none
    - outcast
...
```

## Example

A basic example with some config settings and a few affiliations:

``` {.json}
GET /muc/config?jid=place@channels.example.net
Accept: application/json

HTTP/1.1 200 OK
Content-Type: application/json

{
   "affiliations" : [
      {
         "affiliation" : "owner",
         "jid" : "bosmang@example.net",
         "nick" : "bosmang"
      },
      {
         "affiliation" : "admin",
         "jid" : "xo@example.net",
         "nick" : "xo"
      },
      {
         "affiliation" : "member",
         "jid" : "john@example.net"
      }
   ],
   "config" : {
      "archiving" : true,
      "description" : "This is the place",
      "members_only" : true,
      "moderated" : false,
      "name" : "The Place",
      "persistent" : true,
      "public" : false,
      "subject" : "Discussions regarding The Place"
   }
}
```

To allow the creation without making any changes, letting whoever
created it be the owner, just return an empty JSON object:

    HTTP/1.1 200 OK
    Content-Type: application/json

    {}

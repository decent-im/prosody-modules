---
labels:
- 'Statistics'
...

Exposes server information over Pub/Sub per ProtoXEP: PubSub Server Information.

The module announces support (used to 'opt-in', per the XEP) and publishes the name of the local domain via a Pub/Sub node. The published data
will contain a 'remote-domain' element for inbound and outgoing s2s connections. These elements will be named only when the remote domain announces
support ('opts in') too.

Installation
============

Enable this module in the global or a virtual host.

The default configuration requires the existence of a Pub/Sub component that uses the 'pubsub' subdomain of the host in which the module is enabled:

    Component "pubsub.example.org" "pubsub"

The module will create a node and publish data, using a JID that matches the XMPP domain name of the host. Ensure that this actor is an admin of the
Pub/Sub service:

    admins = { "example.org" }

Configuration
=============

The Pub/Sub service on which data is published, by default, is a component addressed as the `pubsub` subdomain of the domain of the virtual host that
the module is loaded under. To change this, apply this configuration setting:

    pubsub_serverinfo_service = "anotherpubsub.example.org"

The Pub/Sub node on which data is published is, by default, a leaf-node named `serverinfo`. To change this, apply this configuration setting:

    pubsub_serverinfo_node = "foobar"

To prevent a surplus of event notifications, this module will only publish new data after a certain period of time has expired. The default duration
is 300 seconds (5 minutes). To change this simply put in the config:

    pubsub_serverinfo_publication_interval = 180 -- or any other number of seconds

To detect if remote domains allow their domain name to be included in the data that this module publishes, this module will perform a service
discovery request to each remote domain. To prevent a continuous flood of disco/info requests, the response to these requests is cached. By default,
a cached value will remain in cache for one hour. This duration can be modified by adding this configuration option:

    pubsub_serverinfo_cache_ttl = 1800 -- or any other number of seconds

Known Issues / TODOs
====================

The reported data does not contain the optional 'connection' child elements. These can be used to describe the direction of a connection.

More generic server information (eg: user counts, software version) should be included in the data that is published.

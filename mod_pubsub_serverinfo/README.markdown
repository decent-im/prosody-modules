---
labels:
- 'Statistics'
...

Exposes server information over Pub/Sub per ProtoXEP: PubSub Server Information.

This version, announces support (used to 'opt-in', per the XEP) and publishes the name of the local domain via a Pub/Sub node. The published data
will contain an unnamed 'remote-domain' element for each inbound or outgoing s2s connection.

Features yet to be implemented:
- For 'remote-domain' elements, add domain name _only if_ through service discovery that domain advertises the 'urn:xmpp:serverinfo:0' feature.

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

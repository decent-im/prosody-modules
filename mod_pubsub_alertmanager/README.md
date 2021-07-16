---
labels:
- 'Stage-Alpha'
summary: Alertmanager webhook receiver for pubsub
---

# Introduction

This module lets
[Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/)
publish alerts to [pubsub][doc:pubsub] via
[webhooks](https://prometheus.io/docs/alerting/latest/configuration/#webhook_config).

# Setup

The relevant pubsub nodes must be created and configured somehow.
Because the request IP address is used to publish, the `publisher`
affiliation should be given to the IP address Alertmanager sends
webhooks from.

# Configuration

## Prometheus

A Prometheus `rule_files` might contain something along these lines:

``` yaml
groups:
- name: Stuff
  rules:
  - alert: Down
    expr: up == 0
    for: 5m
    annotations:
      title: 'Stuff is down!'
    labels:
      severity: 'critical'
```

## Alertmanager
On the Alertmanager site the webhook configuration may look something
like this:

``` yaml
receivers:
- name: pubsub
  webhook_configs:
  - url: http://pubsub.localhost:5280/pubsub_alertmanager
```

And then finally some Alertmanager routes would point at that receiver:

``` yaml
route:
  receiver: pubsub
```

## Prosody

On the Prosody side, apart from creating and configuring the node(s)
that will be used, configure your pubsub service like this:

``` lua
Component "pubsub.example.com" "pubsub"
modules_enabled = {
    "pubsub_alertmanager",
}

-- optional extra settings:
alertmanager_body_template = [[
*ALARM!* {annotations.title?Alert} is {status}
Since {startsAt}{endsAt& until {endsAt}}
Labels: {labels%
  {idx}: {item}}
Annotations: {annotations%
  {idx}: {item}}
]]

alertmanager_node_template = "alerts/{alert.labels.severity}"
```

## All Options

Available configuration options:

`alertmanager_body_template`
:   Template for the textual representation of alerts.

`alertmanager_node_template`
:   Template for the pubsub node name, defaults to `"{path?alerts}"`

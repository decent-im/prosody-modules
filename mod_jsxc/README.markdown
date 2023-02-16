---
summary: JSXC demo
---

Try out JSXC easily by serving it from Prosodys built-in HTTP server.

# Configuration

mod_jsxc can be set up to either use resources from a separate HTTP
server or serve resources from Prosody's built-in HTTP server.

## Using CDN

`jsxc_cdn`
:   String. Base URL where JSXC resources are served from. Defaults to
    empty string.

`jsxc_version`
:   String. Concatenated with the CDN URL. Defaults to empty string.

## Local resources

Download a JSXC release archive and unpack it somewhere on your server.

`jsxc_resources`
:   String. Path to JSXC resources on the local file system. The target
    directory should contain a `dist` directory. Disabled by default.

## Other options

`jquery_url`
:   String. URL or relative path to jQuery. Defaults to
    `"/share/jquery/jquery.min.js"` which will work with
    [mod_http_libjs].

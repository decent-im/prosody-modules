---
labels:
- 'Stage-Alpha'
summary: Manually configure extended service discovery info
...

XEP-0128 defines a way for servers to provide custom information via service
discovery. Various XEPs and plugins make use of this functionality, so that
e.g. clients can look up necessary information.

This module allows the admin to manually configure service discovery
extensions in the config file. It may be useful as a way to advertise certain
information.

Everything configured here is publicly visible to other XMPP entities.

## Configuration

The `server_info` option accepts a list of dataforms. A dataform is an array
of fields. A field has three required properties:

- `type` - usually `text-single` or `list-multi`
- `var` - the field name
- `value` the field value

Example configuration:

``` lua
server_info = {

	-- Our custom form
	{
		-- Conventionally XMPP dataforms have a 'FORM_TYPE' field to
		-- indicate what type of form it is
		{ type = "hidden", var = "FORM_TYPE", value = "urn:example:foo" };

		-- Advertise that our maximum speed is 88 mph
		{ type = "text-single", var = "speed", value = "88" };

		-- Advertise that the time is 1:20 AM and zero seconds
		{ type = "text-single", var = "time", value = "01:21:00" };
	};

}
```

## Compatibility

This module should be compatible with Prosody 0.12, and possibly earlier
versions.

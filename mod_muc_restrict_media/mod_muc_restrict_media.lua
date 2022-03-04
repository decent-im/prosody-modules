module:depends"muc";

local restrict_by_default = module:get_option_boolean("muc_room_default_restrict_media", true);

local function should_restrict_media(room)
	local restrict_media = room._data.restrict_media;
	if restrict_media == nil then
		restrict_media = restrict_by_default;
	end
	return restrict_media;
end

module:hook("muc-config-form", function(event)
	local room, form = event.room, event.form;
	table.insert(form, {
		name = "{xmpp:prosody.im}muc#roomconfig_unaffiliated_media",
		type = "boolean",
		label = "Display inline media (images, etc.) from non-members",
		value = not should_restrict_media(room),
	});
end);

module:hook("muc-config-submitted", function(event)
	local room, fields, changed = event.room, event.fields, event.changed;
	local new_restrict_media = not fields["{xmpp:prosody.im}muc#roomconfig_unaffiliated_media"];
	if new_restrict_media ~= should_restrict_media(room) then
		if new_restrict_media == restrict_by_default(room) then
			room._data.restrict_media = nil;
		else
			room._data.restrict_media = new_restrict_media;
		end
		if type(changed) == "table" then
			changed["{xmpp:prosody.im}muc#roomconfig_unaffiliated_media"] = true;
		else
			event.changed = true;
		end
	end
end);

module:hook("muc-disco#info", function (event)
	local room, form, formdata = event.room, event.form, event.formdata;

	local allow_unaffiliated_media = not should_restrict_media(room);
	table.insert(form, {
		name = "{xmpp:prosody.im}muc#roomconfig_unaffiliated_media",
		type = "boolean",
	});
	formdata["{xmpp:prosody.im}muc#roomconfig_unaffiliated_media"] = allow_unaffiliated_media;
end);

local function filter_media_tags(tag)
	local xmlns = tag.attr.xmlns;
	if xmlns == "jabber:x:oob" then
		return nil;
	elseif xmlns == "urn:xmpp:reference:0" then
		if tag:get_child("media-sharing", "urn:xmpp:sims:1") then
			return nil;
		end
	end
	return tag;
end

module:hook("muc-occupant-groupchat", function (event)
	local stanza = event.stanza;
	if stanza.attr.type ~= "groupchat" then return; end
	if should_restrict_media(event.room) then
		stanza:maptags(filter_media_tags);
	end
end, 20);

-- Password policy enforcement for Prosody
--
-- Copyright (C) 2012 Waqas Hussain
--
--
-- Configuration:
--    password_policy = {
--        length = 8;
--    }


local options = module:get_option("password_policy");

options = options or {};
options.length = options.length or 8;
if options.exclude_username == nil then
	options.exclude_username = true;
end

local st = require "util.stanza";

function check_password(password, additional_info)
	if not password or password == "" then
		return nil, "No password provided", "no-password";
	end

	if #password < options.length then
		return nil, ("Password is too short (minimum %d characters)"):format(options.length), "length";
	end

	if additional_info then
		local username = additional_info.username;
		if username and password:lower():find(username:lower(), 1, true) then
			return nil, "Password must not include your username", "username";
		end
	end
	return true;
end

function get_policy() --luacheck: ignore 131/get_policy
	return options;
end

function handler(event)
	local origin, stanza = event.origin, event.stanza;

	if stanza.attr.type == "set" then
		local query = stanza.tags[1];

		local passwords = {};

		local dataform = query:get_child("x", "jabber:x:data");
		if dataform then
			for _,tag in ipairs(dataform.tags) do
				if tag.attr.var == "password" then
					table.insert(passwords, tag:get_child_text("value"));
				end
			end
		end

		table.insert(passwords, query:get_child_text("password"));

		local additional_info = {
			username = origin.username;
		};

		for _,password in ipairs(passwords) do
			if password then
				local pw_ok, pw_err, pw_failed_policy = check_password(password, additional_info);
				if not pw_ok then
					module:log("debug", "Password failed check against '%s' policy", pw_failed_policy);
					origin.send(st.error_reply(stanza, "cancel", "not-acceptable", pw_err));
					return true;
				end
			end
		end
	end
end

module:hook("iq/self/jabber:iq:register:query", handler, 10);
module:hook("iq/host/jabber:iq:register:query", handler, 10);
module:hook("stanza/iq/jabber:iq:register:query", handler, 10);

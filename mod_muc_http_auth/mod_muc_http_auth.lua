local wait_for = require "util.async".wait_for;
local http = require "net.http";
local json = require "util.json";
local st = require "util.stanza";
local jid_node = require "util.jid".node;
local jid_bare = require "util.jid".bare;

local authorization_url = module:get_option("muc_http_auth_url", "")
local enabled_for = module:get_option_set("muc_http_auth_enabled_for",  nil)
local disabled_for = module:get_option_set("muc_http_auth_disabled_for",  nil)
local insecure = module:get_option("muc_http_auth_insecure", false) --For development purposes

local function must_be_authorized(room_node)
	-- If none of these is set, all rooms need authorization
	if not enabled_for and not disabled_for then return true; end

	if enabled_for and not disabled_for then
		for _, _room_node in ipairs(enabled_for) do
			if _room_node == room_node then
				return true;
			end
		end
	end

	if disabled_for and not enabled_for then
		for _, _room_node in ipairs(disabled_for) do
			if _room_node == room_node then
				return false;
			end
		end
	end

	return true;
end

local function handle_success(response)
	local body = json.decode(response.body or "") or {}
	response = {
		err = body.error,
		allowed = body.allowed,
		code = response.code
	}
	return {response=response, err=response.err};
end

local function handle_error(err)
	return {err=err};
end

local function handle_presence(event)
	local stanza = event.stanza;
	if stanza.name ~= "presence" or stanza.attr.type == "unavailable" then
		return;
	end

	local room, origin = event.room, event.origin;
	if (not room) or (not origin) then return; end

	if not must_be_authorized(jid_node(room.jid)) then return; end

	local user_bare_jid = jid_bare(stanza.attr.from);
	local url = authorization_url .. "?userJID=" .. user_bare_jid .."&mucJID=" .. room.jid;

	local result = wait_for(http.request(url, {method="GET", insecure=insecure}):next(handle_success, handle_error));
	local response, err = result.response, result.err;

	if not (response and response.allowed) then
		-- User is not authorized to join this room
		err = (response or {}).err or err
		module:log("debug", user_bare_jid .. " is not authorized to join " .. room.jid .. " Error: " .. tostring(err));
		origin.send(st.error_reply(stanza, "error", "not-authorized", nil, module.host));
		return true;
	end

	module:log("debug", user_bare_jid .. " is authorized to join " .. room.jid);
	return;
end


module:hook("muc-occupant-pre-join", handle_presence);
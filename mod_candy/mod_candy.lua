-- mod_candy.lua
-- Copyright (C) 2013-2017 Kim Alvefur

local json_encode = require"util.json".encode;
local get_host_children = require "core.hostmanager".get_children;
local is_module_loaded = require "core.modulemanager".is_loaded;

local serve = module:depends"http_files".serve;

local candy_rooms = module:get_option_array("candy_rooms");

local function get_autojoin()
	if candy_rooms then
		-- Configured room list, if any
		return candy_rooms;
	end
	for subdomain in pairs(get_host_children(module.host)) do
		-- Attempt autodetect a MUC host
		if is_module_loaded(subdomain, "muc") then
			return { "candy@" .. subdomain }
		end
	end
	-- Autojoin bookmarks then?
	-- Check out mod_default_bookmarks
	return true;
end

local function get_connect_path()
	if is_module_loaded(module.host, "websocket") then
		return module:http_url("websocket", "xmpp-websocket"):gsub("^http", "ws");
	end
	if not is_module_loaded(module.host, "bosh") then
		module:depends("bosh");
	end
	return module:http_url("bosh", "/http-bind");
end

module:provides("http", {
	route = {
		["GET /prosody.js"] = function(event)
			event.response.headers.content_type = "text/javascript";

			return ("// Generated by Prosody\n"
				.."var Prosody = %s;\n")
					:format(json_encode({
						connect_path = get_connect_path();
						autojoin = get_autojoin();
						version = prosody.version;
						host = module:get_host();
						anonymous = module:get_option_string("authentication") == "anonymous";
					}));
		end;
		["GET /*"] = serve(module:get_directory().."/www_files");
		GET = function(event)
			event.response.headers.location = event.request.path.."/";
			return 301;
		end;
	}
});


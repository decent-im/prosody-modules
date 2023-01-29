module:set_global();

local json = require "util.json";
local datetime = require "util.datetime".datetime;

local modulemanager = require "core.modulemanager";

module:provides("http", {
	route = {
		GET = function(event)
			local request, response = event.request, event.response;
			response.headers.content_type = "application/json";

			local resp = { ["*"] = true };

			for host in pairs(prosody.hosts) do
				resp[host] = true;
			end

			for host in pairs(resp) do
				local hostmods = {};
				local mods = modulemanager.get_modules(host);
				for mod_name, mod in pairs(mods) do
					hostmods[mod_name] = {
						type = mod.module.status_type;
						message = mod.module.status_message;
						time = datetime(math.floor(mod.module.status_time));
					};
				end
				resp[host] = hostmods;
			end

			return json.encode(resp);
		end;
	};
});

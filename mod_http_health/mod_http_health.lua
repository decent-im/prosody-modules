module:set_global();


local modulemanager = require "core.modulemanager";

module:provides("http", {
	route = {
		GET = function()
			for host in pairs(prosody.hosts) do
				local mods = modulemanager.get_modules(host);
				for _, mod in pairs(mods) do
					if mod.module.status_type == "error" then
						return { status_code = 500; headers = { content_type = "text/plain" }; body = "HAS ERRORS\n" };
					end
				end
			end

			return { status_code = 200; headers = { content_type = "text/plain" }; body = "OK\n" };
		end;
	};
});

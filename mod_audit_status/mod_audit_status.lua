module:depends("audit");

-- Suppress warnings about module:audit()
-- luacheck: ignore 143/module

local heartbeat_interval = module:get_option_number("audit_status_heartbeat_interval", 60);

local store = module:open_store(nil, "keyval+");

module:hook_global("server-started", function ()
	local recorded_status = store:get();
	if recorded_status.status == "started" then
		module:audit(nil, "server-crashed", { timestamp = recorded_status.heartbeat });
	end
	module:audit(nil, "server-started");
	store:set_key(nil, "status", "started");
end);

module:hook_global("server-stopped", function ()
	module:audit(nil, "server-stopped");
	store:set_key(nil, "status", "stopped");
end);

if heartbeat_interval then
	module:add_timer(0, function ()
		store:set_key(nil, "heartbeat", os.time());
		return heartbeat_interval;
	end);
end

local store = module:open_store("lastlog2");

local measure_d1 = module:measure("active_users_1d", "amount");
local measure_d7 = module:measure("active_users_7d", "amount");
local measure_d30 = module:measure("active_users_30d", "amount");

function update_calculations()
	module:log("debug", "Calculating active users");
	local host_user_sessions = prosody.hosts[module.host].sessions;
	local active_d1, active_d7, active_d30 = 0, 0, 0;
	local now = os.time();
	for username in store:users() do
		if host_user_sessions[username] then
			-- Active now
			active_d1, active_d7, active_d30 =
				active_d1 + 1, active_d7 + 1, active_d30 + 1;
		else
			local lastlog_data = store:get(username);
			if lastlog_data then
				-- Due to server restarts/crashes/etc. some events
				-- may not always get recorded, so we'll just take the
				-- latest as a sign of last activity
				local last_active = math.max(
					lastlog_data.login and lastlog_data.login.timestamp or 0,
					lastlog_data.logout and lastlog_data.logout.timestamp or 0
				);
				if now - last_active < 86400 then
					active_d1 = active_d1 + 1;
				end
				if now - last_active < 86400*7 then
					active_d7 = active_d7 + 1;
				end
				if now - last_active < 86400*30 then
					active_d30 = active_d30 + 1;
				end
			end
		end
	end
	module:log("debug", "Active users (took %ds): %d (24h), %d (7d), %d (30d)", os.time()-now, active_d1, active_d7, active_d30);
	measure_d1(active_d1);
	measure_d7(active_d7);
	measure_d30(active_d30);

	return 3600 + (300*math.random());
end

module:add_timer(15, update_calculations);

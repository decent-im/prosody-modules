local usermanager = require "core.usermanager";

local id = require "util.id";
local json = require "util.json";

module:depends("http");

local invites = module:depends("invites");
local tokens = module:depends("tokenauth");
local mod_pep = module:depends("pep");

local group_info_store = module:open_store("group_info");
local group_members_store = module:open_store("groups");
local group_memberships = module:open_store("groups", "map");
local push_errors = module:shared("cloud_notify/push_errors");

local site_name = module:get_option_string("site_name", module.host);

local json_content_type = "application/json";

local www_authenticate_header = ("Bearer realm=%q"):format(module.host.."/"..module.name);

local function check_credentials(request)
	local auth_type, auth_data = string.match(request.headers.authorization or "", "^(%S+)%s(.+)$");
	if not (auth_type and auth_data) then
		return false;
	end

	if auth_type == "Bearer" then
		local token_info = tokens.get_token_info(auth_data);
		if not token_info or not token_info.session then
			return false;
		end
		return token_info.session;
	end
	return nil;
end

function check_auth(routes)
	local function check_request_auth(event)
		local session = check_credentials(event.request);
		if not session then
			event.response.headers.authorization = www_authenticate_header;
			return false, 401;
		elseif session.auth_scope ~= "prosody:scope:admin" then
			return false, 403;
		end
		event.session = session;
		return true;
	end

	for route, handler in pairs(routes) do
		routes[route] = function (event, ...)
			local permit, code = check_request_auth(event);
			if not permit then
				return code;
			end
			return handler(event, ...);
		end;
	end
	return routes;
end

local function token_info_to_invite_info(token_info)
	local additional_data = token_info.additional_data;
	local groups = additional_data and additional_data.groups or nil;
	local source = additional_data and additional_data.source or nil;
	return {
		id = token_info.token;
		type = token_info.type;
		reusable = not not token_info.reusable;
		inviter = token_info.inviter;
		jid = token_info.jid;
		uri = token_info.uri;
		landing_page = token_info.landing_page;
		created_at = token_info.created_at;
		expires = token_info.expires;
		groups = groups;
		source = source;
	};
end

function list_invites(event)
	local invites_list = {};
	for token, invite in invites.pending_account_invites() do --luacheck: ignore 213/token
		table.insert(invites_list, token_info_to_invite_info(invite));
	end
	table.sort(invites_list, function (a, b)
		return a.created_at < b.created_at;
	end);

	event.response.headers["Content-Type"] = json_content_type;
	return json.encode_array(invites_list);
end

function get_invite_by_id(event, invite_id)
	local invite = invites.get_account_invite_info(invite_id);
	if not invite then
		return 404;
	end

	event.response.headers["Content-Type"] = json_content_type;
	return json.encode(token_info_to_invite_info(invite));
end

function create_invite(event)
	local invite_options;

	local request = event.request;
	if request.body and #request.body > 0 then
		if request.headers.content_type ~= json_content_type then
			module:log("warn", "Invalid content type");
			return 400;
		end
		invite_options = json.decode(event.request.body);
		if not invite_options then
			module:log("warn", "Invalid JSON");
			return 400;
		end
	else
		invite_options = {};
	end

	local invite;
	if invite_options.reusable then
		invite = invites.create_group(invite_options.groups, invite_options.ttl, {
			source = "admin_api/"..event.session.username;
		});
	else
		invite = invites.create_account(nil, {
			source = "admin_api/"..event.session.username;
			groups = invite_options.groups;
		});
	end
	if not invite then
		return 500;
	end

	event.response.headers["Content-Type"] = json_content_type;
	return json.encode(token_info_to_invite_info(invite));
end

function delete_invite(event, invite_id) --luacheck: ignore 212/event
	if not invites.delete_account_invite(invite_id) then
		return 404;
	end
	return 200;
end

local function get_user_info(username)
	if not usermanager.user_exists(username, module.host) then
		return nil;
	end
	local display_name;
	do
		local pep_service = mod_pep.get_pep_service(username);
		local ok, _, nick_item = pep_service:get_last_item("http://jabber.org/protocol/nick", true);
		if ok and nick_item then
			display_name = nick_item:get_child_text("nick", "http://jabber.org/protocol/nick");
		end
	end

	return {
		username = username;
		display_name = display_name;
	};
end

local function get_session_debug_info(session)
	local info = {
		full_jid = session.full_jid;
		ip = session.ip;
		since = math.floor(session.conntime);
		status = {
			connected = not not session.conn;
			hibernating = not not session.hibernating;
		};
		features = {
			carbons = not not session.want_carbons;
			encrypted = not not session.secure;
			acks = not not session.smacks;
			resumption = not not session.resumption_token;
			mobile_optimization = not not session.csi_counter;
			push_notifications = not not session.push_identifier;
			history = not not session.mam_requested;
		};
		queues = {};
	};
	-- CSI
	if session.state then
		info.status.active = session.state == "active";
		info.queues.held_stanzas = session.csi_counter or 0;
	end
	-- Smacks queue
	if session.last_requested_h and session.last_acknowledged_stanza then
		info.queues.awaiting_acks = session.last_requested_h - session.last_acknowledged_stanza;
	end
	if session.push_identifier then
		info.push_info = {
			id = session.push_identifier;
			wakeup_push_sent = session.first_hibernated_push;
		};
	end
	return info;
end

local function get_user_omemo_info(username)
	local everything_valid = true;
	local any_device = false;
	local omemo_status = {};
	local omemo_devices;
	local pep_service = mod_pep.get_pep_service(username);
	if pep_service and pep_service.nodes then
		local ok, _, device_list = pep_service:get_last_item("eu.siacs.conversations.axolotl.devicelist", true);
		if ok and device_list then
			device_list = device_list:get_child("list", "eu.siacs.conversations.axolotl");
		end
		if device_list then
			omemo_devices = {};
			for device_entry in device_list:childtags("device") do
				any_device = true;
				local device_info = {};
				local device_id = tonumber(device_entry.attr.id or "");
				if device_id then
					device_info.id = device_id;
					local bundle_id = ("eu.siacs.conversations.axolotl.bundles:%d"):format(device_id);
					local have_bundle, _, bundle = pep_service:get_last_item(bundle_id, true);
					if have_bundle and bundle and bundle:get_child("bundle", "eu.siacs.conversations.axolotl") then
						device_info.have_bundle = true;
						local config_ok, bundle_config = pep_service:get_node_config(bundle_id, true);
						if config_ok and bundle_config then
							device_info.bundle_config = bundle_config;
							if bundle_config.max_items == 1
							and bundle_config.access_model == "open"
							and bundle_config.persist_items == true
							and bundle_config.publish_model == "publishers" then
								device_info.valid = true;
							end
						end
					end
				end
				if device_info.valid == nil then
					device_info.valid = false;
					everything_valid = false;
				end
				table.insert(omemo_devices, device_info);
			end

			local config_ok, list_config = pep_service:get_node_config("eu.siacs.conversations.axolotl.devicelist", true);
			if config_ok and list_config then
				omemo_status.config = list_config;
				if list_config.max_items == 1
				and list_config.access_model == "open"
				and list_config.persist_items == true
				and list_config.publish_model == "publishers" then
					omemo_status.config_valid = true;
				end
			end
			if omemo_status.config_valid == nil then
				omemo_status.config_valid = false;
				everything_valid = false;
			end
		end
	end
	omemo_status.valid = everything_valid and any_device;
	return {
		status = omemo_status;
		devices = omemo_devices;
	};
end

local function get_user_debug_info(username)
	local debug_info = {
		time = os.time();
	};
	-- Online sessions
	do
		local user_sessions = hosts[module.host].sessions[username];
		if user_sessions then
			user_sessions = user_sessions.sessions
		end
		local sessions = {};
		if user_sessions then
			for _, session in pairs(user_sessions) do
				table.insert(sessions, get_session_debug_info(session));
			end
		end
		debug_info.sessions = sessions;
	end
	-- Push registrations
	do
		local store = module:open_store("cloud_notify");
		local services = store:get(username);
		local push_registrations = {};
		if services then
			for identifier, push_info in pairs(services) do
				push_registrations[identifier] = {
					since = push_info.timestamp;
					service = push_info.jid;
					node = push_info.node;
					error_count = push_errors[identifier] or 0;
				};
			end
		end
		debug_info.push_registrations = push_registrations;
	end
	-- OMEMO
	debug_info.omemo = get_user_omemo_info(username);

	return debug_info;
end

local function get_user_groups(username)
	local groups;
	do
		local group_set = group_memberships:get_all(username);
		if group_set and next(group_set) then
			groups = {};
			for group_id in pairs(group_set) do
				table.insert(groups, group_id);
			end
		end
	end
	return groups;
end

function list_users(event)
	local user_list = {};
	for username in usermanager.users(module.host) do
		table.insert(user_list, get_user_info(username));
	end

	event.response.headers["Content-Type"] = json_content_type;
	return json.encode_array(user_list);
end

function get_user_by_name(event, username)
	local property
	do
		local name, sub_path = username:match("^([^/]+)/(%w+)$");
		if name then
			username = name;
			property = sub_path;
		end
	end

	if property == "groups" then
		event.response.headers["Content-Type"] = json_content_type;
		return json.encode(get_user_groups(username));
	elseif property == "debug" then
		event.response.headers["Content-Type"] = json_content_type;
		return json.encode(get_user_debug_info(username));
	end

	local user_info = get_user_info(username);
	if not user_info then
		return 404;
	end

	event.response.headers["Content-Type"] = json_content_type;
	return json.encode(user_info);
end

function delete_user(event, username) --luacheck: ignore 212/event
	if not usermanager.delete_user(username, module.host) then
		return 404;
	end
	return 200;
end

function list_groups(event)
	local group_list = {};
	for group_id in group_info_store:users() do
		local group_info = group_info_store:get(group_id);
		table.insert(group_list, {
			id = group_id;
			name = group_info.name;
			members = group_members_store:get(group_id);
		});
	end

	event.response.headers["Content-Type"] = json_content_type;
	return json.encode_array(group_list);
end

function get_group_by_id(event, group_id)
	local group = group_info_store:get(group_id);
	if not group then
		return 404;
	end

	event.response.headers["Content-Type"] = json_content_type;

	return json.encode({
		id = group_id;
		name = group.name;
		members = group_members_store:get(group_id);
	});
end

function create_group(event)
	local request = event.request;
	if request.headers.content_type ~= json_content_type
	or (not request.body or #request.body == 0) then
		return 400;
	end
	local group = json.decode(event.request.body);
	if not group then
		return 400;
	end

	if not group.name then
		module:log("warn", "Group missing name property");
		return 400;
	end

	local group_id = id.short();

	local ok = group_info_store:set(group_id, {
		name = group.name;
	});
	if not ok then
		return 500;
	end

	event.response.headers["Content-Type"] = json_content_type;
	return json.encode({
		id = group_id;
		name = group.name;
		members = {};
	});
end

function update_group(event, group) --luacheck: ignore 212/event
	local group_id, member_name = group:match("^([^/]+)/members/([^/]+)$");
	if group_id and member_name then
		if not group_info_store:get(group_id) then
			return 404;
		elseif not group_memberships:set(group_id, member_name, true) then
			return 500;
		end
		return 204;
	end

	local group_id = group:match("^([^/]+)$")
	if group_id then
		local request = event.request;
		if request.headers.content_type ~= json_content_type
		or (not request.body or #request.body == 0) then
			return 400;
		end

		local update = json.decode(event.request.body);
		if not update then
			return 400;
		end

		local group_info = group_info_store:get(group_id);
		if not group_info then
			return 404;
		end

		if update.name then
			group_info["name"] = update.name
		end
		group_info_store:set(group_id, group_info);
		return 204;
	end
	return 400;
end

function delete_group(event, subpath) --luacheck: ignore 212/event
	-- Check if this is a membership deletion and handle it
	local group_id, member_name = subpath:match("^([^/]+)/members/([^/]+)$");
	if group_id and member_name then
		if not group_info_store:get(group_id) then
			return 404;
		end
		if group_memberships:set(group_id, member_name, nil) then
			return 200;
		else
			return 500;
		end
	else
		group_id = subpath;
	end

	if not group_id then
		return 400;
	end

	if not group_info_store:get(group_id) then
		return 404;
	end

	if not group_members_store:set(group_id, nil) then
		return 500;
	else
		if not group_info_store:set(group_id, nil) then
			return 500;
		end
	end
	return 200;
end

local function get_server_info(event)
	event.response.headers["Content-Type"] = json_content_type;
	return json.encode({
		site_name = site_name;
		version = prosody.version;
	});
end

module:provides("http", {
	route = check_auth {
		["GET /invites"] = list_invites;
		["GET /invites/*"] = get_invite_by_id;
		["POST /invites"] = create_invite;
		["DELETE /invites/*"] = delete_invite;

		["GET /users"] = list_users;
		["GET /users/*"] = get_user_by_name;
		["DELETE /users/*"] = delete_user;

		["GET /groups"] = list_groups;
		["GET /groups/*"] = get_group_by_id;
		["POST /groups"] = create_group;
		["PUT /groups/*"] = update_group;
		["DELETE /groups/*"] = delete_group;

		["GET /server/info"] = get_server_info;
	};
});

local usermanager = require "core.usermanager";

local json = require "util.json";

module:depends("http");

local invites = module:depends("invites");
local tokens = module:depends("tokenauth");
local mod_pep = module:depends("pep");

local group_store = module:open_store("groups");
local group_memberships = module:open_store("groups", "map");

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
	end

	local invite;
	if invite_options and invite_options.reusable then
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

	return {
		username = username;
		display_name = display_name;
		groups = groups;
	};
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
	for group_id in group_store:users() do
		table.insert(group_list, {
			id = group_id;
			name = group_id;
		});
	end

	event.response.headers["Content-Type"] = json_content_type;
	return json.encode_array(group_list);
end

function get_group_by_id(event, group_id)
	local property;
	do
		local id, sub_path = group_id:match("^[^/]+/(%w+)$");
		if id then
			group_id = id;
			property = sub_path;
		end
	end

	local group = group_store:get(group_id);
	if not group then
		return 404;
	end

	event.response.headers["Content-Type"] = json_content_type;

	if property == "members" then
		return json.encode(group);
	end

	return json.encode({
		id = group_id;
		name = group_id;
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

	local ok = group_store:set(group.id, {});
	if not ok then
		return 500;
	end
	return 200;
end

function delete_group(event, group_id) --luacheck: ignore 212/event
	if not group_id then
		return 400;
	end
	if not group_store:set(group_id, nil) then
		return 500;
	end
	return 200;
end

module:provides("http", {
	route = check_auth {
		["GET /invites"] = list_invites;
		["GET /invites/*"] = get_invite_by_id;
		["PUT /invites"] = create_invite;
		["DELETE /invites/*"] = delete_invite;

		["GET /users"] = list_users;
		["GET /users/*"] = get_user_by_name;
		["DELETE /users/*"] = delete_user;

		["GET /groups"] = list_groups;
		["GET /groups/*"] = get_group_by_id;
		["PUT /groups"] = create_group;
		["DELETE /groups/*"] = delete_group;
	};
});

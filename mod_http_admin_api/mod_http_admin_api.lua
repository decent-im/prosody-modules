local usermanager = require "core.usermanager";

local json = require "util.json";

module:depends("http");

local invites = module:depends("invites");
local tokens = module:depends("tokenauth");
local mod_pep = module:depends("pep");

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
	return {
		id = token_info.token;
		type = token_info.type;
		inviter = token_info.inviter;
		jid = token_info.jid;
		landing_page = token_info.landing_page;
		created_at = token_info.created_at;
		expires = token_info.expires;
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
	return json.encode(invites_list);
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
	local invite = invites.create_account(nil, { source = "admin_api/"..event.session.username });
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

function list_users(event)
	local user_list = {};
	for username in usermanager.users(module.host) do
		table.insert(user_list, get_user_info(username));
	end

	event.response.headers["Content-Type"] = json_content_type;
	return json.encode(user_list);
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

module:provides("http", {
	route = check_auth {
		["GET /invites"] = list_invites;
		["GET /invites/*"] = get_invite_by_id;
		["PUT /invites"] = create_invite;
		["DELETE /invites/*"] = delete_invite;

		["GET /users"] = list_users;
		["GET /users/*"] = get_user_by_name;
		["DELETE /users/*"] = delete_user;
	};
});

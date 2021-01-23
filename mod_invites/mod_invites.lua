local id = require "util.id";
local it = require "util.iterators";
local url = require "socket.url";
local jid_node = require "util.jid".node;
local jid_split = require "util.jid".split;

local default_ttl = module:get_option_number("invite_expiry", 86400 * 7);

local token_storage;
if prosody.process_type == "prosody" or prosody.shutdown then
	token_storage = module:open_store("invite_token", "map");
end

local function get_uri(action, jid, token, params) --> string
	return url.build({
			scheme = "xmpp",
			path = jid,
			query = action..";preauth="..token..(params and (";"..params) or ""),
		});
end

local function create_invite(invite_action, invite_jid, allow_registration, additional_data, ttl, reusable)
	local token = id.medium();

	local created_at = os.time();
	local expires = created_at + (ttl or default_ttl);

	local invite_params = (invite_action == "roster" and allow_registration) and "ibr=y" or nil;

	local invite = {
		type = invite_action;
		jid = invite_jid;

		token = token;
		allow_registration = allow_registration;
		additional_data = additional_data;

		uri = get_uri(invite_action, invite_jid, token, invite_params);

		created_at = created_at;
		expires = expires;

		reusable = reusable;
	};

	module:fire_event("invite-created", invite);

	if allow_registration then
		local ok, err = token_storage:set(nil, token, invite);
		if not ok then
			module:log("warn", "Failed to store account invite: %s", err);
			return nil, "internal-server-error";
		end
	end

	if invite_action == "roster" then
		local username = jid_node(invite_jid);
		local ok, err = token_storage:set(username, token, expires);
		if not ok then
			module:log("warn", "Failed to store subscription invite: %s", err);
			return nil, "internal-server-error";
		end
	end

	return invite;
end

-- Create invitation to register an account (optionally restricted to the specified username)
function create_account(account_username, additional_data) --luacheck: ignore 131/create_account
	local jid = account_username and (account_username.."@"..module.host) or module.host;
	return create_invite("register", jid, true, additional_data);
end

-- Create invitation to reset the password for an account
function create_account_reset(account_username) --luacheck: ignore 131/create_account_reset
	return create_account(account_username, { allow_reset = account_username });
end

-- Create invitation to become a contact of a local user
function create_contact(username, allow_registration, additional_data) --luacheck: ignore 131/create_contact
	return create_invite("roster", username.."@"..module.host, allow_registration, additional_data);
end

-- Create invitation to register an account and join a user group
-- If explicit ttl is passed, invite is valid for multiple signups
-- during that time period
function create_group(group_ids, ttl, additional_data) --luacheck: ignore 131/create_group
	local merged_additional_data = {
		groups = group_ids;
	};
	if additional_data then
		for k, v in pairs(additional_data) do
			merged_additional_data[k] = v;
		end
	end
	return create_invite("register", module.host, true, merged_additional_data, ttl, not not ttl);
end

-- Iterates pending (non-expired, unused) invites that allow registration
function pending_account_invites() --luacheck: ignore 131/pending_account_invites
	local store = module:open_store("invite_token");
	local now = os.time();
	local function is_valid_invite(_, invite)
		return invite.expires > now;
	end
	return it.filter(is_valid_invite, pairs(store:get(nil) or {}));
end

function get_account_invite_info(token) --luacheck: ignore 131/get_account_invite_info
	if not token then
		return nil, "no-token";
	end

	-- Fetch from host store (account invite)
	local token_info = token_storage:get(nil, token);
	if not token_info then
		return nil, "token-invalid";
	elseif os.time() > token_info.expires then
		return nil, "token-expired";
	end

	return token_info;
end

function delete_account_invite(token) --luacheck: ignore 131/delete_account_invite
	if not token then
		return nil, "no-token";
	end

	return token_storage:set(nil, token, nil);
end

local valid_invite_methods = {};
local valid_invite_mt = { __index = valid_invite_methods };

function valid_invite_methods:use()
	if self.reusable then
		return true;
	end

	if self.username then
		-- Also remove the contact invite if present, on the
		-- assumption that they now have a mutual subscription
		token_storage:set(self.username, self.token, nil);
	end
	token_storage:set(nil, self.token, nil);

	return true;
end

-- Get a validated invite (or nil, err). Must call :use() on the
-- returned invite after it is actually successfully used
-- For "roster" invites, the username of the local user (who issued
-- the invite) must be passed.
-- If no username is passed, but the registration is a roster invite
-- from a local user, the "inviter" field of the returned invite will
-- be set to their username.
function get(token, username)
	if not token then
		return nil, "no-token";
	end

	local valid_until, inviter;

	-- Fetch from host store (account invite)
	local token_info = token_storage:get(nil, token);

	if username then -- token being used for subscription
		-- Fetch from user store (subscription invite)
		valid_until = token_storage:get(username, token);
	else -- token being used for account creation
		valid_until = token_info and token_info.expires;
		if token_info and token_info.type == "roster" then
			username = jid_node(token_info.jid);
			inviter = username;
		end
	end

	if not valid_until then
		module:log("debug", "Got unknown token: %s", token);
		return nil, "token-invalid";
	elseif os.time() > valid_until then
		module:log("debug", "Got expired token: %s", token);
		return nil, "token-expired";
	end

	return setmetatable({
		token = token;
		username = username;
		inviter = inviter;
		type = token_info and token_info.type or "roster";
		uri = token_info and token_info.uri or get_uri("roster", username.."@"..module.host, token);
		additional_data = token_info and token_info.additional_data or nil;
		reusable = token_info.reusable;
	}, valid_invite_mt);
end

function use(token) --luacheck: ignore 131/use
	local invite = get(token);
	return invite and invite:use();
end

--- shell command
do
	-- Since the console is global this overwrites the command for
	-- each host it's loaded on, but this should be fine.

	local get_module = require "core.modulemanager".get_module;

	local console_env = module:shared("/*/admin_shell/env");

	-- luacheck: ignore 212/self
	console_env.invite = {};
	function console_env.invite:create_account(user_jid)
		local username, host = jid_split(user_jid);
		local mod_invites, err = get_module(host, "invites");
		if not mod_invites then return nil, err or "mod_invites not loaded on this host"; end
		local invite, err = mod_invites.create_account(username);
		if not invite then return nil, err; end
		return true, invite.uri;
	end

	function console_env.invite:create_contact(user_jid, allow_registration)
		local username, host = jid_split(user_jid);
		local mod_invites, err = get_module(host, "invites");
		if not mod_invites then return nil, err or "mod_invites not loaded on this host"; end
		local invite, err = mod_invites.create_contact(username, allow_registration);
		if not invite then return nil, err; end
		return true, invite.uri;
	end
end

--- prosodyctl command
function module.command(arg)
	if #arg < 2 or arg[1] ~= "generate" then
		print("usage: prosodyctl mod_"..module.name.." generate example.com");
		return;
	end
	table.remove(arg, 1); -- pop command

	local sm = require "core.storagemanager";
	local mm = require "core.modulemanager";

	local host = arg[1];
	assert(hosts[host], "Host "..tostring(host).." does not exist");
	sm.initialize_host(host);
	table.remove(arg, 1); -- pop host
	module.host = host; --luacheck: ignore 122/module
	token_storage = module:open_store("invite_token", "map");

	-- Load mod_invites
	local invites = module:depends("invites");
	local invites_page_module = module:get_option_string("invites_page_module", "invites_page");
	if mm.get_modules_for_host(host):contains(invites_page_module) then
		module:depends(invites_page_module);
	end


	local invite, roles;
	if arg[1] == "--reset" then
		local nodeprep = require "util.encodings".stringprep.nodeprep;
		local username = nodeprep(arg[2]);
		if not username then
			print("Please supply a valid username to generate a reset link for");
			return;
		end
		invite = assert(invites.create_account_reset(username));
	else
		if arg[1] == "--admin" then
			roles = { ["prosody:admin"] = true };
		elseif arg[1] == "--role" then
			roles = { [arg[2]] = true };
		end
		invite = assert(invites.create_account(nil, { roles = roles }));
	end

	print(invite.landing_page or invite.uri);
end

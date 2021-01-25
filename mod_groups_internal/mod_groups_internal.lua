local rostermanager = require"core.rostermanager";
local id = require "util.id";
local jid = require "util.jid";
local jid_join = jid.join;
local host = module.host;

local group_info_store = module:open_store("group_info");
local group_members_store = module:open_store("groups");
local group_memberships = module:open_store("groups", "map");

local is_contact_subscribed = rostermanager.is_contact_subscribed;

-- Make a *one-way* subscription. User will see when contact is online,
-- contact will not see when user is online.
local function subscribe(user, user_jid, contact, contact_jid)
	-- Update user's roster to say subscription request is pending...
	rostermanager.set_contact_pending_out(user, host, contact_jid);
	-- Update contact's roster to say subscription request is pending...
	rostermanager.set_contact_pending_in(contact, host, user_jid);
	-- Update contact's roster to say subscription request approved...
	rostermanager.subscribed(contact, host, user_jid);
	-- Update user's roster to say subscription request approved...
	rostermanager.process_inbound_subscription_approval(user, host, contact_jid);

	-- Push updates to both rosters
	rostermanager.roster_push(user, host, contact_jid);
	rostermanager.roster_push(contact, host, user_jid);
end

local function user_groups(username)
	return pairs(group_memberships:get_all(username) or {});
end

local function do_single_group_subscriptions(username, group_id)
	local members = group_members_store:get(group_id);
	if not members then return; end
	local user_jid = jid_join(username, host);
	for membername in pairs(members) do
		if membername ~= username then
			local member_jid = jid_join(membername, host);
			if not is_contact_subscribed(username, host, member_jid) then
				module:log("debug", "[group %s] Subscribing %s to %s", member_jid, user_jid);
				subscribe(membername, member_jid, username, user_jid);
			end
			if not is_contact_subscribed(membername, host, user_jid) then
				module:log("debug", "[group %s] Subscribing %s to %s", user_jid, member_jid);
				subscribe(username, user_jid, membername, member_jid);
			end
		end
	end
end

local function do_all_group_subscriptions_by_user(username)
	for group_id in user_groups(username) do
		do_single_group_subscriptions(username, group_id);
	end
end

local function do_all_group_subscriptions_by_group(group_id)
	for membername in pairs(get_members(group_id)) do
		do_single_group_subscriptions(membername, group_id);
	end
end

module:hook("resource-bind", function(event)
	module:log("debug", "Updating group subscriptions...");
	do_all_group_subscriptions_by_user(event.session.username);
end);

local function get_group_muc(group_id)
	-- Group MUC
	local group_info = group_info_store:get(group_id);
	if group_info and group_info.muc_jid then
		local muc_jid = group_info.muc_jid;
		local mod_muc = hosts[jid.host(muc_jid)].modules.muc;
		if mod_muc then
			local room = mod_muc.get_room_from_jid(muc_jid);
			if not room then
				room = mod_muc.create_room(muc_jid);
			end
			return room;
		end
	end
end

--luacheck: ignore 131
function create(group_info, create_muc, group_id)
	if not group_info.name then
		return nil, "group-name-required";
	end
	if group_id then
		if exists(group_id) then
			return nil, "conflict"
		end
	else
		group_id = id.short();
	end

	if create_muc then
		return nil, "not-implemented";
	end

	local ok = group_info_store:set(group_id, {
		name = group_info.name;
	});
	if not ok then
		return nil, "internal-server-error";
	end
	return group_id;
end

function get_info(group_id)
	return group_info_store:get(group_id);
end

function set_info(group_id, info)
	if not info then
		return nil, "bad-request"
	end

	if not info.name or #info.name == 0 then
		return nil, "bad-request"
	end

	local ok = group_info_store:set(group_id, info);
	if not ok then
		return nil, "internal-server-error";
	end
	return true
end

function get_members(group_id)
	return group_members_store:get(group_id);
end

function exists(group_id)
	return not not get_info(group_id);
end

function get_user_groups(username)
	local groups = {};
	do
		local group_set = group_memberships:get_all(username);
		if group_set then
			for group_id in pairs(group_set) do
				table.insert(groups, group_id);
			end
		end
	end
	return groups;
end

function delete(group_id)
	if group_members_store:set(group_id, nil) then
		return group_info_store:set(group_id, nil);
	end
	return nil, "internal-server-error";
end

function add_member(group_id, username, delay_update)
	local group_info = group_info_store:get(group_id);
	if not group_info then
		return nil, "group-not-found";
	end
	if not group_memberships:set(group_id, username, {}) then
		return nil, "internal-server-error";
	end
	if not delay_update then
		do_all_group_subscriptions_by_group(group_id);
	end
	return true;
end

function remove_member(group_id, username)
	local group_info = group_info_store:get(group_id);
	if not group_info then
		return nil, "group-not-found";
	end
	if not group_memberships:set(group_id, username, nil) then
		return nil, "internal-server-error";
	end
	return true;
end

function sync(group_id)
	do_all_group_subscriptions_by_group(group_id)
end

-- Returns iterator over group ids
function groups()
	return group_info_store:users();
end

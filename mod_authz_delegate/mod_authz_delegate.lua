local target_host = assert(module:get_option("authz_delegate_to"));
local this_host = module:get_host();

local jid_split = import("prosody.util.jid", "split");

local hosts = prosody.hosts;

function get_jids_with_role(role)  --luacheck: ignore 212/role
	return nil
end

function get_user_role(user)
	-- this is called where the JID belongs to the host this module is loaded on
	-- that means we have to delegate that to get_jid_role with an appropriately composed JID
	return hosts[target_host].authz.get_jid_role(user .. "@" .. this_host)
end

function set_user_role(user, role_name)  --luacheck: ignore 212/user 212/role_name
	-- no roles for entities on this host.
	return false, "cannot set user role on delegation target"
end

function get_user_secondary_roles(user)  --luacheck: ignore 212/user
	-- no roles for entities on this host.
	return {}
end

function add_user_secondary_role(user, role_name)  --luacheck: ignore 212/user 212/role_name
	-- no roles for entities on this host.
	return nil, "cannot set user role on delegation target"
end

function remove_user_secondary_role(user, role_name)  --luacheck: ignore 212/user 212/role_name
	-- no roles for entities on this host.
	return nil, "cannot set user role on delegation target"
end

function user_can_assume_role(user, role_name)  --luacheck: ignore 212/user 212/role_name
	-- no roles for entities on this host.
	return false
end

function get_jid_role(jid)
	local user, host = jid_split(jid);
	if host == target_host then
		return hosts[target_host].authz.get_user_role(user);
	end
	return hosts[target_host].authz.get_jid_role(jid);
end

function set_jid_role(jid)  --luacheck: ignore 212/jid
	-- TODO: figure out if there are actually legitimate uses for this...
	return nil, "cannot set jid role on delegation target"
end

function add_default_permission(role_name, action, policy)
	return hosts[target_host].authz.add_default_permission(role_name, action, policy)
end

function get_role_by_name(role_name)
	return hosts[target_host].authz.get_role_by_name(role_name)
end

function get_all_roles()
	return hosts[target_host].authz.get_all_roles()
end

local it = require "util.iterators";
local http = require "util.http";
local sm = require "core.storagemanager";
local st = require "util.stanza";
local xml = require "util.xml";

local tokens = module:depends("tokenauth");
module:depends("storage_xep0227");

local archive_store_name = module:get_option("archive_store", "archive");

local known_stores = {
	accounts = "keyval";
	roster = "keyval";
	private = "keyval";
	pep = "keyval";
	vcard = "keyval";

	[archive_store_name] = "archive";
	pep_data = "archive";
};

local function new_user_xml(username, host)
	local user_xml = st.stanza("server-data", {xmlns='urn:xmpp:pie:0'})
		:tag("host", { jid = host })
			:tag("user", { name = username }):reset();

	return {
		set_user_xml = function (_, store_username, store_host, new_xml)
			if username ~= store_username or store_host ~= host then
				return nil;
			end
			user_xml = new_xml;
			return true;
		end;

		get_user_xml = function (_, store_username, store_host)
			if username ~= store_username or store_host ~= host then
				return nil;
			end
			return user_xml;
		end
	};
end

local function get_selected_stores(query_params)
	local selected_kv_stores, selected_archive_stores, export_pep_data = {}, {}, false;
	if query_params.stores then
		for store_name in query_params.stores:gmatch("[^,]+") do
			local store_type = known_stores[store_name];
			if store_type == "keyval" then
				table.insert(selected_kv_stores, store_name);
			elseif store_type == "archive" then
				if store_name == "pep_data" then
					export_pep_data = true;
				else
					table.insert(selected_archive_stores, store_name);
				end
			else
				module:log("warn", "Unknown store: %s", store_name);
				return 400;
			end
		end
	end
	return {
		keyval = selected_kv_stores;
		archive = selected_archive_stores;
		export_pep_data = export_pep_data;
	};
end

local function get_config_driver(store_name, host)
	-- Fiddling to handle the 'pep_data' storage config override
	if store_name:find("pep_", 1, true) == 1 then
		store_name = "pep_data";
	end
	-- Return driver
	return sm.get_driver(host, store_name);
end

local function handle_export_227(event)
	local session = assert(event.session, "No session found");
	local xep227_driver = sm.load_driver(session.host, "xep0227");

	local username = session.username;

	local user_xml = new_user_xml(session.username, session.host);

	local query_params = http.formdecode(event.request.url.query or "");

	local selected_stores = get_selected_stores(query_params);

	for store_name in it.values(selected_stores.keyval) do
		-- Open the source store that contains the data
		local store = sm.open(session.host, store_name);
		-- Read the current data
		local data, err = store:get(username);
		if data ~= nil or not err then
			-- Initialize the destination store (XEP-0227 backed)
			local target_store = xep227_driver:open_xep0227(store_name, nil, user_xml);
			-- Transform the data and update user_xml (via the _set_user_xml callback)
			if not target_store:set(username, data == nil and {} or data) then
				return 500;
			end
		elseif err then
			return 500;
		end
	end

	if selected_stores.export_pep_data then
		local pep_node_list = sm.open(session.host, "pep"):get(session.username);
		if pep_node_list then
			for node_name in it.keys(pep_node_list) do
				table.insert(selected_stores.archive, "pep_"..node_name);
			end
		end
	end

	for store_name in it.values(selected_stores.archive) do
		local source_driver = get_config_driver(store_name, session.host);
		local source_archive = source_driver:open(store_name, "archive");
		local dest_archive = xep227_driver:open_xep0227(store_name, "archive", user_xml);
		local count, errs = 0, 0;
		for id, item, when, with in source_archive:find(username) do
			local ok, err = dest_archive:append(username, id, item, when, with);
			if ok then
				count = count + 1;
			else
				module:log("warn", "Error: %s", err);
				errs = errs + 1;
			end
			if ( count + errs ) % 100 == 0 then
				module:log("info", "%d items migrated, %d errors", count, errs);
			end
		end
	end

	local xml_data = user_xml:get_user_xml(username, session.host);

	if not xml_data or not xml_data:find("host/user") then
		module:log("warn", "No data to export: %s", tostring(xml_data));
		return 204;
	end

	event.response.headers["Content-Type"] = "application/xml";
	return [[<?xml version="1.0" encoding="utf-8" ?>]]..tostring(xml_data);
end

local function is_looking_like_xep227(xml_data)
	if not xml_data or xml_data.name ~= "server-data"
	or xml_data.attr.xmlns ~= "urn:xmpp:pie:0" then
		return false;
	end
	-- Looks like 227, but check it has at least one host + user element
	return not not xml_data:find("host/user");
end

local function handle_import_227(event)
	local session = assert(event.session, "No session found");
	local username = session.username;

	local input_xml_raw = event.request.body;
	local input_xml_parsed = xml.parse(input_xml_raw);

	-- Some sanity checks
	if not input_xml_parsed or not is_looking_like_xep227(input_xml_parsed) then
		module:log("warn", "No data to import");
		return 422;
	end

	-- Set the host and username of the import to the new account's user/host
	input_xml_parsed:find("host").attr.jid = session.host;
	input_xml_parsed:find("host/user").attr.name = username;

	local user_xml = new_user_xml(session.username, session.host);

	user_xml:set_user_xml(username, session.host, input_xml_parsed);

	local xep227_driver = sm.load_driver(session.host, "xep0227");

	local selected_stores = get_selected_stores(event.request.url.query);

	for _, store_name in ipairs(selected_stores.keyval) do
		-- Initialize the destination store (XEP-0227 backed)
		local store = xep227_driver:open_xep0227(store_name, nil, user_xml);

		-- Read the current data
		local data, err = store:get(username);
		if data ~= nil or not err then
			local target_store = sm.open(session.host, store_name);
			-- Transform the data and update user_xml (via the _set_user_xml callback)
			if not target_store:set(username, data == nil and {} or data) then
				return 500;
			end
		elseif err then
			return 500;
		end
	end

	if selected_stores.export_pep_data then
		local pep_store = xep227_driver:open_xep0277("pep", nil, user_xml);
		local pep_node_list = pep_store:get(session.username);
		if pep_node_list then
			for node_name in it.keys(pep_node_list) do
				table.insert(selected_stores.archive, "pep_"..node_name);
			end
		end
	end

	for store_name in it.values(selected_stores.archive) do
		local source_archive = xep227_driver:open_xep0227(store_name, "archive", user_xml);
		local dest_driver = get_config_driver(store_name, session.host);
		local dest_archive = dest_driver:open(store_name, "archive");
		local count, errs = 0, 0;
		for id, item, when, with in source_archive:find(username) do
			local ok, err = dest_archive:append(username, id, item, when, with);
			if ok then
				count = count + 1;
			else
				module:log("warn", "Error: %s", err);
				errs = errs + 1;
			end
			if ( count + errs ) % 100 == 0 then
				module:log("info", "%d items migrated, %d errors", count, errs);
			end
		end
	end

	return 200;
end

---

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

local function check_auth(routes)
	local function check_request_auth(event)
		local session = check_credentials(event.request);
		if not session then
			event.response.headers.authorization = ("Bearer realm=%q"):format(module.host.."/"..module.name);
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

module:provides("http", {
	route = check_auth {
		["GET /export"] = handle_export_227;
		["PUT /import"] = handle_import_227;
	};
});

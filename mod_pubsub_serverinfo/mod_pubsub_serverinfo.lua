local st = require "util.stanza";
local new_id = require"util.id".medium;
local dataform = require "util.dataforms".new;

local local_domain = module:get_host();
local service = module:get_option(module.name .. "_service") or "pubsub." .. local_domain;
local node = module:get_option(module.name .. "_node") or "serverinfo";
local actor = module.host .. "/modules/" .. module.name;
local publication_interval = module:get_option(module.name .. "_publication_interval") or 300;
local cache_ttl = module:get_option(module.name .. "_cache_ttl") or 3600;

local opt_in_reports

function module.load()
	discover_node():next(
		function(exists)
			if not exists then create_node() end
		end
	):catch(
		function(error)
			module:log("warn", "Error prevented discovery or creation of pub/sub node at %s: %s", service, error)
		end
	)

	module:add_feature("urn:xmpp:serverinfo:0");

	module:add_extension(dataform {
		{ name = "FORM_TYPE", type = "hidden", value = "http://jabber.org/network/serverinfo" },
		{ name = "serverinfo-pubsub-node", type = "text-single" },
	}:form({ ["serverinfo-pubsub-node"] = ("xmpp:%s?;node=%s"):format(service, node) }, "result"));

	if cache_ttl < publication_interval then
		module:log("warn", "It is recommended to have a cache interval higher than the publication interval");
	end

	cache_warm_up()
	module:add_timer(10, publish_serverinfo);
end

function module.unload()
	-- This removes all subscribers, which may or may not be desirable, depending on the reason for the unload.
	delete_node(); -- Should this block, to delay unload() until the node is deleted?
end

-- Returns a promise of a boolean
function discover_node()
	local request = st.iq({ type = "get", to = service, from = actor, id = new_id() })
		:tag("query", { xmlns = "http://jabber.org/protocol/disco#items" })

	module:log("debug", "Sending request to discover existence of pub/sub node '%s' at %s", node, service)
	return module:send_iq(request):next(
		function(response)
			if response.stanza == nil or response.stanza.attr.type ~= "result" then
				module:log("warn", "Unexpected response to service discovery items request at %s: %s", service, response.stanza)
				return false
			end

			local query = response.stanza:get_child("query", "http://jabber.org/protocol/disco#items")
			if query ~= nil then
				for item in query:childtags("item") do
					if item.attr.jid == service and item.attr.node == node then
						module:log("debug", "pub/sub node '%s' at %s does exist.", node, service)
						return true
					end
				end
			end
			module:log("debug", "pub/sub node '%s' at %s does not exist.", node, service)
			return false;
		end
	);
end

-- Returns a promise of a boolean
function create_node()
	local request = st.iq({ type = "set", to = service, from = actor, id = new_id() })
		:tag("pubsub", { xmlns = "http://jabber.org/protocol/pubsub" })
			:tag("create", { node = node }):up()
			:tag("configure")
				:tag("x", { xmlns = "jabber:x:data", type = "submit" })
					:tag("field", { var = "FORM_TYPE", type = "hidden"})
						:text_tag("value", "http://jabber.org/protocol/pubsub#node_config")
						:up()
					:tag("field", { var = "pubsub#max_items" })
						:text_tag("value", "1")
						:up()
					:tag("field", { var = "pubsub#persist_items" })
						:text_tag("value", "0")

	module:log("debug", "Sending request to create pub/sub node '%s' at %s", node, service)
	return module:send_iq(request):next(
		function(response)
			if response.stanza == nil or response.stanza.attr.type ~= "result" then
				module:log("warn", "Unexpected response to pub/sub node '%s' creation request at %s: %s", node, service, response.stanza)
				return false
			else
				module:log("debug", "Successfully created pub/sub node '%s' at %s", node, service)
				return true
			end
		end
	)
end

-- Returns a promise of a boolean
function delete_node()
	local request = st.iq({ type = "set", to = service, from = actor, id = new_id() })
		:tag("pubsub", { xmlns = "http://jabber.org/protocol/pubsub" })
			:tag("delete", { node = node });

	module:log("debug", "Sending request to delete pub/sub node '%s' at %s", node, service)
	return module:send_iq(request):next(
		function(response)
			if response.stanza == nil or response.stanza.attr.type ~= "result" then
				module:log("warn", "Unexpected response to pub/sub node '%s' deletion request at %s: %s", node, service, response.stanza)
				return false
			else
				module:log("debug", "Successfully deleted pub/sub node '%s' at %s", node, service)
				return true
			end
		end
	)
end

function get_remote_domain_names()
	-- Iterate over s2s sessions, adding them to a multimap, where the key is the local domain name,
	-- mapped to a collection of remote domain names. De-duplicate all remote domain names by using
	-- them as an index in a table.
	local domains_by_host = {}
	for session, _ in pairs(prosody.incoming_s2s) do
		if session ~= nil and session.from_host ~= nil and local_domain == session.to_host then
			module:log("debug", "Local host '%s' has remote '%s' (inbound)", session.to_host, session.from_host);
			local sessions = domains_by_host[session.to_host]
			if sessions == nil then sessions = {} end; -- instantiate a new entry if none existed
			sessions[session.from_host] = true
			domains_by_host[session.to_host] = sessions
		end
	end

	-- At an earlier stage, the code iterated over all prosody.hosts, trying to generate one pubsub item for all local hosts. That turned out to be
	-- to noisy. Instead, this code now creates an item that includes the local vhost only. It is assumed that this module will also be loaded for
	-- other vhosts. Their data should then be published to distinct pub/sub services and nodes.

	-- for host, data in pairs(prosody.hosts) do
	local host = local_domain
	local data = prosody.hosts[host]
	if data ~= nil then
		local sessions = domains_by_host[host]
		if sessions == nil then sessions = {} end; -- instantiate a new entry if none existed
		if data.s2sout ~= nil then
			for _, session in pairs(data.s2sout) do
				if session.to_host ~= nil then
					module:log("debug", "Local host '%s' has remote '%s' (outbound)", host, session.to_host);
					sessions[session.to_host] = true
					domains_by_host[host] = sessions
				end
			end
		end

		-- When the instance of Prosody hosts more than one host, the other hosts can be thought of as having a 'permanent' s2s connection.
		for host_name, host_info in pairs(prosody.hosts) do
			if host ~= host_name and host_info.type ~= "component" then
				module:log("debug", "Local host '%s' has remote '%s' (vhost)", host, host_name);
				sessions[host_name] = true;
				domains_by_host[host] = sessions
			end
		end
	end

	return domains_by_host
end

function publish_serverinfo()
	module:log("debug", "Publishing server info...");
	local domains_by_host = get_remote_domain_names()

	-- Build the publication stanza.
	local request = st.iq({ type = "set", to = service, from = actor, id = new_id() })
		:tag("pubsub", { xmlns = "http://jabber.org/protocol/pubsub" })
			:tag("publish", { node = node, xmlns = "http://jabber.org/protocol/pubsub" })
				:tag("item", { id = "current", xmlns = "http://jabber.org/protocol/pubsub" })
					:tag("serverinfo", { xmlns = "urn:xmpp:serverinfo:0" })

	request:tag("domain", { name = local_domain })
		:tag("federation")

	local remotes = domains_by_host[local_domain]

	if remotes ~= nil then
		for remote, _ in pairs(remotes) do
			-- include a domain name for remote domains, but only if they advertise support.
			if does_opt_in(remote) then
				request:tag("remote-domain", { name = remote }):up()
			else
				request:tag("remote-domain"):up()
			end
		end
	end

	request:up():up()

	module:send_iq(request):next(
		function(response)
			if response.stanza == nil or response.stanza.attr.type ~= "result" then
				module:log("warn", "Unexpected response to item publication at pub/sub node '%s' on %s: %s", node, service, response.stanza)
				return false
			else
				module:log("debug", "Successfully published item on pub/sub node '%s' at %s", node, service)
				return true
			end
		end,
		function(error)
			module:log("warn", "Error prevented publication of item on pub/sub node at %s: %s", service, error)
		end
	)

	return publication_interval;
end

local opt_in_cache = {}

function cache_warm_up()
	module:log("debug", "Warming up opt-in cache")
	local domains_by_host = get_remote_domain_names()
	local remotes = domains_by_host[local_domain]
	if remotes ~= nil then
		for remote, _ in pairs(remotes) do
			does_opt_in(remote)
		end
	end
end

function does_opt_in(remoteDomain)

	-- try to read answer from cache.
	local cached_value = opt_in_cache[remoteDomain]
	local ttl = cached_value and os.difftime(cached_value.expires, os.time());
	if cached_value and ttl > (publication_interval + 60) then
		module:log("debug", "Opt-in status (from cache) for '%s': %s", remoteDomain, cached_value.opt_in)
		return cached_value.opt_in;
	end

	-- We don't have a cached value, or it is nearing expiration - refresh it now
	-- TODO worry about not having multiple requests in flight to the same domain.cached_value

	module:log("debug", "%s: performing disco/info to determine opt-in", remoteDomain)
	local discoRequest = st.iq({ type = "get", to = remoteDomain, from = actor, id = new_id() })
		:tag("query", { xmlns = "http://jabber.org/protocol/disco#info" })

	module:send_iq(discoRequest):next(
		function(response)
			if response.stanza ~= nil and response.stanza.attr.type == "result" then
				local query = response.stanza:get_child("query", "http://jabber.org/protocol/disco#info")
				if query ~= nil then
					for feature in query:childtags("feature") do
						--module:log("debug", "Disco/info feature for '%s': %s", remoteDomain, feature)
						if feature.attr.var == 'urn:xmpp:serverinfo:0' then
							module:log("debug", "Disco/info response included opt-in for '%s'", remoteDomain)
							opt_in_cache[remoteDomain] = {
								opt_in = true;
								expires = os.time() + cache_ttl;
							}
							return; -- prevent 'false' to be cached, down below.
						end
					end
				end
			end
			module:log("debug", "Disco/info response did not include opt-in for '%s'", remoteDomain)
			opt_in_cache[remoteDomain] = {
				opt_in = false;
				expires = os.time() + cache_ttl;
			}
		end,
		function(response)
			module:log("debug", "An error occurred while performing a disco/info request to determine opt-in for '%s'", remoteDomain, response)
			opt_in_cache[remoteDomain] = {
				opt_in = false;
				expires = os.time() + cache_ttl;
			}
		end
	);

	if ttl and ttl <= 0 then
		-- Cache entry expired, remove it and assume not opted in
		opt_in_cache[remoteDomain] = nil;
		return false;
	end

	return cached_value and cached_value.opt_in;
end

local array = require "util.array";
local hashes = require "util.hashes";
local it = require "util.iterators";
local base64_enc = require "util.encodings".base64.encode;

local hash_functions = {
	["SCRAM-SHA-1"] = hashes.sha1;
	["SCRAM-SHA-1-PLUS"] = hashes.sha1;
	["SCRAM-SHA-256"] = hashes.sha256;
	["SCRAM-SHA-256-PLUS"] = hashes.sha256;
};

function add_ssdp_info(event)
	local sasl_handler = event.session.sasl_handler;
	local hash = hash_functions[sasl_handler.selected];
	if not hash then
		module:log("debug", "Not enabling SSDP for unsupported mechanism: %s", sasl_handler.selected);
		return;
	end
	local mechanism_list = array.collect(it.keys(sasl_handler:mechanisms())):sort();
	local cb = sasl_handler.profile.cb;
	local cb_list = cb and array.collect(it.keys(cb)):sort();
	local ssdp_string;
	if cb_list then
		ssdp_string = mechanism_list:concat(",").."|"..cb_list:concat(",");
	else
		ssdp_string = mechanism_list:concat(",");
	end
	module:log("debug", "Calculated SSDP string: %s", ssdp_string);
	event.message = event.message..",d="..base64_enc(hash(ssdp_string));
	sasl_handler.state.server_first_message = event.message;
end

module:hook("sasl/c2s/challenge", add_ssdp_info, 1);
module:hook("sasl2/c2s/challenge", add_ssdp_info, 1);


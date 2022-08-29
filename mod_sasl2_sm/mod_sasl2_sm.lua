local st = require "util.stanza";

local mod_smacks = module:depends("smacks");

local xmlns_sasl2 = "urn:xmpp:sasl:1";
local xmlns_sm = "urn:xmpp:sm:3";

module:hook("stream-features", function (event)
	if event.origin.type ~= "c2s_unauthed" then return; end
	local features = event.features;
	local inline = features:get_child("inline", xmlns_sasl2);
	if not inline then
		inline = st.stanza("inline", { xmlns = xmlns_sasl2 });
		features:add_child(inline);
	end
	inline:tag("sm", { xmlns = xmlns_sm }):up();
end);

module:hook_tag(xmlns_sasl2, "authenticate", function (session, auth)
	-- Cache action for future processing (after auth success)
	session.sasl2_sm_action = auth:get_child_with_namespace(xmlns_sm);
end, 100);

module:hook("sasl2/c2s/success", function (event)
	local session = event.session;
	local sm_action = session.sasl2_sm_action;
	if not sm_action then return; end
	session.sasl2_sm_action = nil;
	local sm_result;
	if sm_action.name == "resume" then
		local resumed, err = mod_smacks.do_resume(session, sm_action);
		if not resumed then
			local h = err.context and err.context.h;
			sm_result = st.stanza("failed", { xmlns = xmlns_sm, h = h and ("%d"):format(h) or nil })
				:add_error(err);
		else
			event.session = resumed.session; -- Update to resumed session
			event.sasl2_sm_finish = resumed.finish; -- To be called after sending final SASL response
			sm_result = st.stanza("resumed", { xmlns = xmlns_sm,
				h = ("%d"):format(event.session.handled_stanza_count);
				previd = resumed.id; });
		end
	elseif sm_action.name == "enable" then
		local enabled, err = mod_smacks.do_enable(session, sm_action);
		if not enabled then
			sm_result = st.stanza("failed", { xmlns = xmlns_sm })
				:add_error(err);
		else
			event.sasl2_sm_finish = enabled.finish; -- To be called after sending final SASL response
			sm_result = st.stanze("enabled", {
				xmlns = xmlns_sm;
				id = enabled.id;
				resume = enabled.id and "1" or nil;
				max = enabled.resume_max;
			});
		end
	end
	if sm_result then
		event.success:add_child(sm_result);
	end
end, 100);

module:hook("sasl2/c2s/success", function (event)
	-- The authenticate response has already been sent at this point
	local finish = event.sasl2_sm_finish;
	if finish then
		finish(); -- Finish resume and sync stanzas
	end
end, -1100);

module:hook("sasl2/c2s/failure", function (event)
	event.session.sasl2_sm_action = nil;
end);


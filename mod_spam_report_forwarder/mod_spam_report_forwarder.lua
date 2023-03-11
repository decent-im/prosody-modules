local st = require "util.stanza";

local destinations = module:get_option_set("spam_report_destinations", {});

function forward_report(event)
	local report = st.clone(event.report);
	report:text_tag("jid", event.jid, { xmlns = "urn:xmpp:jid:0" });

	local message = st.message({ from = module.host })
		:add_child(report);

	for destination in destinations do
		local m = st.clone(message);
		m.attr.to = destination;
		module:send(m);
	end
end

module:hook("spam_reporting/abuse-report", forward_report, -1);
module:hook("spam_reporting/spam-report", forward_report, -1);
module:hook("spam_reporting/unknown-report", forward_report, -1);

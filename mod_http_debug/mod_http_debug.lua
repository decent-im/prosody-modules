local json = require "util.json"

module:depends("http")
module:provides("http", {
		route = {
			GET = function(event)
				local request = event.request;
				return {
					status_code = 200;
					headers = {
						content_type = "application/json",
					},
					body = json.encode {
						body = request.body;
						headers = request.headers;
						httpversion = request.httpversion;
						ip = request.ip;
						method = request.method;
						path = request.path;
						secure = request.secure;
						url = request.url;
					}
				}
			end;
		}
	})

local http = require "http"
local stdnse = require "stdnse"

description = [[
Checks for open ports and notifies via Teams

You will need to create a webhook in Teams. The steps to do so are at https://support.microsoft.com/en-us/office/create-incoming-webhooks-with-workflows-for-microsoft-teams-8ae491c7-0394-4861-ba59-055e33f75498.

You probably want the results in a chat with just yourself. Teams won't easily allow you to make one. An easy way is to schedule a meeting with no other attendees, send a message in the chat, and use that chat.

Note that it's fiddly escaping the whole Webhook URL to pass into Nmap, so it's better to use --script-args-file to pass the argument in instead.
If you get an error saying 'no path to file/directory' use the absolute path to the file.
]]
author = "Joe DS"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"external"}

-- @usage
-- nmap --script notify.nse --script-args --script-args 'notify.webhook_url=https://submarine.earth.logic.azure.com:443/workflows/deadbeef/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=1337' <target> <nmap scan options>

local webhook_url = stdnse.get_script_args("notify.webhook_url")

hostrule = function() return true end

action = function(host)
		if (webhook_url == nil) then return "Webhook URL missing." end

        -- The best way to do this would be to use the NSE url library, but this will do.
        -- We first find the slash (after the scheme and its double-slashes).
        -- Then split, and make sure to drop the port from the base
        local slash = webhook_url:find("/", 9)
        if (slash == nil) then return "Invalid Webhook provided." end
        local base = webhook_url:sub(9, slash-5)
        local rest = webhook_url:sub(slash)
        stdnse.debug(1, "%s", base)
        stdnse.debug(1, "%s", rest)

        local owner = nil

		local port_table = nmap.get_ports(host, nil, "tcp", "open")
		local count = 0
		while port_table do
			count = count + 1
			port_table = nmap.get_ports(host, port_table, "tcp", "open")
		end

		if count > 0 then
            local opts = {}
            opts['header'] = {}
            opts['header']['Content-Type'] = 'application/json'

            local form = '{"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{"$schema":"http://adaptivecards.io/schemas/adaptive-card.json","type":"AdaptiveCard","version":"1.2","body":[{"type":"TextBlock","text":"GHERKINS","wrap":true}]}}]}'
            if (host.targetname == nil or host.targetname == '') then
                form = form:gsub("GHERKINS", "Host " .. host.ip .. " has " .. count .. " open.")
            else
                form = form:gsub("GHERKINS", "Host " .. host.targetname .. " (" .. host.ip .. ")" .. " has " .. count .. " ports open.")
            end
	
            local response = http.post(base, 443, rest, opts, nil, form)
			if response.status ~= 202 then
				owner = "Error sending message"
			end
		end

        return owner
end
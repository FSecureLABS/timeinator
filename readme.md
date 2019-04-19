#Multi-Time Based Attacker

##About

Multi-Time Based Attacker is an extension for Burp Suite that can be used to perform timing attacks over an unreliable network such as the internet.

The attack mode is similar to the "sniper" mode in burp intruder, but instead of sending a single request for every payload, it is able to send multiple requests for each payload and display the minimum and maximum times taken to receive a response as well as the mean and median averages.

In an effort to prevent slow DNS lookups introducing delays, the domain is resolved at the start of the attack before any http requests are made. In addition, the extension sends HTTP(S) requests sequentially to reduce the chance of delays being introduced by overloading the server.

##Usage

1. Enable the extension in order to add a tab titled Multi-Time Based Attacker to the Burp Suite user interface.
2. Send a request to the extension by right clicking on a request anywhere in Burp Suite and choosing the "Send To Multi-Time Based Attacker" menu item. This will populate the "Attack" tab under the Multi-Time Based Attacker tab.
3. Select the section of the request that should be replaced with the payloads then click the "Add §" button. This will add a § symbol either side of the characters that should be replaced with the payload. More than one payload position can be chosen in a single request.
4. Choose how many requests to make for each payload.
5. Type or copy and paste the payloads into the "Payloads" text area. Place a single payload on each new line.
6. Hit the "Start Attack" button. Results will be displayed in the Results" tab. If there is more than one payload then results will be colour coded to make timing differences easier to spot. Slower requests will be coloured red and faster requests will be coloured green.

##Troubleshooting

This extension is wriiten in Python and therefore requires Jython.

HTTP(S) requests made by this extension will not be shown in the proxy history, however extensions such as Logger++ (available from the BApp store) will do so.

Multi-Time Based Attacker is by [graeme.robinson@mwrinfosecurity.com](mailto:graeme.robinson@mwrinfosecurity.com)
=== Sidcraft Bot Shield ===
Contributors: ssiddiqi4
Donate link: https://paypal.me/SSiddiqi275
Tags: bots, security, block countries, ip blocker, vpn
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lets search engines and AI assistants (Google, Bing, Apple, ChatGPT, Claude, Perplexity, Copilot and more) in. Blocks scrapers, scripts, scanners and fake bots. Block or allow countries, IP ranges, VPNs, proxies and Tor.

== Description ==

Most of the traffic that hits a small site is not people. Some of it you want: search engines send visitors, and AI assistants such as ChatGPT, Claude, Perplexity, Copilot, Gemini and Apple Intelligence can mention and link to your pages. A lot of it you do not want: scrapers that copy your content, scripts that hammer your pages, vulnerability scanners probing for `/shell` or `/.env`, and bots that pretend to be Googlebot.

**Sidcraft Bot Shield sorts them for you.**

= Always welcome (you can switch each group off) =

* **Search engines:** Google, Bing, Apple, DuckDuckGo, Yahoo, Yandex, Baidu, Qwant, Seznam, Naver, Petal and more.
* **AI assistants and AI search:** OpenAI (GPTBot, OAI-SearchBot, ChatGPT-User), Anthropic (ClaudeBot, Claude-User, Claude-SearchBot), Perplexity, Microsoft Copilot, Google Gemini, Apple Intelligence, Meta AI, Amazon, DeepSeek, Cursor, Mistral, Cohere, You.com, DuckDuckGo AI and others.
* **Link previews:** Facebook, X, LinkedIn, Slack, Discord, WhatsApp, Telegram, Pinterest, Reddit.
* **Monitoring:** UptimeRobot, Pingdom, StatusCake, Site24x7, GTmetrix, Lighthouse.
* **Services your site relies on:** WordPress itself, Jetpack, Stripe, PayPal, Square, GitHub, Mailchimp, feed readers.

= Blocked =

* **SEO and data-mining crawlers** such as AhrefsBot, SemrushBot, MJ12bot and DotBot.
* **Scripts and headless browsers** such as python-requests, curl, wget, Go-http-client, Scrapy, Puppeteer and Selenium.
* **Attack tools** such as sqlmap, Nikto, WPScan and Nuclei.
* **Visitors that send no browser name at all.**
* **Attack probes:** requests for `/shell`, `/.env`, `/phpmyadmin`, `/.git` and similar. The address that sent one is banned for a while.
* **Fake bots:** a visitor that says it is Googlebot, Bingbot, Applebot, Yahoo, Yandex or Baidu is checked through DNS. If the address does not belong to that company, it is blocked.

= Countries, addresses, VPN and Tor =

* **Block countries:** pick the countries you do not want.
* **Only allow countries:** pick the countries that may visit; everyone else is blocked.
* **Block addresses:** IPv4 and IPv6, single addresses, ranges such as 203.0.113.0/24 and from - to ranges.
* **Block Tor**, **commercial VPN services** and (stricter) **hosting / data-centre addresses**, using lists that are downloaded once a day.
* **Proxy headers:** optionally block requests that carry proxy headers (only when your site is not behind Cloudflare or another proxy).
* **Optional live check** with proxycheck.io for VPNs and proxies that are not on the lists (needs your own key; off by default).
* Search engines and AI assistants can be exempt from these rules (on by default), because Google and others crawl from the USA. Logged-in users, your own addresses and wp-cron are never blocked.
* The visitor's country is read from Cloudflare, CloudFront or your server when available. Otherwise upload a free country database (.mmdb, for example GeoLite2-Country or DB-IP Lite).

= Safe by design =

* **Monitor mode first.** After installing, nothing is blocked. The plugin only lists what it would block, so you can check the list before you switch to blocking.
* **People are never blocked** because of their browser: anything that looks like a normal browser passes. Logged-in users, your own addresses and the server itself are always allowed.
* **Only page requests** are checked for browser names. Forms, payment webhooks, apps and the REST API keep working.
* **Your own lists:** add names to allow or block, and addresses that must never be blocked.
* **Test tool:** type a browser name and see what would happen.
* Optional extras: a hidden trap link for robots that ignore robots.txt, and a speed limit per address.

= Honest limits =

VPN and country detection is never perfect: lists lag behind new VPN servers, and a visitor can use an address from another country. A country rule with no country source finds every visitor “unknown” (you choose what happens then). A browser name can be faked. Search engines that publish how to verify them (Google, Bing, Apple, Yahoo, Yandex, Baidu) are verified. Most AI companies do not publish a way to prove who is calling, so their crawlers are recognised by name only. A determined scraper that pretends to be a normal browser or an AI crawler can get through. This plugin removes the bulk of the noise and the obvious abuse; it is not a replacement for a firewall such as Cloudflare or a security plugin.

== Installation ==

1. Upload the plugin and activate it.
2. Open Settings > Bot Shield.
3. Leave it in Monitor mode for a few days and look at Recent activity.
4. When the list looks right, choose Block and save.

If your site is behind Cloudflare, choose Cloudflare in "Is your site behind Cloudflare or another proxy?" so that visitors' real addresses are used.

== Frequently Asked Questions ==

= Will this block Google? =

No. Googlebot, Bingbot, Applebot and the other search engines are allowed, and checked so that fakes are blocked.

= Will it block ChatGPT, Claude, Perplexity or Copilot? =

No. They are allowed by default. If you do not want AI companies to read your site, untick "AI assistants and AI search".

= Does it stop AI companies from training on my content? =

No. It lets them in or keeps them out by name. Use robots.txt rules for that as well, and keep in mind that a robots.txt request is only a request.

= I locked myself out. =

Logged-in users are never blocked. If you were blocked while logged out, add your address to "Never block these addresses". If you cannot open the settings, rename the plugin folder over FTP to switch it off.

= Does it slow my site down? =

The checks happen early and take a fraction of a millisecond. Genuine search-engine bots are checked once through DNS and the answer is remembered for a day.

== Privacy ==

When a request is blocked or flagged, the plugin keeps the visitor's IP address, browser name and the page they asked for in a list of the last 500 entries. Entries are removed after 30 days, and you can turn the list off or clear it. Nothing is sent to anyone else, except as listed under External services.

== External services ==

By default this plugin contacts no external service about your visitors.

* **DNS lookup (always, only for visitors claiming to be Google, Bing, Apple, Yahoo, Yandex or Baidu):** the plugin asks the visitor's network for the name of the address (reverse DNS) and checks that it resolves back. No site data is sent.
* **Tor exit list (only if "Block Tor" is on):** once a day the plugin downloads https://check.torproject.org/torbulkexitlist from the Tor Project. No data is sent. Privacy: https://www.torproject.org/about/privacy_policy/
* **VPN and hosting lists (only if those options are on):** once a day the plugin downloads public lists from https://raw.githubusercontent.com/X4BNet/lists_vpn (GitHub). Only your server's address is visible to GitHub. Terms: https://docs.github.com/en/site-policy/github-terms/github-terms-of-service
* **proxycheck.io (only if you turn on the live check and enter a key):** the visitor's IP address and your key are sent to https://proxycheck.io once per address per week to ask whether it is a VPN or proxy. Terms: https://proxycheck.io/terms Privacy: https://proxycheck.io/privacy
* **Country database:** a file you upload yourself; it is read on your server and nothing is sent.

Downloaded lists and the uploaded database are stored in wp-content/uploads/sidcraft-bot-shield/ (protected from direct access).

== Screenshots ==

1. Settings: choose which bots are welcome and which are blocked.
2. Recent activity: what was blocked, and why.

== Changelog ==

= 1.1.0 =
* New: overview cards (blocked today / 7 / 30 days, by type) and a Blocked log tab with filter, top addresses and CSV download.
* New: block countries, or allow only chosen countries.
* New: block IPv4 / IPv6 addresses, CIDR ranges and from-to ranges.
* New: block Tor, VPN services, hosting addresses, proxy headers; optional proxycheck.io check.
* New: country database upload (.mmdb), address tester.

= 1.0.0 =
* First release.

== Upgrade Notice ==

= 1.1.0 =
Adds country, IP range, VPN, proxy and Tor blocking. All new rules are off by default.

= 1.0.0 =
First release.

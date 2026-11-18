=== Sidcraft Bot Shield ===
Contributors: ssiddiqi4
Donate link: https://paypal.me/SSiddiqi275
Tags: two-factor, 2fa, passkey, firewall, security
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.3.8
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lets search engines and AI assistants in. Two-factor login (email, app, SMS, passkey), custom login URL, firewall, malware scan, bot blocking.

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

= Advanced firewall =

* **Web application firewall:** stops SQL injection, cross-site scripting, file inclusion and directory traversal, code execution (PHP, shell, Log4Shell, Shellshock, PHP object injection) and malicious file uploads. Every rule can be switched off, and you can allow specific pages and fields.
* **Learning mode:** a new install only records for 7 days, learns from what administrators do, then turns on by itself. Administrators are never blocked.
* **Extended protection:** optionally runs the firewall before WordPress and every other plugin loads (auto_prepend_file, set up for you and removed again with one click).
* **Login security:** lock out addresses that guess passwords, lock out at once on a user name that does not exist, hide whether the user name or the password was wrong, require strong passwords, optionally refuse passwords from known data breaches.
* **Rate limiting:** limits for crawlers and for missing-page (404) requests, for people and bots separately. Search engines are never limited.
* **Hardening:** hide the WordPress version, stop user name guessing (?author=1 and the REST users list), switch XML-RPC off or block its multicall trick.
* **Blocked addresses list** with one-click unblock.

= Two-factor login =

* **Four ways to confirm a login:** a code by email, a code from an authenticator app (Google Authenticator, Microsoft Authenticator, Authy, 1Password and others; the QR code is made on your own server), a text message (through your own Twilio account), or a passkey (fingerprint, face, phone or security key).
* **Recovery codes** for when a phone or key is lost, and a reset button for administrators.
* **Choose which roles must use it,** with a grace period to set it up. Anyone can also turn it on for themselves under Users > Profile.
* Wrong codes count as failed logins, so the lockout rules apply. After 5 wrong codes the login starts over.
* Works with the normal login page and with the custom login address. REST API, XML-RPC and application passwords are not affected.

= Custom login address =

* Move the login page from /wp-login.php and /wp-admin to an address only you know, for example example.com/mysecret.
* Visitors who keep opening the old addresses are blocked: you set the number of tries, the minutes and the days (or for good).
* Visitors who open the old addresses see a "page not found" (or are sent to the home page or an address you choose). Logged-in users and admin-ajax.php are not affected.
* The new address is emailed to the administrator, and a wp-config.php line switches the feature off if it is ever forgotten.

= Bots that search for missing pages =

* Set how many missing pages (404) in how many minutes block an address, and for how many days, or for good.
* Search engines, logged-in users, your own addresses and common browser requests (favicon, robots.txt) are not counted.
* **Email alert** with the IP address, its host name (for example badperson.example.com), the reason and how long it is blocked, with a link to unblock it. An hourly limit prevents mail floods.
* **Unblock:** from the list of blocked addresses, from the email link, or, if you blocked yourself, with the "Email me an unlock link" button that a blocked visitor sees.

= Malware scan =

* **Core files:** compares every WordPress file with the official version and reports changed, missing and unknown files. Repair restores the official file.
* **Plugin files:** compares plugins from WordPress.org with the official version.
* **Malware and backdoors:** looks for web shells, hidden or encoded code, code that runs visitor input, hacked .htaccess files, and PHP in the uploads folder. Hidden PHP inside images is checked too.
* **Posts, pages and comments:** hidden iframes, hidden links, scripts that hide their code, spam links.
* **Exposed files:** backups, database dumps, .env, logs, phpinfo, and open directory listings.
* **Updates and abandoned plugins:** out-of-date WordPress, plugins and themes; plugins not updated for 2 years or removed from WordPress.org.
* **Weak passwords** of administrators and editors; low disk space; old PHP version.
* **Scan types** (quick, standard, high sensitivity, custom), file size and time limits, excluded paths, daily or weekly schedule, email alerts.
* **Works on any host:** the scan runs in short steps and continues in the background. For each result you can view the file, repair it, delete it, ignore it or mark it as fixed.
* Files that match WordPress.org are trusted and skipped by the malware check, which keeps false alarms low.

= Safe by design =

* **Monitor mode first.** After installing, nothing is blocked. The plugin only lists what it would block, so you can check the list before you switch to blocking.
* **People are never blocked** because of their browser: anything that looks like a normal browser passes. Logged-in users, your own addresses and the server itself are always allowed.
* **Only page requests** are checked for browser names. Forms, payment webhooks, apps and the REST API keep working.
* **Your own lists:** add names to allow or block, and addresses that must never be blocked.
* **Wordfence-style actions:** from the log or the Dashboard widget, unblock an address (lifts a ban and adds it to your never-block list), block it for good, or allow a bot name, in one click.
* **Test tool:** type a browser name and see what would happen.
* Optional extras: a hidden trap link for robots that ignore robots.txt, and a speed limit per address.

= Honest limits =

VPN and country detection is never perfect: lists lag behind new VPN servers, and a visitor can use an address from another country. A country rule with no country source finds every visitor “unknown” (you choose what happens then). The scanner looks for known patterns and changes against official files; it cannot promise to find every kind of malware, and it does not use a cloud database of signatures. Keep backups. The firewall catches common attack patterns, but it is not a replacement for keeping WordPress, plugins and themes up to date. A browser name can be faked. Search engines that publish how to verify them (Google, Bing, Apple, Yahoo, Yandex, Baidu) are verified. Most AI companies do not publish a way to prove who is calling, so their crawlers are recognised by name only. A determined scraper that pretends to be a normal browser or an AI crawler can get through. This plugin removes the bulk of the noise and the obvious abuse; it is not a replacement for a firewall such as Cloudflare or a security plugin.

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

* **WordPress.org (scan; only when you run or schedule a scan):** the plugin asks api.wordpress.org for the official checksums of your WordPress version and for update and plugin information, downloads.wordpress.org for the official checksums of your plugins, and (only when you click Repair) core.svn.wordpress.org or plugins.svn.wordpress.org for the official copy of one file. Your WordPress version, locale, and the names and versions of your plugins are sent, as WordPress itself does when it checks for updates. Privacy: https://wordpress.org/about/privacy/
* **Pwned Passwords (only if you turn on "Block passwords that appeared in data breaches"):** the first 5 characters of the SHA-1 hash of a password are sent to https://api.pwnedpasswords.com/range/ when an administrator logs in or a password is set. The password itself never leaves your site. Terms: https://haveibeenpwned.com/API/v3
* **Twilio (only if you turn on text-message codes and enter your Twilio details):** the user's phone number and the code are sent to https://api.twilio.com to deliver the text message. Privacy: https://www.twilio.com/legal/privacy
* **Passkeys** are handled by the visitor's browser and device. Nothing is sent to a third party.
* **Your own site:** the scan sends requests to your own website address to check whether backup or log files can be downloaded.

Downloaded lists and the uploaded database are stored in wp-content/uploads/sidcraft-bot-shield/ (protected from direct access).

== Screenshots ==

1. Settings: choose which bots are welcome and which are blocked.
2. Recent activity: what was blocked, and why.

== Changelog ==

= 1.3.3 =
* New: two-factor login (email code, authenticator app, text message, passkey, recovery codes).
* New: custom login address.
* New: block bots that search for missing pages; email alerts with IP and host name; unblock links; permanent blocks.

= 1.2.0 =
* New: advanced firewall (rule engine, learning mode, extended protection, login security, rate limits, hardening, blocked addresses list).
* New: malware scan (core and plugin file checks with repair, malware signatures, content scan, exposed files, updates, abandoned plugins, weak passwords, schedule and email alerts).

= 1.1.0 =
* New: Unblock / Block for good / Allow this bot name links on every log row, and a WordPress Dashboard widget with the latest blocks.
* New: overview cards (blocked today / 7 / 30 days, by type) and a Blocked log tab with filter, top addresses and CSV download.
* New: block countries, or allow only chosen countries.
* New: block IPv4 / IPv6 addresses, CIDR ranges and from-to ranges.
* New: block Tor, VPN services, hosting addresses, proxy headers; optional proxycheck.io check.
* New: country database upload (.mmdb), address tester.

= 1.0.0 =
* First release.

== Upgrade Notice ==

= 1.3.8 =
Makes removing flagged files safe and reversible.

= 1.3.7 =
Makes the never-block list easy to find and protects it from being blocked by mistake.

= 1.3.6 =
Adds lock-out protection for administrators and an unlock-by-email button on every block page.

= 1.3.5 =
Adds an emergency switch for lock-outs and makes the wrong-login-address rule gentler.

= 1.3.4 =
Fixes extended protection failing to turn on.

= 1.3.3 =
Adds two-factor login, a custom login address and missing-page (404) blocking. Two-factor login and the custom address are off until you turn them on. The 404 rule is on by default (15 missing pages in 2 minutes block an address for 7 days).

= 1.2.0 =
Adds an advanced firewall and a malware scanner. The firewall starts in learning mode and does not block anything for the first 7 days.

= 1.1.0 =
Adds country, IP range, VPN, proxy and Tor blocking. All new rules are off by default.

= 1.0.0 =
First release.

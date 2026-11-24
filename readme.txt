=== Sidcraft BotVanguard ===
Contributors: ssiddiqi4
Donate link: https://paypal.me/SSiddiqi275
Tags: two-factor, 2fa, passkey, firewall, security
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.11.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lets search engines and AI assistants in. Two-factor login (email, app, SMS, passkey), custom login URL, firewall, malware scan, bot blocking.

== Description ==

Most of the traffic that hits a small site is not people. Some of it you want: search engines send visitors, and AI assistants such as ChatGPT, Claude, Perplexity, Copilot, Gemini and Apple Intelligence can mention and link to your pages. A lot of it you do not want: scrapers that copy your content, scripts that hammer your pages, vulnerability scanners probing for `/shell` or `/.env`, and bots that pretend to be Googlebot.

**Sidcraft BotVanguard sorts them for you.**

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
2. Open Sidcraft BotVanguard in the WordPress menu (it has its own Dashboard).
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

= I locked myself out. What is the emergency switch? =

Logged-in users are never blocked. If you were blocked while logged out, add your address to "Never block these addresses" (Sidcraft BotVanguard > Bots). If you cannot open the settings, use one of the emergency switches below. They work even when you cannot log in.

**Switch off all blocking: `SIDCRAFT_BOTSHIELD_OFF`**

1. Open `wp-config.php` in your site's main folder (over FTP, SFTP or your host's file manager).
2. Add this line above the line that says `/* That's all, stop editing! Happy publishing. */`:

`define( 'SIDCRAFT_BOTSHIELD_OFF', true );`

3. Save the file and reload your site. Sidcraft BotVanguard stops all of its blocking: bad-bot and country blocking, the firewall, login lockouts, the REST API rules, the blocked core files check and the custom login address, so `wp-login.php` works again. The plugin stays active and its settings are kept.
4. Log in, fix the setting that locked you out (for example add your address to "Never block these addresses"), then delete the line from `wp-config.php` to switch the protection back on.

If the emergency switch is not enough:

* `.htaccess` lines: It does not remove the lines Sidcraft BotVanguard wrote into `.htaccess`: the optional pre-WordPress firewall and the core files rule. They run before WordPress loads, so the constant can't switch them off. If one of those is blocking you, delete the block between `# BEGIN Sidcraft Bot Shield …` and `# END Sidcraft Bot Shield …` in `.htaccess`.
* Two-factor login: It has its own switch. Add `define( 'SIDCRAFT_BOTSHIELD_DISABLE_2FA', true );` to `wp-config.php`, or upload an empty file named `sidcraft-botshield-disable-2fa` (no extension) to the `wp-content` folder.
* No FTP access: Rename the plugin folder `wp-content/plugins/botvanguard` to switch the whole plugin off, then rename it back.

Tip: before you change firewall or login settings, open Sidcraft BotVanguard > Dashboard and use the "Back up .htaccess", "Back up wp-config.php", "Back up php.ini" and "Back up .user.ini" buttons. Each downloads a copy of the file (it ends in .txt). php.ini and .user.ini are read from your site's main folder; which one exists depends on your host, so the button for a missing file simply tells you it was not found. Keep the wp-config.php copy private: it contains your database password.

= My site is under a DDoS attack and I cannot log in. What do I do? =

A DDoS attack floods your site with so many requests that it slows down or stops, and your own login may time out. Sidcraft BotVanguard has an attack mode that makes every visitor pass a short browser check before WordPress does any real work. Attack tools almost never pass it. You can switch it on without the dashboard, over FTP or your host's file manager. Use either way:

**Way 1: a line in `wp-config.php`**

1. Open `wp-config.php` in your site's main folder.
2. Add this line above the line that says `/* That's all, stop editing! Happy publishing. */`:

`define( 'BOTVANGUARD_DDOS', true );`

3. Save. Attack mode is on straight away.

**Way 2: an empty file.** Upload an empty file named `botvanguard-ddos` (no extension) to the `wp-content` folder. Delete it to switch attack mode off again.

Optional, stricter: limit how many requests a minute one address may make with `define( 'BOTVANGUARD_DDOS_RATE', 30 );` (the default in this emergency mode is 60).

When the attack is over, remove the line or delete the file. Then log in and open Sidcraft BotVanguard > DDoS to see what happened.

= What does attack mode do, exactly? =

* Every visitor who is not logged in and not on your trusted list is shown a short "Checking your browser" page once. Their browser solves a small puzzle and the site opens. They are not asked again for 6 hours (you can change this).
* Search engines and other bots that you allow in Sidcraft BotVanguard, and that prove who they are, are never asked. Logged-in users are never asked.
* An address that passed the check but still sends too many requests a minute (120 by default) is blocked for 30 minutes.
* Outside calls to `wp-cron.php`, a favourite target, are refused while it is on.
* The check page is tiny and needs no database work, so your server can turn away a flood cheaply.

= Can it switch on by itself? =

Yes. In Sidcraft BotVanguard > DDoS the default is Automatic: if the whole site gets more than 600 requests in one minute, attack mode starts and stays on for 30 minutes. Change the numbers to fit your normal traffic. You can also start it by hand for 30 minutes up to 24 hours, or set it to Always on.

= Will payments, forms and webhooks still work in attack mode? =

Visitors' browsers pass the check once, so forms and checkouts keep working. Servers that call your site, such as payment webhooks, cannot pass a browser check. The "Never asked" list in Sidcraft BotVanguard > DDoS covers WooCommerce callbacks (`wc-api`) by default. Add the address of any other callback, for example `/wp-json/stripe/`.

= Will attack mode hurt my search ranking? =

Not for the search engines you allow in Sidcraft BotVanguard that prove who they are by reverse DNS (Google, Bing and others). They are not asked. Keep attack mode off when there is no attack, so that other crawlers and visitors are not slowed down. Visitors with JavaScript turned off cannot pass the check while it is on.

= Is this enough to stop any DDoS attack? =

No. Sidcraft BotVanguard protects your WordPress site from floods of web requests. It cannot stop an attack that fills your server's internet connection before the requests even reach your site. For serious attacks also put your site behind a CDN such as Cloudflare (turn on its "Under Attack" mode), or ask your host for DDoS protection. If you use Cloudflare, set "Proxy" to Cloudflare in Sidcraft BotVanguard > Bots so visitors' real addresses are seen.

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
* **AbuseIPDB (only if you turn on "AbuseIPDB" in the Firewall tab and enter your key):** the visitor's IP address and your API key are sent to https://api.abuseipdb.com once per address per day (or the number of hours you choose) to ask for its abuse score. Verified search engine crawlers are not sent. Terms: https://www.abuseipdb.com/terms Privacy: https://www.abuseipdb.com/privacy
* **abuse.ch MalwareBazaar (only if you turn on "Known-malware lookup" in the Scan tab and enter your own Auth-Key):** the SHA-256 fingerprint (not the file) of a file the scan already flagged is sent to https://mb-api.abuse.ch, at most 30 files per scan. abuse.ch provides this free of charge for personal and non-commercial use under its fair-use rules; business or commercial use may need a paid abuse.ch licence, which you must obtain from abuse.ch yourself. Terms: https://abuse.ch/terms-of-use/
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

= 1.11.0 =
* New: Scan tab, "Known-malware lookup". Optional and off by default. With your own free abuse.ch Auth-Key, files the scan flags are checked by their SHA-256 fingerprint against the MalwareBazaar list of known malware, and a match is reported as critical with the malware family. Only the fingerprint is sent, at most 30 files per scan. abuse.ch is free for personal and non-commercial use; business use may need a paid abuse.ch licence (noted on the screen and in External services).

= 1.10.1 =
* Firewall tab: the error log and php.ini option now always shows the nginx line to give your host, not only after a problem.

= 1.10.0 =
* New: Firewall tab, "Block direct access to core and server files" now also blocks web access to PHP error logs and PHP settings files: error_log, php_errorlog, debug.log, php.ini and .user.ini, in every folder of your site. Off until you turn it on. It adds a rule to .htaccess (Apache and LiteSpeed) between the Sidcraft Bot Shield Core Files lines, and shows the lines to add by hand on nginx or when .htaccess cannot be written.

= 1.9.0 =
* New: Dashboard, "Export and import settings". Save every BotVanguard setting and list to a .json file and restore it later or on another site. API keys and tokens are left out unless you tick the box. A setting missing from the file keeps its current value. The block log, current blocks and scan results are not part of the file.

= 1.8.0 =
* New: Firewall tab, "AbuseIPDB". Paste your AbuseIPDB API key and visitors whose address has an abuse score above your limit (40% to start) are denied. Real search engine crawlers are always let through, checked by their address and not only their name. If AbuseIPDB cannot be reached, visitors are let through. Each address is looked up once and remembered.

= 1.7.3 =
* Plugin Check: Firewall tab values are now escaped where they are printed.

= 1.7.2 =
* Plugin Check: escaping warnings in the Firewall tab fixed.

= 1.7.1 =
* New: wildcards in the forbidden list. * means any characters and ? one character, for example *.tar, *gz, *.sql or backup*.zip. A wildcard line must match a whole file or folder name, so *gz does not block /gzip-guide/.

= 1.7.0 =
* New: Firewall tab, "Forbidden files and words". Type names such as back.tar or backup.tar.gz (one per line); an address that asks for one is refused and blocked for good (or for the number of days you choose). Search engines, logged-in users and your never-block list are never blocked.

= 1.6.1 =
* Fixed: with a custom login address switched on, the login page could show "Warning: Undefined variable $user_login" and "$error" (and garbage text in the username box) on servers that display PHP warnings. WordPress's login page now runs with its variables in the global scope, as it does at /wp-login.php.

= 1.6.0 =
* Renamed: the plugin is now Sidcraft BotVanguard (folder and slug botvanguard), so that it cannot be confused with other plugins named Bot Shield. Your settings, bans, logs and the firewall lines in .htaccess are kept. Activating Sidcraft BotVanguard switches the old Sidcraft Bot Shield plugin off, whatever folder it is in; delete the old one afterwards. All class and function names are new, so the two plugins can never crash each other. If both are somehow active, Sidcraft BotVanguard stays idle and shows a notice.
* New: its own menu in the WordPress dashboard with a Dashboard (protection status and the latest blocks), Bots, Firewall, Login, Scan and Blocked log screens. It no longer sits under Settings.
* New: Firewall > REST API (/wp-json/). Watch-only mode (logs what would be closed), or close the REST API to visitors who are not logged in with an allow list of routes (oEmbed, form sending, visitor counting, Contact Form 7, WooCommerce Store API and Jetpack are allowed by default), routes that are always closed, a requests-a-minute limit, and counting of failed REST logins (application passwords) as failed logins. Logged-in users and your trusted addresses are never affected.
* Blocked requests to the REST API show in the Blocked log under REST API.
* New: DDoS tab with an attack mode: every visitor passes a short browser check (with a small calculation) before WordPress does real work, per-address request limits, automatic start on a surge of requests, and two emergency switches that work without the dashboard: `define( 'BOTVANGUARD_DDOS', true );` in wp-config.php, or an empty file wp-content/botvanguard-ddos. Search engines you allow and logged-in users are never asked. See the FAQ.
* New: Dashboard buttons "Back up .htaccess", "Back up wp-config.php", "Back up php.ini" and "Back up .user.ini" download a copy of each file (administrators only).
* Readme: step-by-step instructions for the emergency switches (SIDCRAFT_BOTSHIELD_OFF and SIDCRAFT_BOTSHIELD_DISABLE_2FA) in the FAQ.

= 1.5.6 =
* New: Firewall tab > "Block direct access to core files". Tick xmlrpc.php, wp-settings.php and/or wp-config.php to refuse direct requests to them. The plugin writes a rule into .htaccess (Apache, LiteSpeed; removed when you untick the boxes or deactivate), shows the lines to add on nginx, and also refuses xmlrpc.php and wp-config.php itself as a second line of defence. wp-settings.php can only be blocked by the server rule, because WordPress stops before any plugin loads when it is opened directly. Addresses on your trusted list are still let through for xmlrpc.php.

= 1.5.5 =
* Plugin Check clean-up: the limit rows on the Firewall tab build their field names through one escaped helper.

= 1.5.4 =
* SMTP password: a saved password is now shown as a masked field (••••••••••) with a Change password button, and is only replaced when you press that button. A blank field, or a browser auto-filling the field with your WordPress login password, can no longer overwrite it. An already-encrypted value is never encrypted twice.

= 1.5.3 =
* Two-factor login: when the email code cannot be sent, the second-step screen now says why (for example "SMTP Error: Could not authenticate") instead of pretending it was sent. Login > Email delivery shows the last email Sidcraft BotVanguard sent: when, to whom, through which server, and whether it was accepted or failed.

= 1.5.2 =
* Two-factor login: new setting "Send login codes to" (Login tab, Email delivery). Leave it empty to use each user's own profile address, or enter one address that receives every email code. The second-step screen now says where the code was sent (for example s*****@gmail.com), so a wrong profile address is easy to spot.

= 1.5.1 =
* The test email result no longer sounds like proof of delivery when the PHP mailer is used; it explains that the web server only accepted the message and suggests SMTP.

= 1.5.0 =
* New: Email delivery settings under Two-factor login (Login tab). Use the PHP mailer (WordPress default) or configure an SMTP server: host, encryption and port, user name and password (stored encrypted, or set SIDCRAFT_BOTSHIELD_SMTP_PASS in wp-config.php), From address and name, and whether it applies to Sidcraft BotVanguard emails only or every email on the site. "Send a test email to me" saves the values, sends a test and shows the server conversation if it fails. Login codes and alerts are sent through it.

= 1.4.1 =
* Two-factor login: new emergency switch for people locked out by a missing code. Besides the SIDCRAFT_BOTSHIELD_DISABLE_2FA constant in wp-config.php, an empty file named sidcraft-botshield-disable-2fa in the wp-content folder (upload it by FTP) turns two-factor login off. A notice reminds you to remove it.

= 1.4.0 =
* New: block an address that logs in with user names that do not exist, after a number of tries within a number of minutes, for a number of days (replaces the "lock out at once" tick box; an existing tick is kept as 1 try).
* New: block an address that keeps opening /wp-login.php, /wp-admin, /wp-register.php or /register without logging in, with the same three numbers. A normal login does not count; /register counts only when the site has no such page.

= 1.3.12 =
* New: the Quarantine list is always shown on the Scan tab (with a link at the top), so you can restore or delete quarantined files at any time.
* Plugin Check: two remaining notes.

= 1.3.11 =
* Plugin Check clean-up: escaping, sanitising and nonce notes, ordered placeholders, direct-access guard on the firewall files, scan "skip paths" setting renamed.

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

= 1.11.0 =
New optional scan check: look flagged files up in abuse.ch MalwareBazaar (needs your own Auth-Key; see the licence note).

= 1.10.1 =
Small wording improvement on the Firewall tab. No change in behaviour.

= 1.10.0 =
New optional Firewall rule: block web downloads of error_log, debug.log, php.ini and .user.ini.

= 1.9.0 =
New: export and import of all settings on the Dashboard tab, for backup and restore.

= 1.8.0 =
New optional Firewall rule: deny addresses with a high AbuseIPDB score (needs your API key). Off until you turn it on.

= 1.7.3 =
Code-quality fix (Plugin Check). No change in behaviour.

= 1.7.2 =
Code-quality fix (Plugin Check). No change in behaviour.

= 1.7.1 =
The forbidden files and words list now accepts wildcards such as *.tar and *gz.

= 1.7.0 =
New optional Firewall rule: block addresses that ask for forbidden file names such as backup.tar.gz. Off until you turn it on.

= 1.6.1 =
Fixes undefined-variable warnings on the login page when a custom login address is used.

= 1.6.0 =
Renamed to Sidcraft BotVanguard with its own menu and a new REST API protection. After updating by upload, activate Sidcraft BotVanguard and delete the old Sidcraft Bot Shield plugin; your settings are kept.

= 1.4.0 =
Adds attempt limits for unknown user names and for repeated visits to login and register pages.

= 1.3.12 =
Quarantined files can now always be viewed, restored or deleted from the Scan tab.

= 1.3.11 =
Tidies the code for the WordPress.org Plugin Check. No change in how it works.

= 1.3.10 =
Cuts false alarms in the malware scan and shows file paths.

= 1.3.9 =
Fixes a false “web shell” alarm on plugins that contain lists of scanner names. Update before you scan again.

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

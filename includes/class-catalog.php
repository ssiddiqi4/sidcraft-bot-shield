<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** The lists of well-known bots. Tokens are matched case-insensitively inside the User-Agent header. */
class Botvaguard_Catalog {

	/**
	 * Bots that are allowed. group => array( label, bots ). Each bot: token => array( name, rdns suffixes that prove it is genuine ).
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public static function allowed() {
		return array(
			'search' => array(
				'label' => __( 'Search engines', 'botvaguard' ),
				'bots'  => array(
					'googlebot' => array( 'Google', array( '.googlebot.com', '.google.com' ) ), 'adsbot-google' => array( 'Google Ads', array( '.googlebot.com', '.google.com' ) ), 'mediapartners-google' => array( 'Google AdSense', array( '.googlebot.com', '.google.com' ) ),
					'google-inspectiontool' => array( 'Google Search Console', array( '.googlebot.com', '.google.com' ) ), 'googleother' => array( 'Google (other)', array( '.googlebot.com', '.google.com' ) ), 'google-extended' => array( 'Google Gemini', array( '.googlebot.com', '.google.com' ) ),
					'bingbot' => array( 'Bing', array( '.search.msn.com' ) ), 'bingpreview' => array( 'Bing preview', array( '.search.msn.com' ) ), 'msnbot' => array( 'Bing (MSN)', array( '.search.msn.com' ) ),
					'applebot' => array( 'Apple (Siri, Spotlight, Safari)', array( '.applebot.apple.com' ) ),
					'duckduckbot' => array( 'DuckDuckGo', null ), 'slurp' => array( 'Yahoo', array( '.crawl.yahoo.net' ) ),
					'yandex' => array( 'Yandex', array( '.yandex.ru', '.yandex.net', '.yandex.com' ) ), 'baiduspider' => array( 'Baidu', array( '.baidu.com', '.baidu.jp' ) ),
					'qwantify' => array( 'Qwant', null ), 'seznambot' => array( 'Seznam', null ), 'yeti' => array( 'Naver', null ), 'petalbot' => array( 'Petal Search (Huawei)', null ), 'sogou' => array( 'Sogou', null ), 'ecosiabot' => array( 'Ecosia', null ), 'archive.org_bot' => array( 'Internet Archive', null ),
				),
			),
			'ai' => array(
				'label' => __( 'AI assistants and AI search', 'botvaguard' ),
				'bots'  => array(
					'gptbot' => array( 'OpenAI GPTBot', null ), 'oai-searchbot' => array( 'OpenAI (ChatGPT search)', null ), 'chatgpt-user' => array( 'ChatGPT (visits for a user)', null ),
					'claudebot' => array( 'Anthropic Claude', null ), 'claude-user' => array( 'Claude (visits for a user)', null ), 'claude-searchbot' => array( 'Claude search', null ), 'claude-web' => array( 'Claude (web)', null ), 'anthropic-ai' => array( 'Anthropic', null ),
					'perplexitybot' => array( 'Perplexity', null ), 'perplexity-user' => array( 'Perplexity (visits for a user)', null ),
					'copilot' => array( 'Microsoft Copilot', null ), 'cursor' => array( 'Cursor', null ), 'deepseek' => array( 'DeepSeek', null ),
					'meta-externalagent' => array( 'Meta AI', null ), 'meta-externalfetcher' => array( 'Meta AI (fetch)', null ), 'amazonbot' => array( 'Amazon (Alexa)', null ),
					'duckassistbot' => array( 'DuckDuckGo AI', null ), 'mistralai-user' => array( 'Mistral', null ), 'cohere-ai' => array( 'Cohere', null ), 'youbot' => array( 'You.com', null ),
					'gemini' => array( 'Google Gemini (user visits)', null ), 'google-notebooklm' => array( 'Google NotebookLM', null ), 'applebot-extended' => array( 'Apple Intelligence', array( '.applebot.apple.com' ) ),
					'ccbot' => array( 'Common Crawl (used to train AI)', null ), 'bytespider' => array( 'ByteDance (TikTok, Doubao)', null ), 'diffbot' => array( 'Diffbot', null ),
				),
			),
			'social' => array(
				'label' => __( 'Link previews (social and chat apps)', 'botvaguard' ),
				'bots'  => array(
					'facebookexternalhit' => array( 'Facebook', null ), 'facebot' => array( 'Facebook', null ), 'twitterbot' => array( 'X (Twitter)', null ), 'linkedinbot' => array( 'LinkedIn', null ),
					'slackbot' => array( 'Slack', null ), 'discordbot' => array( 'Discord', null ), 'whatsapp' => array( 'WhatsApp', null ), 'telegrambot' => array( 'Telegram', null ),
					'pinterestbot' => array( 'Pinterest', null ), 'redditbot' => array( 'Reddit', null ), 'skypeuripreview' => array( 'Skype', null ), 'embedly' => array( 'Embedly', null ),
				),
			),
			'monitor' => array(
				'label' => __( 'Uptime and site monitoring', 'botvaguard' ),
				'bots'  => array(
					'uptimerobot' => array( 'UptimeRobot', null ), 'pingdom' => array( 'Pingdom', null ), 'statuscake' => array( 'StatusCake', null ), 'site24x7' => array( 'Site24x7', null ),
					'betteruptime' => array( 'Better Stack', null ), 'newrelic' => array( 'New Relic', null ), 'gtmetrix' => array( 'GTmetrix', null ), 'lighthouse' => array( 'Google Lighthouse', null ), 'pagespeed' => array( 'PageSpeed Insights', null ),
				),
			),
			'services' => array(
				'label' => __( 'Services your site relies on (payments, WordPress, feed readers)', 'botvaguard' ),
				'bots'  => array(
					'wordpress/' => array( 'WordPress itself', null ), 'jetpack' => array( 'Jetpack', null ), 'stripe' => array( 'Stripe', null ), 'paypal' => array( 'PayPal', null ), 'square' => array( 'Square', null ),
					'github-hookshot' => array( 'GitHub', null ), 'mailchimp' => array( 'Mailchimp', null ), 'feedly' => array( 'Feedly', null ), 'feedbin' => array( 'Feedbin', null ), 'inoreader' => array( 'Inoreader', null ), 'newsblur' => array( 'NewsBlur', null ),
				),
			),
		);
	}

	/**
	 * Bots and tools that are blocked. group => array( label, tokens ).
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public static function blocked() {
		return array(
			'seo' => array(
				'label'  => __( 'SEO and data-mining crawlers', 'botvaguard' ),
				'tokens' => array( 'ahrefsbot', 'semrushbot', 'mj12bot', 'dotbot', 'blexbot', 'dataforseobot', 'serpstatbot', 'barkrowler', 'zoominfobot', 'seekportbot', 'megaindex', 'rogerbot', 'screaming frog', 'siteauditbot', 'linkpadbot', 'spbot', 'exabot', 'netpeaksite', 'sistrix', 'awariobot', 'scrapy', 'ia_archiver' ),
			),
			'tools' => array(
				'label'  => __( 'Scripts and headless browsers', 'botvaguard' ),
				'tokens' => array( 'python-requests', 'python-urllib', 'python-httpx', 'aiohttp', 'curl/', 'wget/', 'libwww-perl', 'java/', 'apache-httpclient', 'okhttp', 'go-http-client', 'node-fetch', 'axios/', 'got (', 'headlesschrome', 'phantomjs', 'selenium', 'puppeteer', 'playwright', 'httpclient', 'mechanize', 'winhttp', 'http_request2', 'lwp-', 'guzzlehttp', 'php/', 'ruby', 'scrapy' ),
			),
			'attack' => array(
				'label'  => __( 'Attack and scanner tools', 'botvaguard' ),
				'tokens' => array( 'sqlmap', 'nikto', 'masscan', 'nmap', 'zgrab', 'dirbuster', 'gobuster', 'wpscan', 'acunetix', 'nessus', 'havij', 'netsparker', 'openvas', 'w3af', 'wfuzz', 'ffuf', 'nuclei', 'zmeu', 'morfeus', 'fhscan', 'hydra' ),
			),
		);
	}

	/** Request paths only attackers ask for. Whole path segments only. */
	public static function scanner_regex() {
		return '#(^|/)(shell|shells|webshell|wshell|cmd|c99|r57|wso|b374k|backdoor|eval-stdin\.php|phpmyadmin|pma|myadmin|adminer|wp-config\.php|wp-config\.bak|cgi-bin|boaform|actuator|solr|\.env|\.git|\.svn|\.ds_store|\.aws|\.htpasswd|vendor/phpunit|wp-content/uploads/[^?]*\.php|wp-content/plugins/[^/]+/(readme\.txt)?\.\./)(/|$|\.|\?)#i';
	}
}

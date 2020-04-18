// WebRTC stands for “Web Real-Time Communication” and it allows for voice, video chat, and P2P sharing through your browser.
// Unfortunately, this capability can also expose your real IP address through browser STUN requests,
// even if you are using a good VPN service.
user_pref("media.peerconnection.enabled", false);
/* 2002: limit WebRTC IP leaks if using WebRTC
* In FF70+ these settings match Mode 4 (Mode 3 in older versions) (see [3])
* [TEST] https://browserleaks.com/webrtc
* [1] https://bugzilla.mozilla.org/buglist.cgi?bug_id=1189041,1297416,1452713
* [2] https://wiki.mozilla.org/Media/WebRTC/Privacy
* [3] https://tools.ietf.org/html/draft-ietf-rtcweb-ip-handling-12#section-5.2 ***/
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.no_host", true); // [FF51+]
// user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true); // [FF70+]

// Changing this preference to true will help to make Firefox more resistant to browser fingerprinting.
user_pref("privacy.resistFingerprinting", true);

// This is a new preference with Firefox 67+ to block fingerprinting.
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);

// Another new preference with Firefox 67+, this will block cryptominers.
user_pref("privacy.trackingprotection.cryptomining.enabled", true);

// Changing this to true will isolate cookies to the first party domain, which prevents tracking across multiple domains.
// First party isolation also does much more than isolating cookies, it affects: cookies, cache, HTTP Authentication, DOM Storage,
// Flash cookies, SSL and TLS session resumption, Shared Workers, blob URIs, SPDY and HTTP/2, automated cross-origin redirects,
// window.name, auto-form fill, HSTS and HPKP supercookies, broadcast channels, OCSP, favicons, mediasource URIs and Mediastream,
// speculative and prefetched connections.
// https://www.ghacks.net/2017/11/22/how-to-enable-first-party-isolation-in-firefox/
// ---
// A result of the Tor Uplift effort, this preference isolates all browser identifier sources (e.g. cookies) to the first party domain,
// with the goal of preventing tracking across different domains.
// (Don't do this if you are using the Firefox Addon "Cookie AutoDelete" with Firefox v58 or below.)
user_pref("privacy.firstparty.isolate", true);

// Another new update, this is Mozilla’s built-in tracking protection feature. This will use a Disconnect.me filter list,
// but may be redundant if you are using uBlock Origin 3rd party filters.
user_pref("privacy.trackingprotection.enabled", true);

// Setting this to false will disable geolocation tracking, which may be requested by a site you are visiting.
// As explained by Mozilla, this preference is enabled by default and utilizes Google Location Services to pinpoint your location.
// In order to do that, Firefox sends Google:
// 1. your computer’s IP address
// 2. information about nearby wireless access points
// 3. a random client identifier, which is assigned by Google (expires every two weeks)
// Before this data is sent to Google, you would first get a request by the site you are visiting.
// Therefore you do have control over this, even if geo remains enabled.
user_pref("geo.enabled", false);

// Setting this preference to false will block websites from being able to track the microphone and camera status of your device.
user_pref("media.navigator.enabled", false);

// This is an integer type preference with different values. Here are the cookie preference options:
// 0 = Accept all cookies by default
// 1 = Only accept from the originating site (block third-party cookies)
// 2 = Block all cookies by default
// 3 = Block cookies from unvisited sites
// 4 = New Cookie Jar policy (prevent storage access to trackers)
// Any selection between 1 and 4 would improve privacy. The New Cookie Jar policy (value 4) offers more protection,
// but it may also break the functionality of some websites. Ghacks has a discussion of the New Cookie Jar policy here.
// https://www.ghacks.net/2018/09/23/firefox-65-new-cookie-jar-policy-to-block-tracking/
user_pref("network.cookie.cookieBehavior", 4);

// This is another integer type preference that you should set to a value of 2.
// This preference determines when cookies are deleted. Here are the different options:
// 0 = Accept cookies normally (set if use Cookie Auto Delete extension)
// 1 = Prompt for each cookie
// 2 = Accept for current session only
// 3 = Accept for N days
// With a value of 2, websites you visit should work without any problems, and all cookies will be automatically deleted at the end of the session.
user_pref("network.cookie.lifetimePolicy", 0);

// Setting this preference to true will disable Firefox from “prefetching” DNS requests.
// While advanced domain name resolution may slightly improve page load speeds, this also comes with some risks, as described in this paper.
// https://www.usenix.org/legacy/events/leet10/tech/full_papers/Krishnan.pdf
user_pref("network.dns.disablePrefetch", true);

// Similar to prefetching DNS requests above, setting this preference to false will prevent pages from being prefetched by Firefox.
// Mozilla has deployed this feature to speed up web pages that you might visit. However, it will use up resources and poses a risk to privacy.
// This is another example of performance at the price of privacy.
user_pref("network.prefetch-next", false);

// Disable Firefox prefetching pages it thinks you will visit next:
// Prefetching causes cookies from the prefetched site to be loaded and other potentially unwanted behavior.
// user_pref("network.dns.disablePrefetchFromHTTPS", true);
user_pref("network.predictor.enabled", false);
user_pref("network.predictor.enable-prefetch", false);

// WebGL is a potential security risk, which is why it is best disabled by setting webgl.disabled to true.
// Another issue with WebGL is that it can be used to fingerprint your device.
user_pref("webgl.disabled", true);
user_pref("webgl.enable-webgl2", false);
/* 2012: limit WebGL ***/
user_pref("webgl.min_capability_mode", true);
user_pref("webgl.disable-fail-if-major-performance-caveat", true);

// This prevents websites from getting notifications if you copy, paste, or cut something from the page.
user_pref("dom.event.clipboardevents.enabled", false);

// The attribute would be useful for letting websites track visitors' clicks.
user_pref("browser.send_pings", false);
user_pref("browser.send_pings.require_same_host", true);

// Disable preloading of autocomplete URLs. Firefox preloads URLs that autocomplete when a user types into the address bar,
// which is a concern if URLs are suggested that the user does not want to connect to.
// https://www.ghacks.net/2017/07/24/disable-preloading-firefox-autocomplete-urls/
// user_pref("browser.urlbar.speculativeConnect.enabled", false);

// This preference controls when to store extra information about a session: contents of forms, scrollbar positions, cookies, and POST data. Details
// 0 = Store extra session data for any site. (Default starting with Firefox 4.)
// 1 = Store extra session data for unencrypted (non-HTTPS) sites only. (Default before Firefox 4.)
// 2 = Never store extra session data.
user_pref("browser.sessionstore.privacy_level", 2);

// Disables sending additional analytics to web servers.
user_pref("beacon.enabled", false);

// Prevents Firefox from sending information about downloaded executable files to Google Safe Browsing
// to determine whether it should be blocked for safety reasons.
user_pref("browser.safebrowsing.downloads.remote.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.url", "");

// Not rendering IDNs as their Punycode equivalent leaves you open to phishing attacks that can be very difficult to notice.
// https://krebsonsecurity.com/2018/03/look-alike-domains-and-visual-confusion/#more-42636
user_pref("network.IDN_show_punycode", true);

// Disable IPv6
user_pref("network.dns.disableIPv6", true);

// GHACKS user.js

/* 0105a: disable Activity Stream telemetry ***/
// user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
// user_pref("browser.newtabpage.activity-stream.telemetry", false);

/* 0204: disable using the OS's geolocation service ***/
// user_pref("geo.provider.ms-windows-location", false); // [WINDOWS]
// user_pref("geo.provider.use_corelocation", false); // [MAC]
// user_pref("geo.provider.use_gpsd", false); // [LINUX]

/* 0206: disable geographically specific results/search engines e.g. "browser.search.*.US"
 * i.e. ignore all of Mozilla's various search engines in multiple locales ***/
user_pref("browser.search.geoSpecificDefaults", false);
user_pref("browser.search.geoSpecificDefaults.url", "");

/* 0309: disable sending Flash crash reports ***/
user_pref("dom.ipc.plugins.flash.subprocess.crashreporter.enabled", false);

/* 0310: disable sending the URL of the website where a plugin crashed ***/
user_pref("dom.ipc.plugins.reportCrashURL", false);

/* 0320: disable about:addons' Recommendations pane (uses Google Analytics) ***/
// user_pref("extensions.getAddons.showPane", false); // [HIDDEN PREF]

/* 0321: disable recommendations in about:addons' Extensions and Themes panes [FF68+] ***/
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);

/* 0330: disable telemetry
 * the pref (.unified) affects the behaviour of the pref (.enabled)
 * IF unified=false then .enabled controls the telemetry module
 * IF unified=true then .enabled ONLY controls whether to record extended data
 * so make sure to have both set as false
 * [NOTE] FF58+ 'toolkit.telemetry.enabled' is now LOCKED to reflect prerelease
 * or release builds (true and false respectively), see [2]
 * [1] https://firefox-source-docs.mozilla.org/toolkit/components/telemetry/telemetry/internals/preferences.html
 * [2] https://medium.com/georg-fritzsche/data-preference-changes-in-firefox-58-2d5df9c428b5 ***/
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.enabled", false); // see [NOTE] above FF58+
user_pref("toolkit.telemetry.server", "data:,");
// user_pref("toolkit.telemetry.archive.enabled", false);
// user_pref("toolkit.telemetry.newProfilePing.enabled", false); // [FF55+]
// user_pref("toolkit.telemetry.shutdownPingSender.enabled", false); // [FF55+]
// user_pref("toolkit.telemetry.updatePing.enabled", false); // [FF56+]
// user_pref("toolkit.telemetry.bhrPing.enabled", false); // [FF57+] Background Hang Reporter
// user_pref("toolkit.telemetry.firstShutdownPing.enabled", false); // [FF57+]

/* 0331: disable Telemetry Coverage
 * [1] https://blog.mozilla.org/data/2018/08/20/effectively-measuring-search-in-firefox/ ***/
// user_pref("toolkit.telemetry.coverage.opt-out", true); // [HIDDEN PREF]
// user_pref("toolkit.coverage.opt-out", true); // [FF64+] [HIDDEN PREF]
// user_pref("toolkit.coverage.endpoint.base", "");

/* 0340: disable Health Reports
 * [SETTING] Privacy & Security>Firefox Data Collection & Use>Allow Firefox to send technical... data ***/
// user_pref("datareporting.healthreport.uploadEnabled", false);

/* 0341: disable new data submission, master kill switch [FF41+]
 * If disabled, no policy is shown or upload takes place, ever
 * [1] https://bugzilla.mozilla.org/1195552 ***/
user_pref("datareporting.policy.dataSubmissionEnabled", false);

/* 0342: disable Studies (see 0503)
 * [SETTING] Privacy & Security>Firefox Data Collection & Use>Allow Firefox to install and run studies ***/
// user_pref("app.shield.optoutstudies.enabled", false);

/* 0350: disable Crash Reports ***/
user_pref("breakpad.reportURL", "");
// user_pref("browser.tabs.crashReporting.sendReport", false); // [FF44+]
// user_pref("browser.crashReports.unsubmittedCheck.enabled", false); // [FF51+]

/* 0351: disable backlogged Crash Reports
 * [SETTING] Privacy & Security>Firefox Data Collection & Use>Allow Firefox to send backlogged crash reports  ***/
// user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false); // [FF58+]

/* 0390: disable Captive Portal detection
 * [1] https://www.eff.org/deeplinks/2017/08/how-captive-portals-interfere-wireless-security-and-privacy
 * [2] https://wiki.mozilla.org/Necko/CaptivePortal ***/
user_pref("captivedetect.canonicalURL", "");
user_pref("network.captive-portal-service.enabled", false); // [FF52+]

/* 0391: disable Network Connectivity checks [FF65+]
 * [1] https://bugzilla.mozilla.org/1460537 ***/
user_pref("network.connectivity-service.enabled", false);

/* 0503: disable Normandy/Shield [FF60+]
 * Shield is an telemetry system (including Heartbeat) that can also push and test "recipes"
 * [1] https://wiki.mozilla.org/Firefox/Shield
 * [2] https://github.com/mozilla/normandy ***/
// user_pref("app.normandy.enabled", false);
// user_pref("app.normandy.api_url", "");

/* 0506: disable PingCentre telemetry (used in several System Add-ons) [FF57+]
 * Currently blocked by 'datareporting.healthreport.uploadEnabled' (see 0340) ***/
// user_pref("browser.ping-centre.telemetry", false);

/* 1610: ALL: enable the DNT (Do Not Track) HTTP header
 * [NOTE] DNT is enforced with Enhanced Tracking Protection regardless of this pref
 * [SETTING] Privacy & Security>Enhanced Tracking Protection>Send websites a "Do Not Track" signal... ***/
user_pref("privacy.donottrackheader.enabled", true);

/* 2623: disable permissions delegation [FF73+]
 * Currently applies to cross-origin geolocation, camera, mic and screen-sharing
 * permissions, and fullscreen requests. Disabling delegation means any prompts
 * for these will show/use their correct 3rd party origin
 * [1] https://groups.google.com/forum/#!topic/mozilla.dev.platform/BdFOMAuCGW8/discussion */
// user_pref("permissions.delegation.enabled", false);

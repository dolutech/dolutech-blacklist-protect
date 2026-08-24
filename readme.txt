=== Dolutech Blacklist Protect ===
Contributors: Dolutech
Tags: security, blacklist, ip-block, geolocation, brute-force
Requires at least: 6.7
Tested up to: 7.1
Requires PHP: 8.2
Stable tag: 0.9.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Advanced WordPress protection with automatic blacklists, MaxMind country blocking, brute-force protection, reCAPTCHA, and XML-RPC security.

== Description ==

**Dolutech Blacklist Protect** is an advanced security system that provides multiple layers of protection for WordPress sites through a modern and intuitive interface.

### Geolocation Blocking
- **MaxMind GeoIP2 Integration**: Automatically block entire countries
- **Automatic Validation**: Test credentials when saving settings
- **Smart Caching**: Reduce API requests with 24-hour per-IP caching
- **Intuitive Interface**: Reference list of commonly blocked countries
- **ISO Codes**: Use two-letter country codes (CN, RU, BR, and more)

### Advanced Blacklist System
- **Dolutech Blacklist**: Automatically updated twice daily
- **Third-Party Blacklists**: Add external .txt list URLs
- **Manual Blocking**: Manage specific IP addresses
- **Smart Whitelist**: Always allow fixed IPs and DDNS domains

### Brute-Force Protection
- Automatically block after a configurable number of failed attempts
- **Temporary Blocking**: Configure the duration in minutes
- **Permanent Blocking**: For maximum protection
- **XML-RPC Protection**: Configurable complete or partial blocking

### Specific User Blocking
- Configure trap usernames such as admin, root, and administrator
- Immediately block the IP when a protected username is used
- Automatic validation: block only when the username does not exist

### Intelligent Unblocking
- Request unblocking by email with a secure token
- **Secret Key**: Optional additional security layer
- **Google reCAPTCHA v2**: Bot protection for forms
- Responsive interface with toggles for viewing keys

### Complete Monitoring
- Dashboard with detailed statistics by source
- Active temporary blocks with remaining time
- Pending unblock tokens
- Third-party blacklist status and counters

### Advanced Features
- **Dynamic Interface**: JavaScript for conditional fields
- **Robust Validation**: Nonces, sanitization, and escaping
- **Automatic Logs**: Record security events
- **Cron Jobs**: Automatically clean up old data

Ideal for **developers**, **administrators**, and **agencies** that need strong security without sacrificing usability.

== Installation ==

1. **Upload**: Upload the `dolutech-blacklist-protect` folder to `/wp-content/plugins/`
2. **Activate**: Activate the plugin under **Plugins** -> **Installed Plugins**
3. **Configure**: Go to **Settings** -> **Dolutech Blacklist Protect**
4. **Requirements**: PHP 8.2+ and WordPress 6.7+ are checked automatically
5. **Recommendations**:
   - Configure your whitelist BEFORE enabling blocking features
   - Test the email system for unblock requests
   - Configure reCAPTCHA for maximum protection

== Frequently Asked Questions ==

= How does geolocation blocking work? =

When MaxMind GeoIP2 is enabled, enter your API credentials and select the countries to block using ISO codes. When someone from a blocked country accesses the site, the plugin queries the MaxMind API, identifies the IP country, and blocks it automatically. Results are cached for 24 hours to improve performance.

= Where can I get MaxMind credentials? =

Visit https://www.maxmind.com/en/geolite2/signup and create a free account. Under "Manage License Keys", create a new key. You will receive an Account ID and a License Key. The plugin validates them automatically when they are saved.

= How are blacklists updated? =

Blacklists are updated automatically twice daily through WordPress cron. This includes the official Dolutech blacklist and all configured third-party lists.

= What if my IP is blocked? =

Configure your **whitelist** first. Add a fixed IP or DDNS domain under **Settings** -> **Whitelist**. IPs blocked manually can request an unblock review.

= How does the unblocking system work? =

1. A blocked IP sees a "Request Unblock" option
2. The system sends a secure token by email to administrators
3. An administrator clicks the link to unblock the IP
4. If configured, reCAPTCHA and the secret key are also required

= Can I use reCAPTCHA on the forms? =

Yes. Configure your Google reCAPTCHA v2 keys under **Settings** -> **reCAPTCHA**. It is added automatically to unblock forms.

= How can I protect specific usernames? =

Use **Specific User Blocking** and add usernames such as "admin" and "root". Any login attempt with a protected username that does not exist blocks the IP immediately.

= Is XML-RPC completely disabled? =

You can choose **Complete Blocking**, which disables everything, or **Partial Protection**, which removes dangerous methods and monitors attempts.

= Are third-party blacklists trustworthy? =

You should add only URLs that you trust. The plugin validates IP addresses before blocking them. Sources such as Spamhaus and AbuseIPDB are common examples.

= Does the plugin affect performance? =

The impact is minimal. Blocks are checked at the beginning of the request. The plugin uses caching and automatically removes old data.

= Can I contribute? =

Yes. GitHub: [https://github.com/dolutech](https://github.com/dolutech) | Suggestions: support@dolutech.com

== Screenshots ==

1. Main dashboard with detailed blacklist statistics
2. MaxMind GeoIP2 configuration with automatic credential validation
3. Country blocking interface with ISO codes and common countries
4. Login protection settings with temporary blocking
5. Third-party blacklist management interface with status and counters
6. Unblock system with reCAPTCHA
7. Specific user blocking configuration
8. Complete and partial XML-RPC protection settings

== Changelog ==

= 0.9.0 =
* **New**: Security event logging with a complete dashboard (filters, pagination, and cleanup)
* **New**: CIDR-range and user-agent blocking (IPv4 and IPv6)
* **New**: REST API for managing blocks, logs, and blacklist updates (Application Passwords)
* **New**: Telegram and webhook notifications for blocking events
* **Improvement**: Daily maintenance cron job with automatic cleanup of old logs

= 0.8.0 =
* **Compatibility**: Tested up to WordPress 7.1
* **Fix**: reCAPTCHA now works on unblock forms with inline rendering
* **Fix**: The admin page no longer downloads the blacklist from GitHub on every visit
* **Fix**: Generic and translatable login message without revealing the plugin
* **Security**: Automatic reporting respects the "Automatic Reporting" toggle
* **Security**: Rate limiting on unblock requests (2 per day per IP) and secret-key attempts (5 per 15 minutes per IP)
* **Security**: Secret keys are stored as hashes and are no longer shown in HTML
* **Security**: Support for real client IPs behind a proxy or CDN (configurable X-Forwarded-For)
* **Performance**: Blacklists stored as a non-autoloaded string; persisted statistics; negative MaxMind cache; whitelist DNS cache
* **Maintenance**: uninstall.php removes all data; ABSPATH guards in all includes; i18n (Text Domain and .pot)
* **Docs**: FAQ corrected to clarify that blocking applies to nonexistent users

= 0.7.0 =
* **New**: MaxMind GeoIP2 integration for geolocation blocking
* **New**: Automatic validation of MaxMind credentials when saving
* **New**: Fields for the MaxMind Account ID and License Key
* **New**: Country blocking by two-letter ISO code
* **New**: 24-hour geolocation caching for better performance
* **New**: Automatic cleanup of expired geolocation cache
* **Improvement**: Custom blocking pages for geolocation blocks
* **Improvement**: Toggle to safely show the MaxMind License Key using textContent
* **Improvement**: Conditional interface shown after credentials are validated
* **Docs**: Complete instructions for obtaining MaxMind credentials
* **Security**: Country-code validation with a regular expression
* **Security**: Sanitization and escaping for all MaxMind fields

= 0.6.0 =
* **New**: Toggle button to show or hide the secret key
* **New**: Blocking of specific usernames (admin, root, and others)
* **New**: Automatic validation of whether usernames exist
* **Improvement**: Dynamic JavaScript interface for conditional fields
* **Improvement**: Login interception through the wp_authenticate hook
* **Docs**: Complete instructions for dynamic fields and specific user blocking

= 0.5.0 =
* **New**: Google reCAPTCHA v2 integration for unblock forms
* **New**: Complete reCAPTCHA configuration (Site Key and Secret Key)
* **New**: Robust server-side reCAPTCHA validation
* **Improvement**: Responsive forms with an improved design
* **Improvement**: Graceful error handling for reCAPTCHA
* **Security**: Timeout and IP validation for reCAPTCHA requests

= 0.4.0 =
* **New**: Third-party blacklist system with external list URLs
* **New**: Complete interface for managing external lists
* **New**: Detailed statistics by source
* **New**: Visual status for blacklists (Active, Error, and Pending)
* **Improvement**: Parallel updates for multiple lists
* **Improvement**: Reorganized dashboard

= 0.3.0 =
* **New**: Temporary blocking in minutes, not hours
* **New**: Secret key for unblocking
* **New**: Configurable complete and partial XML-RPC protection
* **New**: Interface showing the remaining temporary-block time
* **Improvement**: Custom temporary-block pages
* **Improvement**: JavaScript for conditional fields

= 0.2.0 =
* **New**: Complete unblock request system
* **New**: Secure email tokens valid for 24 hours
* **New**: Maximum login-attempt configuration
* **New**: Automatic emails to administrators
* **Improvement**: Admin interface for pending tokens
* **Improvement**: Automatic cleanup of expired tokens

= 0.1.0 =
* **New**: Advanced brute-force protection
* **New**: Automatic reporting of malicious IP addresses
* **New**: Login-attempt counters using transients
* **Improvement**: More efficient blocking system
* **Security**: Improved IP validation

= 0.0.1 =
* **Initial release**: Stable first version
* Automatic Dolutech blacklist updated twice daily
* Manual IP blocking and unblocking
* Manual reporting system for abuse@dolutech.com
* Whitelist with fixed-IP and DDNS-domain support
* Complete administration interface
* WordPress 6.7+ and PHP 8.2+ compatibility

== External Services ==

This plugin connects to external services to provide its full functionality.

**Dolutech Blacklist (Required)**
- URL: https://raw.githubusercontent.com/dolutech/blacklist-dolutech/refs/heads/main/Black-list-semanal-dolutech.txt
- Description: Official malicious-IP list, updated automatically
- Terms: https://dolutech.com/termos-de-uso/
- Privacy: https://dolutech.com/politica-de-privacidade/

**Email System (Optional)**
- abuse@dolutech.com: For automatic reports
- Site administrators: For unblock notifications
- Uses the native WordPress `wp_mail()` function

**Google reCAPTCHA v2 (Optional)**
- API: https://www.google.com/recaptcha/api/siteverify
- Description: Form validation against bots
- Configuration: Requires a Site Key and Secret Key
- Terms: https://developers.google.com/recaptcha/docs/terms

**MaxMind GeoIP2 (Optional)**
- API: https://geolite.info/geoip/v2.1/country/
- Description: IP geolocation for country blocking
- Configuration: Requires an Account ID and License Key
- Registration: https://www.maxmind.com/en/geolite2/signup
- Terms: https://www.maxmind.com/en/geolite2/eula
- Privacy: IP data queried by the plugin is cached locally for 24 hours

**Third-Party Blacklists (Optional)**
- URLs are defined by the site administrator
- Automatic validation of .txt list format
- Examples: Spamhaus and AbuseIPDB

== Upgrade Notice ==

= 0.9.0 =
New features: security event logs, CIDR and user-agent blocking, REST API, and Telegram/webhook notifications.

= 0.8.0 =
Security and performance improvements: fixed reCAPTCHA, automatic-reporting toggle, unblock-form rate limits, hashed secret keys, a faster admin page, and WordPress 7.1 compatibility.

= 0.7.0 =
Geolocation blocking with complete MaxMind GeoIP2 integration. Block entire countries using two-letter ISO codes with smart caching and automatic credential validation.

= 0.6.0 =
New features: secret-key visibility toggle and specific-user blocking with a dynamic configuration interface.

= 0.5.0 =
Google reCAPTCHA v2 integration. Add bot protection to unblock forms by configuring your keys.

= 0.4.0 =
Third-party blacklists. Add external .txt list URLs with dashboard statistics.

= 0.3.0 =
Temporary blocking in minutes, a secret key, and configurable XML-RPC protection.

= 0.2.0 =
Secure email tokens for unblock requests. Blocked IPs can request an administrator review.

= 0.1.0 =
Brute-force protection with automatic reporting and configurable thresholds.

= 0.0.1 =
First stable release with automatic blacklists, manual blocking, whitelists, and reporting.

== License ==

This plugin is licensed under the GNU General Public License v2.0 or later. For more information, visit https://www.gnu.org/licenses/gpl-2.0.html.

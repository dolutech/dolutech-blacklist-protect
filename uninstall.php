<?php
/**
 * Remove all Dolutech Blacklist Protect data when the plugin is deleted.
 *
 * @package Dolutech_Blacklist_Protect
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

$blwp_options = [
    'blwp_blacklist_enabled',
    'blwp_blacklisted_ips',
    'blwp_last_update',
    'blwp_manual_blocked_ips',
    'blwp_whitelist',
    'blwp_temp_blocked_ips',
    'blwp_unblock_tokens',
    'blwp_max_login_attempts',
    'blwp_temp_block_enabled',
    'blwp_temp_block_duration',
    'blwp_secret_key_enabled',
    'blwp_secret_key',
    'blwp_user_block_enabled',
    'blwp_blocked_usernames',
    'blwp_recaptcha_enabled',
    'blwp_recaptcha_site_key',
    'blwp_recaptcha_secret_key',
    'blwp_block_xmlrpc',
    'blwp_xmlrpc_log_attempts',
    'blwp_max_xmlrpc_attempts',
    'blwp_disable_dangerous_xmlrpc',
    'blwp_auto_report',
    'blwp_third_party_blacklists',
    'blwp_maxmind_enabled',
    'blwp_maxmind_account_id',
    'blwp_maxmind_api_key',
    'blwp_blocked_countries',
    'blwp_last_fetch_stats',
    'blwp_cidr_blocked',
    'blwp_ua_blocked',
    'blwp_ua_block_enabled',
    'blwp_telegram_enabled',
    'blwp_telegram_bot_token',
    'blwp_telegram_chat_id',
    'blwp_webhook_enabled',
    'blwp_webhook_url',
    'blwp_notify_events',
    'blwp_log_retention_days',
    'blwp_proxy_mode',
    'blwp_version',
];

foreach ($blwp_options as $blwp_option) {
    delete_option($blwp_option);
}

// Remove remaining transients (login attempts, MaxMind cache, DNS, and rate limits).
global $wpdb;
$blwp_options_table = $wpdb->options;
/* phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WordPress has no bulk API for deleting plugin transients during uninstall. */
$wpdb->query(
    $wpdb->prepare(
        'DELETE FROM %i WHERE option_name LIKE %s OR option_name LIKE %s',
        $blwp_options_table,
        $wpdb->esc_like('_transient_blwp_') . '%',
        $wpdb->esc_like('_transient_timeout_blwp_') . '%'
    )
);

// Remove scheduled events.
wp_clear_scheduled_hook('blwp_update_blacklist_hook');
wp_clear_scheduled_hook('blwp_daily_maintenance_hook');

// Remove the custom log table.
$blwp_logs_table = $wpdb->prefix . 'blwp_logs';
/* phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Dropping the plugin-owned log table is part of the uninstall contract. */
$wpdb->query($wpdb->prepare('DROP TABLE IF EXISTS %i', $blwp_logs_table));

// Remove log files through the WordPress Filesystem API.
$blwp_upload_dir = wp_upload_dir();
$blwp_log_dir = trailingslashit($blwp_upload_dir['basedir']) . 'dolutech-blacklist-protect';

require_once ABSPATH . 'wp-admin/includes/file.php';
global $wp_filesystem;

if (WP_Filesystem() && $wp_filesystem->exists($blwp_log_dir)) {
    $wp_filesystem->delete($blwp_log_dir, true);
}

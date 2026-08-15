<?php
/**
 * Limpeza completa dos dados do Dolutech Blacklist Protect ao deletar o plugin.
 *
 * @package Dolutech_Blacklist_Protect
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

$options = [
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
];

foreach ($options as $option) {
    delete_option($option);
}

// Remove transients restantes (tentativas de login, cache MaxMind, DNS, rate-limits).
global $wpdb;
$wpdb->query(
    $wpdb->prepare(
        "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
        $wpdb->esc_like('_transient_blwp_') . '%',
        $wpdb->esc_like('_transient_timeout_blwp_') . '%'
    )
);

// Remove cron e arquivos de log.
wp_clear_scheduled_hook('blwp_update_blacklist_hook');
wp_clear_scheduled_hook('blwp_daily_maintenance_hook');

// Remove tabela de logs.
global $wpdb;
$logs_table = $wpdb->prefix . 'blwp_logs';
$wpdb->query("DROP TABLE IF EXISTS {$logs_table}");

$upload_dir = wp_upload_dir();
$log_dir = $upload_dir['basedir'] . '/dolutech-blacklist-protect';
if (is_dir($log_dir)) {
    array_map('unlink', glob($log_dir . '/*'));
    rmdir($log_dir);
}

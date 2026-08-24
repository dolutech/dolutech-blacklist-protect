<?php
/**
 * Plugin Name: Dolutech Blacklist Protect
 * Description: Advanced WordPress protection with automatic blacklists, brute-force mitigation, automatic reporting, custom IP blocking, and MaxMind geolocation.
 * Version: 0.9.1
 * Requires at least: 6.7
 * Requires PHP: 8.2
 * Tested up to: 7.1
 * Author: Dolutech
 * Author URI: https://dolutech.com
 * License: GPL2
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: dolutech-blacklist-protect
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) {
    exit;
}

define('BLWP_DIR', plugin_dir_path(__FILE__));
define('BLWP_URL', plugin_dir_url(__FILE__));
define('BLWP_VERSION', '0.9.1');

require_once BLWP_DIR . 'includes/functions.php';
require_once BLWP_DIR . 'includes/admin-page.php';
require_once BLWP_DIR . 'includes/cron-jobs.php';
require_once BLWP_DIR . 'includes/integration-security-plugins.php';
require_once BLWP_DIR . 'includes/maxmind-integration.php';
require_once BLWP_DIR . 'includes/logs.php';
require_once BLWP_DIR . 'includes/cidr-ua.php';
require_once BLWP_DIR . 'includes/notifications.php';
require_once BLWP_DIR . 'includes/rest-api.php';

if (is_admin()) {
    require_once BLWP_DIR . 'includes/admin-logs-page.php';
}

register_activation_hook(__FILE__, 'blwp_activate_plugin');
register_deactivation_hook(__FILE__, 'blwp_deactivate_plugin');

/**
 * Upgrade path: garante tabela de logs e cron diário também em sites que
 * atualizam o plugin via auto-update (activation hook não dispara em update).
 */
add_action('admin_init', 'blwp_maybe_upgrade');
function blwp_maybe_upgrade() {
    if (get_option('blwp_version', '0') === BLWP_VERSION) {
        return;
    }

    if (!wp_next_scheduled('blwp_update_blacklist_hook')) {
        wp_schedule_event(time(), 'twicedaily', 'blwp_update_blacklist_hook');
    }

    blwp_create_logs_table();

    if (!wp_next_scheduled('blwp_daily_maintenance_hook')) {
        wp_schedule_event(time(), 'daily', 'blwp_daily_maintenance_hook');
    }

    update_option('blwp_version', BLWP_VERSION);
}

function blwp_activate_plugin() {
    if (version_compare(PHP_VERSION, '8.2', '<')) {
        deactivate_plugins(plugin_basename(__FILE__));
        wp_die(
            esc_html__('Este plugin requer PHP 8.2 ou superior.', 'dolutech-blacklist-protect'),
            esc_html__('Versão de PHP incompatível', 'dolutech-blacklist-protect'),
            ['back_link' => true]
        );
    }

    global $wp_version;
    if (version_compare($wp_version, '6.7', '<')) {
        deactivate_plugins(plugin_basename(__FILE__));
        wp_die(
            esc_html__('Este plugin requer WordPress 6.7 ou superior.', 'dolutech-blacklist-protect'),
            esc_html__('Versão do WordPress incompatível', 'dolutech-blacklist-protect'),
            ['back_link' => true]
        );
    }

    if (!wp_next_scheduled('blwp_update_blacklist_hook')) {
        wp_schedule_event(time(), 'twicedaily', 'blwp_update_blacklist_hook');
    }

    // Só define o default quando a opção ainda não existe (não sobrescreve "off" em reativação).
    if (get_option('blwp_blacklist_enabled', null) === null) {
        update_option('blwp_blacklist_enabled', 1);
    }

    // Migração 0.7 → 0.8: blacklist em string com autoload off (performance)
    $ips = get_option('blwp_blacklisted_ips', []);
    if (!empty($ips)) {
        update_option('blwp_blacklisted_ips', is_array($ips) ? implode(PHP_EOL, $ips) : $ips, false);
    }

    // Cria tabela de logs
    blwp_create_logs_table();

    // Cron diário de manutenção (purge de logs antigos)
    if (!wp_next_scheduled('blwp_daily_maintenance_hook')) {
        wp_schedule_event(time(), 'daily', 'blwp_daily_maintenance_hook');
    }

    update_option('blwp_version', BLWP_VERSION);
}

function blwp_deactivate_plugin() {
    wp_clear_scheduled_hook('blwp_update_blacklist_hook');
    wp_clear_scheduled_hook('blwp_daily_maintenance_hook');
}

add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'blwp_add_plugin_action_links');
function blwp_add_plugin_action_links($links) {
    $settings_link = '<a href="' . esc_url(admin_url('options-general.php?page=blacklist-wp-protect')) . '">' . esc_html__('Configurações', 'dolutech-blacklist-protect') . '</a>';
    $github_link   = '<a href="https://github.com/dolutech" target="_blank" rel="noopener noreferrer">GitHub</a>';
    $dolutech_link = '<a href="https://dolutech.com" target="_blank" rel="noopener noreferrer">Dolutech</a>';
    array_unshift($links, $settings_link, $github_link, $dolutech_link);
    return $links;
}

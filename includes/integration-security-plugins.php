<?php

if (!defined('ABSPATH')) {
    exit;
}

add_action('init', 'blwp_hook_security_plugins');
function blwp_hook_security_plugins() {
    if (!get_option('blwp_auto_report', 0)) {
        return;
    }

    add_action('security_plugin_ip_blocked', function ($ip, $reason = 'Bloqueio automático') {
        blwp_send_abuse_report($ip, $reason);
    });
}

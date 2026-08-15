<?php
/**
 * Stubs mínimos de funções do WordPress para testes unitários.
 *
 * @package Dolutech_Blacklist_Protect
 */

if (!function_exists('get_option')) {
    /** @var array<string,mixed> */
    $GLOBALS['blwp_test_options'] = [];

    function get_option($option, $default = false) {
        return $GLOBALS['blwp_test_options'][$option] ?? $default;
    }

    function update_option($option, $value, $autoload = null) {
        $GLOBALS['blwp_test_options'][$option] = $value;
        return true;
    }

    function delete_option($option) {
        unset($GLOBALS['blwp_test_options'][$option]);
        return true;
    }
}

if (!function_exists('get_transient')) {
    /** @var array<string,mixed> */
    $GLOBALS['blwp_test_transients'] = [];

    function get_transient($key) {
        $data = $GLOBALS['blwp_test_transients'][$key] ?? null;
        if ($data === null) {
            return false;
        }
        if (is_array($data) && $data['expires'] < time()) {
            unset($GLOBALS['blwp_test_transients'][$key]);
            return false;
        }
        return is_array($data) ? $data['value'] : $data;
    }

    function set_transient($key, $value, $expiration = 0) {
        $GLOBALS['blwp_test_transients'][$key] = [
            'value'   => $value,
            'expires' => $expiration ? time() + $expiration : PHP_INT_MAX,
        ];
        return true;
    }

    function delete_transient($key) {
        unset($GLOBALS['blwp_test_transients'][$key]);
        return true;
    }
}

if (!function_exists('sanitize_text_field')) {
    function sanitize_text_field($str) {
        return trim((string) $str);
    }
}

if (!function_exists('wp_unslash')) {
    function wp_unslash($value) {
        return is_string($value) ? stripslashes($value) : $value;
    }
}

if (!function_exists('sanitize_key')) {
    function sanitize_key($key) {
        return strtolower(preg_replace('/[^a-z0-9_\-]/i', '', (string) $key));
    }
}

if (!function_exists('esc_html')) {
    function esc_html($text) {
        return htmlspecialchars((string) $text, ENT_QUOTES, 'UTF-8');
    }
}

<?php
/**
 * Bloqueio por faixa CIDR e user-agent.
 *
 * @package Dolutech_Blacklist_Protect
 * @since 0.9.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Verifica se um IP está dentro de um bloco CIDR (IPv4 e IPv6).
 *
 * @param string $ip   Endereço IP.
 * @param string $cidr Bloco CIDR (ex.: 192.168.1.0/24, 2001:db8::/32).
 * @return bool
 */
function blwp_ip_in_cidr($ip, $cidr) {
    $parts = explode('/', $cidr);
    $subnet = trim($parts[0]);
    $prefix = isset($parts[1]) ? (int) $parts[1] : null;

    $ip_bin = @inet_pton($ip);
    $sub_bin = @inet_pton($subnet);
    if ($ip_bin === false || $sub_bin === false) {
        return false;
    }

    // Normaliza o prefixo conforme a família do IP.
    if (strlen($ip_bin) === 4) {
        $bits = 32;
        if ($prefix === null || $prefix < 0 || $prefix > 32) {
            $prefix = 32;
        }
    } else {
        $bits = 128;
        if ($prefix === null || $prefix < 0 || $prefix > 128) {
            $prefix = 128;
        }
    }

    // Máscara binária.
    $mask = str_repeat("\xff", intdiv($prefix, 8));
    if ($prefix % 8 !== 0) {
        // & 0xff: chr() exige byte em [0,255] (PHP 8.5+ deprecia valores fora).
        $mask .= chr((0xff << (8 - ($prefix % 8))) & 0xff);
    }
    $mask = str_pad($mask, strlen($ip_bin), "\x00");

    return (substr($ip_bin, 0, strlen($mask)) & $mask) === (substr($sub_bin, 0, strlen($mask)) & $mask);
}

/**
 * Verifica se o IP está em alguma faixa CIDR configurada.
 *
 * @param string $ip Endereço IP.
 * @return bool
 */
function blwp_is_cidr_blocked($ip) {
    $cidrs = get_option('blwp_cidr_blocked', []);
    if (empty($cidrs)) {
        return false;
    }
    foreach ($cidrs as $cidr) {
        if (blwp_ip_in_cidr($ip, $cidr)) {
            return true;
        }
    }
    return false;
}

/**
 * Verifica se o user-agent atual está na lista de bloqueio (substring, case-insensitive).
 *
 * @return bool
 */
function blwp_is_ua_blocked() {
    if (!get_option('blwp_ua_block_enabled', 0)) {
        return false;
    }
    $blocked = get_option('blwp_ua_blocked', []);
    if (empty($blocked)) {
        return false;
    }
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
    if ($ua === '') {
        return false;
    }
    $ua_lower = strtolower($ua);
    foreach ($blocked as $pattern) {
        if ($pattern !== '' && strpos($ua_lower, strtolower($pattern)) !== false) {
            return true;
        }
    }
    return false;
}

/**
 * Valida um bloco CIDR (retorna true/false).
 *
 * @param string $cidr Bloco CIDR.
 * @return bool
 */
function blwp_is_valid_cidr($cidr) {
    $parts = explode('/', $cidr);
    $ip = trim($parts[0]);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }
    if (isset($parts[1])) {
        // Exige que o prefixo seja um inteiro real (evita (int)'abc' = 0).
        if (!preg_match('/^\d{1,3}$/', $parts[1])) {
            return false;
        }
        $prefix = (int) $parts[1];
        $max = (strpos($ip, ':') !== false) ? 128 : 32;
        if ($prefix < 0 || $prefix > $max) {
            return false;
        }
    }
    return true;
}

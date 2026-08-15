<?php
/**
 * REST API de gestão do Dolutech Blacklist Protect.
 *
 * Rotas em /wp-json/blwp/v1/ — autenticação via Application Passwords
 * (usuário com manage_options).
 *
 * @package Dolutech_Blacklist_Protect
 * @since 0.9.0
 */

if (!defined('ABSPATH')) {
    exit;
}

add_action('rest_api_init', 'blwp_register_rest_routes');
function blwp_register_rest_routes() {
    register_rest_route('blwp/v1', '/blocked', [
        'methods'             => 'GET',
        'callback'            => 'blwp_rest_get_blocked',
        'permission_callback' => 'blwp_rest_permission',
    ]);
    register_rest_route('blwp/v1', '/block', [
        'methods'             => 'POST',
        'callback'            => 'blwp_rest_block',
        'permission_callback' => 'blwp_rest_permission',
    ]);
    register_rest_route('blwp/v1', '/unblock', [
        'methods'             => 'POST',
        'callback'            => 'blwp_rest_unblock',
        'permission_callback' => 'blwp_rest_permission',
    ]);
    register_rest_route('blwp/v1', '/block/(?P<ip>[^/]+)', [
        'methods'             => 'DELETE',
        'callback'            => 'blwp_rest_delete_block',
        'permission_callback' => 'blwp_rest_permission',
    ]);
    register_rest_route('blwp/v1', '/logs', [
        'methods'             => 'GET',
        'callback'            => 'blwp_rest_get_logs',
        'permission_callback' => 'blwp_rest_permission',
    ]);
    register_rest_route('blwp/v1', '/blacklist/refresh', [
        'methods'             => 'POST',
        'callback'            => 'blwp_rest_refresh_blacklist',
        'permission_callback' => 'blwp_rest_permission',
    ]);
}

/**
 * Permissão: Application Passwords autenticam como usuário; exigimos manage_options.
 */
function blwp_rest_permission() {
    return current_user_can('manage_options');
}

/**
 * GET /blocked — lista bloqueios atuais.
 */
function blwp_rest_get_blocked() {
    return rest_ensure_response([
        'manual' => blwp_get_manual_blocked_ips(),
        'cidr'   => get_option('blwp_cidr_blocked', []),
        'ua'     => get_option('blwp_ua_blocked', []),
    ]);
}

/**
 * POST /block — bloqueia IP ou CIDR.
 */
function blwp_rest_block($request) {
    $ip = sanitize_text_field($request->get_param('ip'));
    $cidr = sanitize_text_field($request->get_param('cidr'));
    $reason = sanitize_text_field($request->get_param('reason'));

    if ($cidr !== '') {
        if (!blwp_is_valid_cidr($cidr)) {
            return new WP_Error('blwp_invalid_cidr', 'CIDR inválido.', ['status' => 400]);
        }
        $list = get_option('blwp_cidr_blocked', []);
        if (!in_array($cidr, $list, true)) {
            $list[] = $cidr;
            update_option('blwp_cidr_blocked', $list);
        }
        blwp_log_event('', 'admin_block', 'Bloqueio CIDR via REST: ' . $cidr . ($reason ? ' — ' . $reason : ''), 'admin');
        return rest_ensure_response(['success' => true, 'type' => 'cidr', 'value' => $cidr]);
    }

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return new WP_Error('blwp_invalid_ip', 'IP inválido.', ['status' => 400]);
    }
    $list = blwp_get_manual_blocked_ips();
    if (!in_array($ip, $list, true)) {
        $list[] = $ip;
        update_option('blwp_manual_blocked_ips', $list);
    }
    blwp_log_event($ip, 'admin_block', 'Bloqueio via REST' . ($reason ? ' — ' . $reason : ''), 'admin');
    return rest_ensure_response(['success' => true, 'type' => 'ip', 'value' => $ip]);
}

/**
 * POST /unblock — desbloqueia IP.
 */
function blwp_rest_unblock($request) {
    $ip = sanitize_text_field($request->get_param('ip'));
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return new WP_Error('blwp_invalid_ip', 'IP inválido.', ['status' => 400]);
    }
    $list = blwp_get_manual_blocked_ips();
    $list = array_diff($list, [$ip]);
    update_option('blwp_manual_blocked_ips', $list);
    blwp_log_event($ip, 'admin_unblock', 'Desbloqueio via REST', 'admin');
    return rest_ensure_response(['success' => true]);
}

/**
 * DELETE /block/{ip} — remove IP ou CIDR da lista.
 */
function blwp_rest_delete_block($request) {
    $item = rawurldecode($request['ip']);

    $list = blwp_get_manual_blocked_ips();
    if (in_array($item, $list, true)) {
        $list = array_diff($list, [$item]);
        update_option('blwp_manual_blocked_ips', $list);
        blwp_log_event($item, 'admin_unblock', 'Desbloqueio via REST (DELETE)', 'admin');
        return rest_ensure_response(['success' => true]);
    }

    $cidrs = get_option('blwp_cidr_blocked', []);
    if (in_array($item, $cidrs, true)) {
        $cidrs = array_diff($cidrs, [$item]);
        update_option('blwp_cidr_blocked', $cidrs);
        blwp_log_event('', 'admin_unblock', 'Remoção de CIDR via REST (DELETE): ' . $item, 'admin');
        return rest_ensure_response(['success' => true]);
    }

    return new WP_Error('blwp_not_found', 'Item não encontrado.', ['status' => 404]);
}

/**
 * GET /logs — consulta logs paginados.
 */
function blwp_rest_get_logs($request) {
    $args = [
        'ip'         => sanitize_text_field($request->get_param('ip')),
        'event_type' => sanitize_text_field($request->get_param('event_type')),
        'source'     => sanitize_text_field($request->get_param('source')),
        'page'       => (int) $request->get_param('page'),
        'per_page'   => min((int) ($request->get_param('per_page') ?: 20), 100),
    ];
    $items = blwp_get_logs($args);
    $total = blwp_count_logs($args);
    return rest_ensure_response(['total' => $total, 'items' => $items]);
}

/**
 * POST /blacklist/refresh — dispara atualização manual da blacklist.
 */
function blwp_rest_refresh_blacklist() {
    $ok = blwp_fetch_blacklist();
    return rest_ensure_response(['success' => $ok]);
}

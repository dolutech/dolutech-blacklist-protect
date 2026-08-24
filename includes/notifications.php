<?php
/**
 * Notificações via Telegram e Webhook.
 *
 * @package Dolutech_Blacklist_Protect
 * @since 0.9.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Envia notificações (Telegram/Webhook) para um evento, se habilitado.
 *
 * @param string $event_type Tipo do evento.
 * @param string $ip         Endereço IP (pode ser vazio).
 * @param string $reason     Descrição.
 * @param bool   $force      Ignora o filtro de eventos (usado no teste).
 */
function blwp_send_notifications($event_type, $ip, $reason, $force = false) {
    // Filtra pelos eventos selecionados
    $enabled_events = get_option('blwp_notify_events', []);
    if (!$force && !empty($enabled_events) && !in_array($event_type, $enabled_events, true)) {
        return;
    }

    // Throttle: máx. 1 notificação por IP+evento a cada 60s.
    // Um bot martelando um IP bloqueado não pode virar storm de outbound
    // (rate limits do Telegram/webhook e lixo nos logs).
    // Nota: eventos com IP vazio (ex.: bloqueio CIDR via REST) não passam pelo
    // throttle — exigem credencial admin, risco aceito.
    if (!$force && $ip !== '') {
        $throttle_key = 'blwp_notify_rl_' . md5($ip . '|' . $event_type);
        if (get_transient($throttle_key)) {
            return;
        }
        set_transient($throttle_key, 1, MINUTE_IN_SECONDS);
    }

    $text = sprintf(
        "🔒 %s\nSite: %s\nIP: %s\nEvento: %s\nMotivo: %s\nData: %s",
        get_bloginfo('name'),
        get_site_url(),
        $ip ? $ip : '-',
        $event_type,
        $reason,
        current_time('mysql')
    );

    if (get_option('blwp_telegram_enabled', 0)) {
        blwp_send_telegram($text);
    }
    if (get_option('blwp_webhook_enabled', 0)) {
        blwp_send_webhook([
            'event_type' => $event_type,
            'ip'         => $ip,
            'reason'     => $reason,
            'site_url'   => get_site_url(),
            'timestamp'  => current_time('mysql'),
        ]);
    }
}

/**
 * Envia mensagem para o Telegram.
 *
 * @param string $text Texto da mensagem.
 */
function blwp_send_telegram($text) {
    $token = get_option('blwp_telegram_bot_token', '');
    $chat_id = get_option('blwp_telegram_chat_id', '');
    if ($token === '' || $chat_id === '') {
        return;
    }
    $url = 'https://api.telegram.org/bot' . $token . '/sendMessage';
    $response = wp_remote_post($url, [
        'body' => [
            'chat_id' => $chat_id,
            'text'    => $text,
        ],
        'timeout' => 5,
    ]);
    if (is_wp_error($response)) {
        /**
         * Fires when an outbound notification request fails.
         *
         * @since 0.9.0
         *
         * @param string  $channel Notification channel.
         * @param WP_Error $error   Request error.
         */
        do_action('blwp_notification_error', 'telegram', $response);
    }
}

/**
 * Envia payload JSON para o webhook.
 *
 * @param array $payload Dados do evento.
 */
function blwp_send_webhook($payload) {
    $url = get_option('blwp_webhook_url', '');
    if ($url === '') {
        return;
    }
    $response = wp_remote_post($url, [
        'headers' => ['Content-Type' => 'application/json'],
        'body'    => wp_json_encode($payload),
        'timeout' => 5,
    ]);
    if (is_wp_error($response)) {
        do_action('blwp_notification_error', 'webhook', $response);
    }
}

/**
 * Envia notificação de teste (botão no admin) — ignora o filtro de eventos.
 */
function blwp_test_notifications() {
    blwp_send_notifications('test', '127.0.0.1', 'Notificação de teste do Dolutech Blacklist Protect', true);
}

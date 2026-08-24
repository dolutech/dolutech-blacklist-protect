<?php
/**
 * Registro de eventos de segurança (logs).
 *
 * @package Dolutech_Blacklist_Protect
 * @since 0.9.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Cria a tabela de logs (dbDelta — indentação com 2 espaços obrigatória).
 */
function blwp_create_logs_table() {
    global $wpdb;
    $table = $wpdb->prefix . 'blwp_logs';
    $charset = $wpdb->get_charset_collate();
    $sql = "CREATE TABLE {$table} (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      timestamp DATETIME NOT NULL,
      ip VARCHAR(45) NOT NULL DEFAULT '',
      event_type VARCHAR(50) NOT NULL DEFAULT '',
      reason VARCHAR(255) NOT NULL DEFAULT '',
      source VARCHAR(20) NOT NULL DEFAULT '',
      user_agent VARCHAR(255) NOT NULL DEFAULT '',
      PRIMARY KEY  (id),
      KEY ip (ip),
      KEY event_type (event_type),
      KEY timestamp (timestamp)
    ) {$charset};";
    // phpstan-ignore requireOnce.fileNotFound -- ABSPATH é resolvido em runtime pelo WordPress.
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);
}

/**
 * Registra um evento de segurança (ponto único de log + notificação).
 *
 * @param string $ip         Endereço IP (pode ser vazio para eventos sem IP).
 * @param string $event_type Tipo do evento (ver mapeamento na página de logs).
 * @param string $reason     Descrição do evento.
 * @param string $source     Origem: blacklist|manual|bruteforce|username|xmlrpc|geo|admin.
 */
function blwp_log_event($ip, $event_type, $reason, $source) {
    global $wpdb;
    $table = $wpdb->prefix . 'blwp_logs';

    // Self-heal: se a tabela não existe (ex.: site atualizado antes do upgrade path),
    // cria uma vez por requisição e tenta de novo.
    static $table_checked = false;
    if (!$table_checked) {
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom log tables have no equivalent in the WordPress Options API.
        $exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table));
        if (!$exists) {
            blwp_create_logs_table();
        }
        $table_checked = true;
    }

    $user_agent = isset($_SERVER['HTTP_USER_AGENT'])
        ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT']))
        : '';

    $data = [
        'timestamp'  => gmdate('Y-m-d H:i:s'), // UTC, consistente com o purge.
        'ip'         => substr((string) $ip, 0, 45),
        'event_type' => substr((string) $event_type, 0, 50),
        'reason'     => substr((string) $reason, 0, 255),
        'source'     => substr((string) $source, 0, 20),
        'user_agent' => substr($user_agent, 0, 255),
    ];

    $wpdb->insert($table, $data);

    // Notificações (Telegram/Webhook) — nunca devem derrubar o request.
    blwp_send_notifications($event_type, $ip, $reason);
}

/**
 * Consulta logs paginados.
 *
 * @param array $args Filtros: ip, event_type, source, page, per_page.
 * @return array|null
 */
function blwp_get_logs($args = []) {
    global $wpdb;
    $table = $wpdb->prefix . 'blwp_logs';
    $where = ['1=1'];
    $params = [];

    if (!empty($args['ip'])) {
        $where[] = 'ip = %s';
        $params[] = sanitize_text_field($args['ip']);
    }
    if (!empty($args['event_type'])) {
        $where[] = 'event_type = %s';
        $params[] = sanitize_text_field($args['event_type']);
    }
    if (!empty($args['source'])) {
        $where[] = 'source = %s';
        $params[] = sanitize_text_field($args['source']);
    }

    $per_page = isset($args['per_page']) ? min((int) $args['per_page'], 100) : 20;
    $page = isset($args['page']) ? max(1, (int) $args['page']) : 1;
    $offset = ($page - 1) * $per_page;

    $sql = 'SELECT * FROM %i WHERE ' . implode(' AND ', $where) . ' ORDER BY timestamp DESC, id DESC LIMIT %d OFFSET %d';
    $params = array_merge([$table], $params, [$per_page, $offset]);

    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Custom log table query; identifier and values are prepared before execution.
    return $wpdb->get_results($wpdb->prepare($sql, $params), ARRAY_A);
}

/**
 * Conta logs com os mesmos filtros de blwp_get_logs.
 *
 * @param array $args Filtros: ip, event_type, source.
 * @return int
 */
function blwp_count_logs($args = []) {
    global $wpdb;
    $table = $wpdb->prefix . 'blwp_logs';
    $where = ['1=1'];
    $params = [];

    if (!empty($args['ip'])) {
        $where[] = 'ip = %s';
        $params[] = sanitize_text_field($args['ip']);
    }
    if (!empty($args['event_type'])) {
        $where[] = 'event_type = %s';
        $params[] = sanitize_text_field($args['event_type']);
    }
    if (!empty($args['source'])) {
        $where[] = 'source = %s';
        $params[] = sanitize_text_field($args['source']);
    }

    $sql = 'SELECT COUNT(*) FROM %i WHERE ' . implode(' AND ', $where);
    $params = array_merge([$table], $params);

    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Custom log table query; identifier and values are prepared before execution.
    return (int) $wpdb->get_var($wpdb->prepare($sql, $params));
}

/**
 * Remove todos os logs.
 */
function blwp_clear_logs() {
    global $wpdb;
    $table = $wpdb->prefix . 'blwp_logs';
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Clearing the custom log table is an explicit admin action.
    $wpdb->query($wpdb->prepare('TRUNCATE TABLE %i', $table));
}

/**
 * Purga logs mais antigos que a retenção configurada (default 30 dias).
 */
function blwp_purge_old_logs() {
    global $wpdb;
    $table = $wpdb->prefix . 'blwp_logs';
    $days = max(1, (int) get_option('blwp_log_retention_days', 30));
    $cutoff = gmdate('Y-m-d H:i:s', time() - ($days * DAY_IN_SECONDS));
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Purging the custom log table is performed by the scheduled maintenance task.
    $wpdb->query($wpdb->prepare('DELETE FROM %i WHERE timestamp < %s', $table, $cutoff));
}

// Cron diário de manutenção (purge de logs).
add_action('blwp_daily_maintenance_hook', 'blwp_purge_old_logs');

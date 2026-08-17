<?php
/**
 * Página administrativa de Logs de Eventos.
 *
 * @package Dolutech_Blacklist_Protect
 * @since 0.9.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Labels pt-BR dos tipos de evento.
 */
function blwp_get_event_labels() {
    return [
        'block_blacklist' => __('Bloqueio blacklist', 'dolutech-blacklist-protect'),
        'block_manual'    => __('Bloqueio manual', 'dolutech-blacklist-protect'),
        'block_temp'      => __('Bloqueio temporário', 'dolutech-blacklist-protect'),
        'block_cidr'      => __('Bloqueio CIDR', 'dolutech-blacklist-protect'),
        'block_ua'        => __('Bloqueio user-agent', 'dolutech-blacklist-protect'),
        'bruteforce'      => __('Força bruta', 'dolutech-blacklist-protect'),
        'username'        => __('Usuário protegido', 'dolutech-blacklist-protect'),
        'xmlrpc'          => __('XML-RPC', 'dolutech-blacklist-protect'),
        'geo'             => __('Geográfico', 'dolutech-blacklist-protect'),
        'unblock_request' => __('Solicitação de desbloqueio', 'dolutech-blacklist-protect'),
        'unblock'         => __('Desbloqueio', 'dolutech-blacklist-protect'),
        'admin_block'     => __('Bloqueio admin', 'dolutech-blacklist-protect'),
        'admin_unblock'   => __('Desbloqueio admin', 'dolutech-blacklist-protect'),
        'test'            => __('Teste', 'dolutech-blacklist-protect'),
    ];
}

/**
 * Labels pt-BR das origens.
 */
function blwp_get_source_labels() {
    return [
        'blacklist'  => __('Blacklist', 'dolutech-blacklist-protect'),
        'manual'     => __('Manual', 'dolutech-blacklist-protect'),
        'bruteforce' => __('Força bruta', 'dolutech-blacklist-protect'),
        'username'   => __('Usuário protegido', 'dolutech-blacklist-protect'),
        'xmlrpc'     => __('XML-RPC', 'dolutech-blacklist-protect'),
        'geo'        => __('Geográfico', 'dolutech-blacklist-protect'),
        'admin'      => __('Administrador', 'dolutech-blacklist-protect'),
    ];
}

/**
 * Lista de logs (WP_List_Table).
 *
 * WP_List_Table não é autoload: o core só a inclui em telas admin específicas.
 * Sem este require o plugin quebra ao carregar (ex.: plugins.php).
 */
if (!class_exists('WP_List_Table')) {
    // phpstan-ignore requireOnce.fileNotFound -- ABSPATH é resolvido em runtime pelo WordPress.
    require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

class BLWP_Logs_Table extends WP_List_Table {

    /** @var array Filtros ativos. */
    private $filters = [];

    public function __construct($filters = []) {
        parent::__construct([
            'singular' => 'log',
            'plural'   => 'logs',
            'ajax'     => false,
        ]);
        $this->filters = $filters;
    }

    public function get_columns() {
        return [
            'timestamp'  => __('Data/Hora', 'dolutech-blacklist-protect'),
            'ip'         => __('IP', 'dolutech-blacklist-protect'),
            'event_type' => __('Evento', 'dolutech-blacklist-protect'),
            'reason'     => __('Motivo', 'dolutech-blacklist-protect'),
            'source'     => __('Origem', 'dolutech-blacklist-protect'),
            'user_agent' => __('User-Agent', 'dolutech-blacklist-protect'),
        ];
    }

    protected function get_sortable_columns() {
        return [
            'timestamp' => ['timestamp', true],
        ];
    }

    public function prepare_items() {
        $per_page = 20;
        $current_page = $this->get_pagenum();

        $args = array_merge($this->filters, [
            'page'     => $current_page,
            'per_page' => $per_page,
        ]);

        $this->items = blwp_get_logs($args);
        $total = blwp_count_logs($this->filters);

        $this->set_pagination_args([
            'total_items' => $total,
            'per_page'    => $per_page,
            'total_pages' => (int) ceil($total / $per_page),
        ]);
    }

    public function column_default($item, $column_name) {
        switch ($column_name) {
            case 'timestamp':
                return esc_html(wp_date('d/m/Y H:i:s', strtotime((string) $item['timestamp'])));
            case 'ip':
                return esc_html($item['ip'] ? $item['ip'] : '-');
            case 'event_type':
                $labels = blwp_get_event_labels();
                return esc_html($labels[$item['event_type']] ?? $item['event_type']);
            case 'reason':
                return esc_html($item['reason']);
            case 'source':
                $labels = blwp_get_source_labels();
                return esc_html($labels[$item['source']] ?? $item['source']);
            case 'user_agent':
                return esc_html($item['user_agent'] ? $item['user_agent'] : '-');
        }
        return '';
    }

    public function no_items() {
        esc_html_e('Nenhum evento registrado.', 'dolutech-blacklist-protect');
    }
}

/**
 * Registra o submenu de logs.
 */
add_action('admin_menu', 'blwp_admin_logs_menu');
function blwp_admin_logs_menu() {
    add_options_page(
        'Logs de Eventos',
        'Logs BLWP',
        'manage_options',
        'blwp-logs',
        'blwp_render_logs_page'
    );
}

/**
 * Renderiza a página de logs.
 */
function blwp_render_logs_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    // Limpar logs
    if (isset($_POST['blwp_clear_logs']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        blwp_clear_logs();
        echo '<div class="notice notice-success"><p>' . esc_html__('Logs limpos com sucesso.', 'dolutech-blacklist-protect') . '</p></div>';
    }

    // Filtros
    $filters = [
        'ip'         => isset($_GET['blwp_ip']) ? sanitize_text_field(wp_unslash($_GET['blwp_ip'])) : '',
        'event_type' => isset($_GET['blwp_event_type']) ? sanitize_text_field(wp_unslash($_GET['blwp_event_type'])) : '',
        'source'     => isset($_GET['blwp_source']) ? sanitize_text_field(wp_unslash($_GET['blwp_source'])) : '',
    ];
    $filters = array_filter($filters);

    $table = new BLWP_Logs_Table($filters);
    $table->prepare_items();

    $event_labels = blwp_get_event_labels();
    $source_labels = blwp_get_source_labels();
    ?>
    <div class="wrap">
        <h1><?php esc_html_e('Logs de Eventos — Dolutech Blacklist Protect', 'dolutech-blacklist-protect'); ?></h1>

        <form method="get">
            <input type="hidden" name="page" value="blwp-logs" />
            <label><?php esc_html_e('IP:', 'dolutech-blacklist-protect'); ?>
                <input type="text" name="blwp_ip" value="<?php echo esc_attr($filters['ip'] ?? ''); ?>" />
            </label>
            <label><?php esc_html_e('Evento:', 'dolutech-blacklist-protect'); ?>
                <select name="blwp_event_type">
                    <option value=""><?php esc_html_e('Todos', 'dolutech-blacklist-protect'); ?></option>
                    <?php foreach ($event_labels as $key => $label) : ?>
                        <option value="<?php echo esc_attr($key); ?>" <?php selected($filters['event_type'] ?? '', $key); ?>><?php echo esc_html($label); ?></option>
                    <?php endforeach; ?>
                </select>
            </label>
            <label><?php esc_html_e('Origem:', 'dolutech-blacklist-protect'); ?>
                <select name="blwp_source">
                    <option value=""><?php esc_html_e('Todas', 'dolutech-blacklist-protect'); ?></option>
                    <?php foreach ($source_labels as $key => $label) : ?>
                        <option value="<?php echo esc_attr($key); ?>" <?php selected($filters['source'] ?? '', $key); ?>><?php echo esc_html($label); ?></option>
                    <?php endforeach; ?>
                </select>
            </label>
            <?php submit_button(__('Filtrar', 'dolutech-blacklist-protect'), 'secondary', 'blwp_filter_logs', false); ?>
        </form>

        <form method="post" style="margin-bottom: 15px;">
            <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
            <input type="submit" name="blwp_clear_logs" class="button button-link-delete" value="<?php esc_attr_e('Limpar Logs', 'dolutech-blacklist-protect'); ?>" onclick="return confirm('<?php esc_attr_e('Tem certeza que deseja limpar todos os logs?', 'dolutech-blacklist-protect'); ?>');" />
        </form>

        <?php $table->display(); ?>
    </div>
    <?php
}

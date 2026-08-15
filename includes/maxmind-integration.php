<?php
/**
 * Integração com MaxMind GeoIP2 API
 *
 * @package Dolutech_Blacklist_Protect
 * @since 0.7.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Verifica se a API do MaxMind está configurada e ativa
 */
function blwp_is_maxmind_enabled() {
    $enabled = get_option('blwp_maxmind_enabled', 0);
    $api_key = get_option('blwp_maxmind_api_key', '');
    $account_id = get_option('blwp_maxmind_account_id', '');

    return $enabled && !empty($api_key) && !empty($account_id);
}

/**
 * Valida as credenciais da API MaxMind
 *
 * @param string $account_id Account ID do MaxMind
 * @param string $api_key License Key do MaxMind
 * @return array Array com 'valid' (bool) e 'message' (string)
 */
function blwp_validate_maxmind_credentials($account_id, $api_key) {
    // IP de teste para validação
    $test_ip = '8.8.8.8';

    // URL correta para MaxMind Web Services
    $url = sprintf('https://geolite.info/geoip/v2.1/country/%s', $test_ip);

    $args = [
        'headers' => [
            'Authorization' => 'Basic ' . base64_encode($account_id . ':' . $api_key),
            'Accept' => 'application/json'
        ],
        'timeout' => 15,
        'sslverify' => true,
        'user-agent' => 'Dolutech Blacklist Protect/' . BLWP_VERSION
    ];

    $response = wp_remote_get($url, $args);

    if (is_wp_error($response)) {
        return [
            'valid' => false,
            'message' => sprintf(
                /* translators: %s: error message */
                __('Erro ao conectar com a API: %s', 'dolutech-blacklist-protect'),
                $response->get_error_message()
            )
        ];
    }

    $status_code = wp_remote_retrieve_response_code($response);
    $body = wp_remote_retrieve_body($response);

    if ($status_code === 200) {
        $data = json_decode($body, true);
        if (isset($data['country']['iso_code'])) {
            return [
                'valid' => true,
                'message' => __('Credenciais válidas! API MaxMind conectada com sucesso.', 'dolutech-blacklist-protect')
            ];
        }
    }

    if ($status_code === 401) {
        return [
            'valid' => false,
            'message' => __('Credenciais inválidas. Verifique seu Account ID e License Key.', 'dolutech-blacklist-protect')
        ];
    }

    if ($status_code === 402) {
        return [
            'valid' => false,
            'message' => __('Sua conta MaxMind não tem permissão para este serviço ou está sem créditos.', 'dolutech-blacklist-protect')
        ];
    }

    if ($status_code === 403) {
        return [
            'valid' => false,
            'message' => __('Acesso negado. Verifique se sua License Key tem permissão para GeoLite2 ou GeoIP2.', 'dolutech-blacklist-protect')
        ];
    }

    // Debug: mostra detalhes do erro
    $error_details = '';
    if (!empty($body)) {
        $error_data = json_decode($body, true);
        if (isset($error_data['error'])) {
            $error_details = ' - ' . $error_data['error'];
        } elseif (isset($error_data['code'])) {
            $error_details = ' - Código: ' . $error_data['code'];
        }
    }

    return [
        'valid' => false,
        'message' => sprintf(
            /* translators: 1: HTTP status code, 2: error details */
            __('Erro HTTP %1$d ao validar credenciais%2$s', 'dolutech-blacklist-protect'),
            $status_code,
            $error_details
        )
    ];
}

/**
 * Obtém o país de um IP usando a API MaxMind
 *
 * @param string $ip Endereço IP a ser consultado
 * @return string|false Código do país (ISO 3166-1 alpha-2) ou false em caso de erro
 */
function blwp_get_country_from_ip($ip) {
    if (!blwp_is_maxmind_enabled()) {
        return false;
    }

    // Valida o IP
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return false;
    }

    // Verifica cache
    $cache_key = 'blwp_country_' . md5($ip);
    $cached = get_transient($cache_key);
    if ($cached !== false) {
        // 'none' é o cache negativo (API indisponível/erro)
        return ($cached === 'none') ? false : $cached;
    }

    $account_id = get_option('blwp_maxmind_account_id', '');
    $api_key = get_option('blwp_maxmind_api_key', '');

    // URL correta para MaxMind Web Services
    $url = sprintf('https://geolite.info/geoip/v2.1/country/%s', $ip);

    $args = [
        'headers' => [
            'Authorization' => 'Basic ' . base64_encode($account_id . ':' . $api_key),
            'Accept' => 'application/json'
        ],
        'timeout' => 5,
        'sslverify' => true,
        'user-agent' => 'Dolutech Blacklist Protect/' . BLWP_VERSION
    ];

    $response = wp_remote_get($url, $args);

    if (is_wp_error($response)) {
        // Cache negativo: evita bater na API a cada requisição quando está fora
        set_transient($cache_key, 'none', 15 * MINUTE_IN_SECONDS);
        return false;
    }

    $status_code = wp_remote_retrieve_response_code($response);

    if ($status_code !== 200) {
        set_transient($cache_key, 'none', 15 * MINUTE_IN_SECONDS);
        return false;
    }

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    if (!isset($data['country']['iso_code'])) {
        set_transient($cache_key, 'none', 15 * MINUTE_IN_SECONDS);
        return false;
    }

    $country_code = $data['country']['iso_code'];

    // Armazena em cache por 24 horas
    set_transient($cache_key, $country_code, DAY_IN_SECONDS);

    return $country_code;
}

/**
 * Verifica se um IP deve ser bloqueado pela geolocalização
 *
 * @param string $ip Endereço IP a ser verificado
 * @return bool True se deve ser bloqueado, false caso contrário
 */
function blwp_should_block_by_geolocation($ip) {
    if (!blwp_is_maxmind_enabled()) {
        return false;
    }

    $blocked_countries = get_option('blwp_blocked_countries', []);

    if (empty($blocked_countries)) {
        return false;
    }

    $country = blwp_get_country_from_ip($ip);

    if ($country === false) {
        return false;
    }

    return in_array(strtoupper($country), array_map('strtoupper', $blocked_countries), true);
}

/**
 * Adiciona o bloqueio por geolocalização ao sistema de bloqueio principal
 */
add_action('init', 'blwp_block_by_geolocation', 2);
function blwp_block_by_geolocation() {
    if (!blwp_is_maxmind_enabled()) {
        return;
    }

    if (is_admin() || defined('DOING_CRON') || php_sapi_name() === 'cli') {
        return;
    }

    $ip = blwp_get_client_ip();

    if (!$ip || blwp_is_whitelisted($ip)) {
        return;
    }

    if (blwp_should_block_by_geolocation($ip)) {
        $country = blwp_get_country_from_ip($ip);

        status_header(403);
        ?>
        <!DOCTYPE html>
        <html <?php language_attributes(); ?>>
        <head>
            <meta charset="<?php bloginfo('charset'); ?>">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title><?php esc_html_e('Acesso Bloqueado', 'dolutech-blacklist-protect'); ?></title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                    background-color: #f5f5f5;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .blocked-container {
                    background: white;
                    padding: 40px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    text-align: center;
                    max-width: 500px;
                }
                h1 {
                    color: #dc3545;
                    margin-bottom: 20px;
                }
                p {
                    color: #666;
                    line-height: 1.6;
                    margin-bottom: 30px;
                }
                .notice-box {
                    background-color: #f8f9fa;
                    border-left: 4px solid #dc3545;
                    padding: 15px;
                    margin-top: 20px;
                    text-align: left;
                }
            </style>
        </head>
        <body>
            <div class="blocked-container">
                <h1><?php esc_html_e('Acesso Bloqueado', 'dolutech-blacklist-protect'); ?></h1>
                <p>
                    <?php
                    echo esc_html(
                        sprintf(
                            /* translators: %s: country code */
                            __('Seu acesso foi bloqueado devido à sua localização geográfica (%s).', 'dolutech-blacklist-protect'),
                            $country
                        )
                    );
                    ?>
                </p>

                <div class="notice-box">
                    <strong><?php esc_html_e('Aviso:', 'dolutech-blacklist-protect'); ?></strong><br>
                    <?php esc_html_e('Acessos da sua região estão temporariamente restritos. Se você acredita que isso é um erro, entre em contato com o administrador do site.', 'dolutech-blacklist-protect'); ?>
                </div>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
}

/**
 * Obtém lista de países comumente bloqueados para sugestões
 *
 * @return array Array associativo com código do país => nome do país
 */
function blwp_get_common_blocked_countries() {
    return [
        'CN' => __('China', 'dolutech-blacklist-protect'),
        'RU' => __('Rússia', 'dolutech-blacklist-protect'),
        'KP' => __('Coreia do Norte', 'dolutech-blacklist-protect'),
        'IR' => __('Irã', 'dolutech-blacklist-protect'),
        'SY' => __('Síria', 'dolutech-blacklist-protect'),
        'VN' => __('Vietnã', 'dolutech-blacklist-protect'),
        'BR' => __('Brasil', 'dolutech-blacklist-protect'),
        'IN' => __('Índia', 'dolutech-blacklist-protect'),
        'ID' => __('Indonésia', 'dolutech-blacklist-protect'),
        'PK' => __('Paquistão', 'dolutech-blacklist-protect')
    ];
}

/**
 * Limpa cache de geolocalização periodicamente
 */
add_action('blwp_update_blacklist_hook', 'blwp_clean_geolocation_cache');
function blwp_clean_geolocation_cache() {
    // Usa a API de transients do WordPress para limpeza
    // Os transients expirados são limpos automaticamente pelo WordPress
    // Esta função pode ser expandida no futuro se necessário

    // Força a limpeza de transients expirados usando a API nativa do WP
    delete_expired_transients(true);
}

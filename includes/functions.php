<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Obtém o IP real do cliente, considerando proxy reverso/CDN configurado.
 */
function blwp_get_client_ip() {
    $ip = '';

    // Confia em X-Forwarded-For apenas se houver proxy reverso configurado.
    if (blwp_has_trusted_proxy()) {
        $forwarded = isset($_SERVER['HTTP_X_FORWARDED_FOR'])
            ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR']))
            : '';
        if ($forwarded) {
            $parts = explode(',', $forwarded);
            $candidate = trim($parts[0]);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                $ip = $candidate;
            }
        }
    }

    if (!$ip && isset($_SERVER['REMOTE_ADDR'])) {
        $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $ip = '';
        }
    }

    return $ip;
}

/**
 * Verifica se o site está atrás de proxy reverso confiável (Cloudflare, CDN, etc.).
 */
function blwp_has_trusted_proxy() {
    $mode = get_option('blwp_proxy_mode', 'none'); // none | cloudflare | generic
    return in_array($mode, ['cloudflare', 'generic'], true);
}

function blwp_get_blacklist_url() {
    return 'https://raw.githubusercontent.com/dolutech/blacklist-dolutech/refs/heads/main/Black-list-semanal-dolutech.txt';
}

function blwp_fetch_blacklist() {
    // Busca a blacklist principal da Dolutech
    $dolutech_ips = blwp_fetch_single_blacklist(blwp_get_blacklist_url());
    
    // Busca blacklists de terceiros
    $third_party_ips = blwp_fetch_third_party_blacklists();
    
    // Combina todas as blacklists
    $all_ips = array_unique(array_merge($dolutech_ips, $third_party_ips));
    
    if (!empty($all_ips)) {
        // Armazenamento compacto: string separada por quebras de linha, sem autoload
        // (listas podem ter 100k+ IPs e não devem entrar no autoload de toda requisição).
        update_option('blwp_blacklisted_ips', implode(PHP_EOL, $all_ips), false);
        update_option('blwp_last_update', current_time('mysql'));
        
        // Stats persistidas para o dashboard (evita refetch na página de admin)
        update_option('blwp_last_fetch_stats', [
            'dolutech' => count($dolutech_ips),
            'third_party' => count(array_unique($third_party_ips)),
            'total' => count($all_ips),
        ], false);
        
        // Log das blacklists
        $upload_dir = wp_upload_dir();
        $log_dir   = $upload_dir['basedir'] . '/dolutech-blacklist-protect';
        if (! file_exists($log_dir)) {
            wp_mkdir_p($log_dir);
        }
        $log_file = $log_dir . '/blacklist-log.txt';
        file_put_contents($log_file, implode(PHP_EOL, $all_ips));
        
        return true;
    }
    
    return false;
}

/**
 * Busca IPs de uma única URL de blacklist
 */
function blwp_fetch_single_blacklist($url) {
    $ips = [];
    
    $args = [
        'timeout' => 30,
        'sslverify' => true,
        'user-agent' => 'Dolutech Blacklist Protect/' . BLWP_VERSION
    ];
    
    $response = wp_remote_get($url, $args);
    
    if (is_wp_error($response)) {
        return $ips;
    }
    
    $lines = explode("\n", wp_remote_retrieve_body($response));
    foreach ($lines as $line) {
        $line = trim($line);
        // Remove comentários e valida IP
        if ($line && strpos($line, '#') !== 0 && filter_var($line, FILTER_VALIDATE_IP)) {
            $ips[] = $line;
        }
    }
    
    return $ips;
}

/**
 * Busca IPs de todas as blacklists de terceiros
 */
function blwp_fetch_third_party_blacklists() {
    $all_ips = [];
    $third_party_lists = get_option('blwp_third_party_blacklists', []);
    
    if (empty($third_party_lists)) {
        return $all_ips;
    }
    
    foreach ($third_party_lists as $list_id => $list_data) {
        if (!$list_data['enabled']) {
            continue;
        }
        
        $url = $list_data['url'];
        $ips = blwp_fetch_single_blacklist($url);
        
        if (!empty($ips)) {
            // Atualiza estatísticas da lista
            $third_party_lists[$list_id]['last_update'] = current_time('mysql');
            $third_party_lists[$list_id]['ip_count'] = count($ips);
            $third_party_lists[$list_id]['status'] = 'active';
            
            $all_ips = array_merge($all_ips, $ips);
        } else {
            // Marca como erro se não conseguiu buscar
            $third_party_lists[$list_id]['status'] = 'error';
            $third_party_lists[$list_id]['last_error'] = current_time('mysql');
        }
    }
    
    // Salva estatísticas atualizadas
    update_option('blwp_third_party_blacklists', $third_party_lists);
    
    return array_unique($all_ips);
}

/**
 * Adiciona uma nova blacklist de terceiros
 */
function blwp_add_third_party_blacklist($url, $name = '') {
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        return false;
    }
    
    $lists = get_option('blwp_third_party_blacklists', []);
    
    // Verifica se a URL já existe
    foreach ($lists as $list) {
        if ($list['url'] === $url) {
            return false;
        }
    }
    
    // Gera um ID único
    $list_id = 'list_' . wp_generate_password(8, false);
    
    // Extrai o nome do domínio se não foi fornecido um nome
    if (empty($name)) {
        $parsed = wp_parse_url($url);
        $name = $parsed['host'] ?? 'Lista Externa';
    }
    
    $lists[$list_id] = [
        'url' => $url,
        'name' => $name,
        'enabled' => true,
        'added_date' => current_time('mysql'),
        'last_update' => null,
        'ip_count' => 0,
        'status' => 'pending'
    ];
    
    update_option('blwp_third_party_blacklists', $lists);
    
    // Faz uma busca inicial
    blwp_fetch_blacklist();
    
    return true;
}

/**
 * Remove uma blacklist de terceiros
 */
function blwp_remove_third_party_blacklist($list_id) {
    $lists = get_option('blwp_third_party_blacklists', []);
    
    if (isset($lists[$list_id])) {
        unset($lists[$list_id]);
        update_option('blwp_third_party_blacklists', $lists);
        
        // Atualiza as blacklists
        blwp_fetch_blacklist();
        
        return true;
    }
    
    return false;
}

/**
 * Alterna o status de uma blacklist de terceiros
 */
function blwp_toggle_third_party_blacklist($list_id) {
    $lists = get_option('blwp_third_party_blacklists', []);
    
    if (isset($lists[$list_id])) {
        $lists[$list_id]['enabled'] = !$lists[$list_id]['enabled'];
        update_option('blwp_third_party_blacklists', $lists);
        
        // Atualiza as blacklists
        blwp_fetch_blacklist();
        
        return true;
    }
    
    return false;
}

function blwp_get_blacklisted_ips() {
    $raw = get_option('blwp_blacklisted_ips', '');
    // Compatibilidade: versões antigas armazenavam array
    if (is_array($raw)) {
        return $raw;
    }
    return array_values(array_filter(array_map('trim', explode("\n", $raw))));
}

function blwp_get_manual_blocked_ips() {
    return get_option('blwp_manual_blocked_ips', []);
}

function blwp_get_last_update() {
    return get_option('blwp_last_update', 'Nunca');
}

function blwp_send_abuse_report($ip, $reason, $force = false) {
    // Denúncias automáticas só são enviadas com o relato automático ativo.
    // Ações explícitas do admin (formulário manual) passam $force = true.
    if (!$force && !get_option('blwp_auto_report', 0)) {
        return;
    }

    $to      = 'abuse@dolutech.com';
    $subject = sprintf('Denúncia de IP Bloqueado: %s', sanitize_text_field($ip));
    $message = sprintf(
        "IP: %s\nMotivo: %s\nData/Hora: %s",
        sanitize_text_field($ip),
        sanitize_text_field($reason),
        current_time('mysql')
    );

    $headers      = ['Content-Type: text/plain; charset=UTF-8'];
    $site_email   = get_option('admin_email');
    $from_name    = get_bloginfo('name');
    $headers[]    = 'From: ' . sanitize_text_field($from_name) . ' <' . sanitize_email($site_email) . '>';

    wp_mail($to, $subject, $message, $headers);
}

function blwp_is_whitelisted($ip) {
    $whitelist = get_option('blwp_whitelist', []);
    foreach ($whitelist as $entry) {
        if (filter_var($entry, FILTER_VALIDATE_IP) && $entry === $ip) {
            return true;
        } elseif (filter_var($entry, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            // Cache DNS de 6h para domínios DDNS (evita lookup a cada requisição)
            $cache_key = 'blwp_dns_' . md5($entry);
            $resolved_ip = get_transient($cache_key);
            if ($resolved_ip === false) {
                $resolved_ip = gethostbyname($entry);
                set_transient($cache_key, $resolved_ip, 6 * HOUR_IN_SECONDS);
            }
            if ($resolved_ip === $ip) {
                return true;
            }
        }
    }
    return false;
}

add_action('init', 'blwp_block_blacklisted_ips');
function blwp_block_blacklisted_ips() {
    if (! get_option('blwp_blacklist_enabled', 1)) {
        return;
    }

    if (is_admin() || defined('DOING_CRON') || php_sapi_name() === 'cli') {
        return;
    }

    $ip = blwp_get_client_ip();
    if (! $ip || blwp_is_whitelisted($ip)) {
        return;
    }

    // Verifica bloqueios temporários primeiro
    $temp_blocks = get_option('blwp_temp_blocked_ips', []);
    if (isset($temp_blocks[$ip])) {
        if ($temp_blocks[$ip] > time()) {
            // Ainda está no período de bloqueio temporário
            $remaining_time = $temp_blocks[$ip] - time();
            $minutes_remaining = ceil($remaining_time / 60);
            blwp_show_temp_blocked_page($ip, $minutes_remaining);
            exit;
        } else {
            // Bloqueio temporário expirou, remove da lista
            unset($temp_blocks[$ip]);
            update_option('blwp_temp_blocked_ips', $temp_blocks);
        }
    }

    $blacklist = blwp_get_blacklisted_ips();
    $manual    = blwp_get_manual_blocked_ips();
    $all_blocked = array_unique(array_merge($blacklist, $manual));

    if (in_array($ip, $all_blocked, true)) {
        // Verifica se é uma requisição de desbloqueio
        // phpcs:disable WordPress.Security.NonceVerification.Recommended
        if (isset($_GET['blwp_unblock_request']) && $_GET['blwp_unblock_request'] === '1') {
            // phpcs:enable WordPress.Security.NonceVerification.Recommended
            blwp_show_unblock_request_page($ip);
            exit;
        }
        
        // Determina se o IP está na lista manual (pode solicitar desbloqueio)
        $is_manual_block = in_array($ip, $manual, true);
        
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
                .unblock-btn {
                    background-color: #0073aa;
                    color: white;
                    padding: 12px 30px;
                    text-decoration: none;
                    border-radius: 4px;
                    display: inline-block;
                    transition: background-color 0.3s;
                }
                .unblock-btn:hover {
                    background-color: #005177;
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
                <p><?php esc_html_e('Seu acesso foi bloqueado pelo Dolutech Blacklist Protect.', 'dolutech-blacklist-protect'); ?></p>
                
                <?php if ($is_manual_block) : ?>
                    <p><?php esc_html_e('Acredita que seu IP foi bloqueado por engano?', 'dolutech-blacklist-protect'); ?></p>
                    <a href="?blwp_unblock_request=1" class="unblock-btn">
                        <?php esc_html_e('Solicitar Desbloqueio', 'dolutech-blacklist-protect'); ?>
                    </a>
                <?php else : ?>
                    <div class="notice-box">
                        <strong><?php esc_html_e('Aviso:', 'dolutech-blacklist-protect'); ?></strong><br>
                        <?php esc_html_e('Seu IP está em uma lista de segurança global e não pode ser desbloqueado automaticamente. Se você acredita que isso é um erro, entre em contato com o administrador do site.', 'dolutech-blacklist-protect'); ?>
                    </div>
                <?php endif; ?>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
}

/**
 * Mostra a página de requisição de desbloqueio
 */
function blwp_show_unblock_request_page($ip) {
    // Processar envio do formulário
    if (isset($_POST['blwp_request_unblock']) && isset($_POST['blwp_unblock_nonce']) && 
        wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['blwp_unblock_nonce'])), 'blwp_unblock_request')) {
        
        // Rate-limit: máx. 2 solicitações por IP a cada 24h (evita flood de e-mails aos admins)
        $client_ip = blwp_get_client_ip();
        $rl_key = 'blwp_unblock_rl_' . md5($client_ip);
        $requests = (int) get_transient($rl_key);
        if ($requests >= 2) {
            blwp_show_unblock_request_form(
                $ip,
                __('Limite de solicitações atingido. Tente novamente amanhã.', 'dolutech-blacklist-protect')
            );
            return;
        }
        set_transient($rl_key, $requests + 1, DAY_IN_SECONDS);
        
        // Verifica reCAPTCHA se estiver habilitado
        $recaptcha_response = isset($_POST['g-recaptcha-response']) ? sanitize_text_field(wp_unslash($_POST['g-recaptcha-response'])) : '';
        if (!blwp_verify_recaptcha($recaptcha_response)) {
            blwp_show_unblock_request_form($ip, __('Por favor, complete a verificação reCAPTCHA.', 'dolutech-blacklist-protect'));
            return;
        }
        
        $token = wp_generate_password(32, false);
        $expiration = time() + DAY_IN_SECONDS; // Token válido por 24 horas
        
        // Armazena o token
        $tokens = get_option('blwp_unblock_tokens', []);
        $tokens[$token] = [
            'ip' => $ip,
            'expiration' => $expiration,
            'used' => false
        ];
        update_option('blwp_unblock_tokens', $tokens);
        
        // Envia email para administradores
        $admins = get_users(['role' => 'administrator']);
        $site_url = get_site_url();
        $unblock_url = add_query_arg([
            'blwp_token' => $token,
            'blwp_action' => 'unblock'
        ], $site_url);
        
        $subject = sprintf(
            '[%s] Solicitação de Desbloqueio de IP',
            get_bloginfo('name')
        );
        
        $message = sprintf(
            "Uma solicitação de desbloqueio foi recebida:\n\n" .
            "IP Bloqueado: %s\n" .
            "Data/Hora: %s\n\n" .
            "Para desbloquear este IP, clique no link abaixo:\n%s\n\n" .
            "Este link é válido por 24 horas e pode ser usado apenas uma vez.\n\n" .
            "Se você não reconhece esta solicitação, ignore este email.",
            $ip,
            current_time('mysql'),
            $unblock_url
        );
        
        $headers = ['Content-Type: text/plain; charset=UTF-8'];
        
        foreach ($admins as $admin) {
            wp_mail($admin->user_email, $subject, $message, $headers);
        }
        
        ?>
        <!DOCTYPE html>
        <html <?php language_attributes(); ?>>
        <head>
            <meta charset="<?php bloginfo('charset'); ?>">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title><?php esc_html_e('Solicitação Enviada', 'dolutech-blacklist-protect'); ?></title>
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
                .success-container {
                    background: white;
                    padding: 40px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    text-align: center;
                    max-width: 500px;
                }
                h1 {
                    color: #28a745;
                    margin-bottom: 20px;
                }
                p {
                    color: #666;
                    line-height: 1.6;
                }
            </style>
        </head>
        <body>
            <div class="success-container">
                <h1><?php esc_html_e('Solicitação Enviada!', 'dolutech-blacklist-protect'); ?></h1>
                <p><?php esc_html_e('Sua solicitação de desbloqueio foi enviada aos administradores do site.', 'dolutech-blacklist-protect'); ?></p>
                <p><?php esc_html_e('Você receberá uma resposta em breve.', 'dolutech-blacklist-protect'); ?></p>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
    
    // Mostra o formulário
    blwp_show_unblock_request_form($ip);
}

/**
 * Mostra o formulário de solicitação de desbloqueio
 */
function blwp_show_unblock_request_form($ip, $error_message = '') {
    ?>
    <!DOCTYPE html>
    <html <?php language_attributes(); ?>>
    <head>
        <meta charset="<?php bloginfo('charset'); ?>">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title><?php esc_html_e('Solicitar Desbloqueio', 'dolutech-blacklist-protect'); ?></title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                background-color: #f5f5f5;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
                padding: 20px;
            }
            .form-container {
                background: white;
                padding: 40px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                max-width: 500px;
                width: 100%;
            }
            h1 {
                color: #333;
                margin-bottom: 20px;
                text-align: center;
            }
            p {
                color: #666;
                line-height: 1.6;
                margin-bottom: 20px;
            }
            .info-box {
                background: #f8f9fa;
                border-left: 4px solid #0073aa;
                padding: 15px;
                margin-bottom: 20px;
            }
            .error-message {
                background-color: #fee;
                border-left: 4px solid #dc3545;
                padding: 10px;
                margin-bottom: 20px;
                color: #721c24;
            }
            .submit-btn {
                background-color: #0073aa;
                color: white;
                padding: 12px 30px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                width: 100%;
                font-size: 16px;
                transition: background-color 0.3s;
                margin-top: 10px;
            }
            .submit-btn:hover {
                background-color: #005177;
            }
        </style>
    </head>
    <body>
        <div class="form-container">
            <h1><?php esc_html_e('Solicitar Desbloqueio de IP', 'dolutech-blacklist-protect'); ?></h1>
            
            <?php if ($error_message) : ?>
                <div class="error-message">
                    <?php echo esc_html($error_message); ?>
                </div>
            <?php endif; ?>
            
            <div class="info-box">
                <strong><?php esc_html_e('Seu IP:', 'dolutech-blacklist-protect'); ?></strong> <?php echo esc_html($ip); ?>
            </div>
            <p><?php esc_html_e('Ao clicar no botão abaixo, uma solicitação será enviada aos administradores do site para revisar o bloqueio do seu IP.', 'dolutech-blacklist-protect'); ?></p>
            
            <form method="post">
                <?php wp_nonce_field('blwp_unblock_request', 'blwp_unblock_nonce'); ?>
                
                <?php if (blwp_is_recaptcha_enabled()) : ?>
                    <?php echo wp_kses_post(blwp_render_recaptcha()); ?>
                <?php endif; ?>
                
                <button type="submit" name="blwp_request_unblock" class="submit-btn">
                    <?php esc_html_e('Enviar Solicitação', 'dolutech-blacklist-protect'); ?>
                </button>
            </form>
        </div>
    </body>
    </html>
    <?php
}

/**
 * Processa tokens de desbloqueio
 */
add_action('init', 'blwp_process_unblock_token', 5);
function blwp_process_unblock_token() {
    // phpcs:disable WordPress.Security.NonceVerification.Recommended
    if (isset($_GET['blwp_token']) && isset($_GET['blwp_action']) && $_GET['blwp_action'] === 'unblock') {
        $token = sanitize_text_field(wp_unslash($_GET['blwp_token']));
        // phpcs:enable WordPress.Security.NonceVerification.Recommended
        $tokens = get_option('blwp_unblock_tokens', []);
        
        if (isset($tokens[$token]) && !$tokens[$token]['used'] && $tokens[$token]['expiration'] > time()) {
            $ip = $tokens[$token]['ip'];
            
            // Verifica se a chave secreta está habilitada
            $secret_key_enabled = get_option('blwp_secret_key_enabled', 0);
            if ($secret_key_enabled) {
                $stored_secret_key = get_option('blwp_secret_key', '');
                
                // Se o formulário foi enviado
                if (isset($_POST['blwp_unblock_secret_key']) && isset($_POST['blwp_secret_nonce']) && 
                    wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['blwp_secret_nonce'])), 'blwp_secret_key_verify')) {
                    
                    // Rate-limit: máx. 5 tentativas de chave por IP a cada 15 min (anti brute-force)
                    $rl_key = 'blwp_secret_rl_' . md5(blwp_get_client_ip());
                    $attempts = (int) get_transient($rl_key);
                    if ($attempts >= 5) {
                        blwp_show_secret_key_form($token, __('Muitas tentativas. Aguarde 15 minutos.', 'dolutech-blacklist-protect'));
                        exit;
                    }
                    set_transient($rl_key, $attempts + 1, 15 * MINUTE_IN_SECONDS);
                    
                    // Verifica reCAPTCHA se estiver habilitado
                    $recaptcha_response = isset($_POST['g-recaptcha-response']) ? sanitize_text_field(wp_unslash($_POST['g-recaptcha-response'])) : '';
                    if (!blwp_verify_recaptcha($recaptcha_response)) {
                        blwp_show_secret_key_form($token, __('Por favor, complete a verificação reCAPTCHA.', 'dolutech-blacklist-protect'));
                        exit;
                    }
                    
                    $provided_key = sanitize_text_field(wp_unslash($_POST['blwp_unblock_secret_key']));
                    
                    // Comparação em tempo constante contra o hash armazenado
                    if (!hash_equals($stored_secret_key, wp_hash($provided_key))) {
                        blwp_show_secret_key_form($token, __('Chave secreta incorreta. Tente novamente.', 'dolutech-blacklist-protect'));
                        exit;
                    }
                    // Chave correta, continua com o desbloqueio
                } else {
                    // Mostra o formulário para inserir a chave secreta
                    blwp_show_secret_key_form($token);
                    exit;
                }
            }
            
            // Remove o IP da lista de bloqueio manual
            $manual = get_option('blwp_manual_blocked_ips', []);
            $manual = array_diff($manual, [$ip]);
            update_option('blwp_manual_blocked_ips', $manual);
            
            // Remove o IP da lista de bloqueio temporário
            $temp_blocks = get_option('blwp_temp_blocked_ips', []);
            if (isset($temp_blocks[$ip])) {
                unset($temp_blocks[$ip]);
                update_option('blwp_temp_blocked_ips', $temp_blocks);
            }
            
            // Marca o token como usado
            $tokens[$token]['used'] = true;
            update_option('blwp_unblock_tokens', $tokens);
            
            // Limpa tentativas de login falhas
            delete_transient('blwp_failed_attempts_' . $ip);
            
            wp_die(
                sprintf(
                    '<div style="text-align: center; padding: 50px; font-family: sans-serif;">
                        <h1 style="color: #28a745;">%s</h1>
                        <p>%s <strong>%s</strong> %s</p>
                        <p><a href="%s">%s</a></p>
                    </div>',
                    esc_html__('IP Desbloqueado com Sucesso!', 'dolutech-blacklist-protect'),
                    esc_html__('O IP', 'dolutech-blacklist-protect'),
                    esc_html($ip),
                    esc_html__('foi removido da lista de bloqueio.', 'dolutech-blacklist-protect'),
                    esc_url(home_url()),
                    esc_html__('Ir para a página inicial', 'dolutech-blacklist-protect')
                ),
                esc_html__('Desbloqueio Realizado', 'dolutech-blacklist-protect')
            );
        } else {
            wp_die(
                esc_html__('Token inválido ou expirado.', 'dolutech-blacklist-protect'),
                esc_html__('Erro', 'dolutech-blacklist-protect')
            );
        }
    }
}

/**
 * Mostra formulário para inserir chave secreta
 */
function blwp_show_secret_key_form($token, $error_message = '') {
    ?>
    <!DOCTYPE html>
    <html <?php language_attributes(); ?>>
    <head>
        <meta charset="<?php bloginfo('charset'); ?>">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title><?php esc_html_e('Verificação de Segurança', 'dolutech-blacklist-protect'); ?></title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                background-color: #f5f5f5;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
                padding: 20px;
            }
            .form-container {
                background: white;
                padding: 40px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                max-width: 500px;
                width: 100%;
            }
            h1 {
                color: #333;
                margin-bottom: 10px;
                text-align: center;
                font-size: 24px;
            }
            p {
                color: #666;
                line-height: 1.6;
                margin-bottom: 20px;
                text-align: center;
            }
            .error-message {
                background-color: #fee;
                border-left: 4px solid #dc3545;
                padding: 10px;
                margin-bottom: 20px;
                color: #721c24;
            }
            input[type="password"] {
                width: 100%;
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 16px;
                margin-bottom: 20px;
                box-sizing: border-box;
            }
            input[type="password"]:focus {
                outline: none;
                border-color: #0073aa;
                box-shadow: 0 0 0 2px rgba(0,115,170,0.1);
            }
            .submit-btn {
                background-color: #0073aa;
                color: white;
                padding: 12px 30px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                width: 100%;
                font-size: 16px;
                transition: background-color 0.3s;
                margin-top: 10px;
            }
            .submit-btn:hover {
                background-color: #005177;
            }
            .security-notice {
                background-color: #f0f8ff;
                border-left: 4px solid #0073aa;
                padding: 10px;
                margin-top: 20px;
                font-size: 14px;
                color: #31708f;
            }
        </style>
    </head>
    <body>
        <div class="form-container">
            <h1><?php esc_html_e('Verificação de Segurança', 'dolutech-blacklist-protect'); ?></h1>
            <p><?php esc_html_e('Para continuar com o desbloqueio, insira a chave secreta.', 'dolutech-blacklist-protect'); ?></p>
            
            <?php if ($error_message) : ?>
                <div class="error-message">
                    <?php echo esc_html($error_message); ?>
                </div>
            <?php endif; ?>
            
            <form method="post">
                <?php wp_nonce_field('blwp_secret_key_verify', 'blwp_secret_nonce'); ?>
                <input type="password" name="blwp_unblock_secret_key" placeholder="<?php esc_attr_e('Digite a chave secreta', 'dolutech-blacklist-protect'); ?>" required autofocus />
                
                <?php if (blwp_is_recaptcha_enabled()) : ?>
                    <?php echo wp_kses_post(blwp_render_recaptcha()); ?>
                <?php endif; ?>
                
                <button type="submit" class="submit-btn">
                    <?php esc_html_e('Verificar e Desbloquear', 'dolutech-blacklist-protect'); ?>
                </button>
            </form>
            
            <div class="security-notice">
                <strong><?php esc_html_e('Nota:', 'dolutech-blacklist-protect'); ?></strong>
                <?php esc_html_e('Esta é uma medida adicional de segurança. Se você não possui a chave secreta, entre em contato com o administrador do site.', 'dolutech-blacklist-protect'); ?>
            </div>
        </div>
    </body>
    </html>
    <?php
}

/**
 * Limpa tokens expirados periodicamente
 */
add_action('blwp_update_blacklist_hook', 'blwp_clean_expired_tokens');
function blwp_clean_expired_tokens() {
    $tokens = get_option('blwp_unblock_tokens', []);
    $current_time = time();
    
    foreach ($tokens as $token => $data) {
        if ($data['expiration'] < $current_time) {
            unset($tokens[$token]);
        }
    }
    
    update_option('blwp_unblock_tokens', $tokens);
}

/**
 * Bloqueio de IPs por tentativas de login com usuários específicos
 */
add_action('wp_authenticate', 'blwp_block_ip_for_specific_users', 5, 2);
add_action('authenticate', 'blwp_block_ip_for_specific_users_early', 1, 3);

function blwp_block_ip_for_specific_users_early($user, $username, $password) {
    if (empty($username)) {
        return $user;
    }
    
    // Chama a função principal de bloqueio
    blwp_block_ip_for_specific_users($username, $password);
    return $user;
}

function blwp_block_ip_for_specific_users($username, $password) {
    // Valida se o username não está vazio
    if (empty($username)) {
        return;
    }
    
    // Verifica se a funcionalidade está habilitada
    if (!get_option('blwp_user_block_enabled', 0)) {
        return;
    }
    
    // Captura do IP do usuário
    $ip = blwp_get_client_ip();
    
    // Se não houver IP válido ou ele estiver na whitelist, não faz nada
    if (! $ip || blwp_is_whitelisted($ip)) {
        return;
    }
    
    // Obtém a lista de usuários bloqueados
    $blocked_usernames = get_option('blwp_blocked_usernames', []);
    
    if (empty($blocked_usernames)) {
        return;
    }
    
    // Verifica se o username está na lista de bloqueados
    if (in_array($username, $blocked_usernames, true)) {
        // Verifica se o usuário NÃO existe (só bloqueia se NÃO existir)
        if (!username_exists($username)) {
            $temp_block_enabled = get_option('blwp_temp_block_enabled', 0);
            
            if ($temp_block_enabled) {
                // Bloqueio temporário
                $block_duration = (int) get_option('blwp_temp_block_duration', 60); // minutos
                $temp_blocks = get_option('blwp_temp_blocked_ips', []);
                $temp_blocks[$ip] = time() + ($block_duration * MINUTE_IN_SECONDS);
                update_option('blwp_temp_blocked_ips', $temp_blocks);
            } else {
                // Bloqueio permanente
                $manual = get_option('blwp_manual_blocked_ips', []);
                if (!in_array($ip, $manual, true)) {
                    $manual[] = $ip;
                    update_option('blwp_manual_blocked_ips', $manual);
                }
            }
            
            // Envia relatório automático de abuso
            blwp_send_abuse_report(
                $ip,
                sprintf(
                    'Bloqueio automático por tentativa de login com usuário inexistente protegido: %s',
                    $username
                )
            );
            
            // Redireciona para página de bloqueio ou mata a requisição
            wp_die(
                sprintf(
                    '<div style="text-align: center; padding: 50px; font-family: sans-serif;">
                        <h1 style="color: #dc3545;">%s</h1>
                        <p>%s</p>
                        <p style="color: #666; font-size: 14px;">IP: %s</p>
                    </div>',
                    esc_html__('Acesso Bloqueado', 'dolutech-blacklist-protect'),
                    esc_html__('Tentativa de acesso com usuário inexistente protegido. Seu IP foi bloqueado.', 'dolutech-blacklist-protect'),
                    esc_html($ip)
                ),
                esc_html__('Acesso Negado', 'dolutech-blacklist-protect'),
                ['response' => 403]
            );
        }
    }
}

/**
 * Início da funcionalidade de proteção contra brute force.
 * Após X tentativas de login falhas pelo mesmo IP (configurável),
 * adiciona automaticamente o IP à blacklist manual e envia notificação.
 */
add_action('wp_login_failed', 'blwp_track_failed_login', 10, 1);
function blwp_track_failed_login($username) {
    // Captura do IP do usuário
    $ip = blwp_get_client_ip();

    // Se não houver IP válido ou ele estiver na whitelist, não faz nada
    if (! $ip || blwp_is_whitelisted($ip)) {
        return;
    }

    // Obtém o limite configurado (padrão: 3)
    $max_attempts = (int) get_option('blwp_max_login_attempts', 3);
    
    // Chave de transient para armazenar contador de tentativas
    $transient_key = 'blwp_failed_attempts_' . $ip;
    $attempts = (int) get_transient($transient_key);
    $attempts++;
    // Transient expira em 1 hora (HOUR_IN_SECONDS)
    set_transient($transient_key, $attempts, HOUR_IN_SECONDS);

    // Se atingiu o limite de tentativas falhas
    if ($attempts >= $max_attempts) {
        // Verifica se está habilitado o bloqueio temporário
        $temp_block_enabled = get_option('blwp_temp_block_enabled', 0);
        
        if ($temp_block_enabled) {
            // Bloqueio temporário
            $block_duration = (int) get_option('blwp_temp_block_duration', 60); // minutos
            $temp_blocks = get_option('blwp_temp_blocked_ips', []);
            $temp_blocks[$ip] = time() + ($block_duration * MINUTE_IN_SECONDS);
            update_option('blwp_temp_blocked_ips', $temp_blocks);
            
            // Envia relatório automático de abuso
            blwp_send_abuse_report(
                $ip,
                sprintf(
                    'Bloqueio temporário por %d tentativas de login incorretas (duração: %d minutos)',
                    $max_attempts,
                    $block_duration
                )
            );
        } else {
            // Bloqueio permanente (comportamento original)
            $manual = get_option('blwp_manual_blocked_ips', []);
            if (! in_array($ip, $manual, true)) {
                $manual[] = $ip;
                update_option('blwp_manual_blocked_ips', $manual);
                // Envia relatório automático de abuso
                blwp_send_abuse_report(
                    $ip,
                    sprintf(
                        'Bloqueio automático por %d tentativas de login incorretas',
                        $max_attempts
                    )
                );
            }
        }
        // Limpa o contador de tentativas após bloqueio
        delete_transient($transient_key);
    }
}

/**
 * Exibe mensagem genérica em casos de usuário ou senha incorretos
 */
add_filter('login_errors', 'blwp_generic_login_error', 10, 1);
function blwp_generic_login_error($error) {
    // Mensagem genérica: não revela o plugin nem se o usuário existe
    return __('Usuário ou senha incorretos. Tente novamente.', 'dolutech-blacklist-protect');
}

/**
 * Mostra página de bloqueio temporário
 */
function blwp_show_temp_blocked_page($ip, $minutes_remaining) {
    status_header(403);
    ?>
    <!DOCTYPE html>
    <html <?php language_attributes(); ?>>
    <head>
        <meta charset="<?php bloginfo('charset'); ?>">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title><?php esc_html_e('Bloqueio Temporário', 'dolutech-blacklist-protect'); ?></title>
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
                color: #ff9800;
                margin-bottom: 20px;
            }
            p {
                color: #666;
                line-height: 1.6;
                margin-bottom: 20px;
            }
            .time-remaining {
                background-color: #fff3e0;
                border-left: 4px solid #ff9800;
                padding: 15px;
                margin-top: 20px;
                text-align: left;
            }
        </style>
    </head>
    <body>
        <div class="blocked-container">
            <h1><?php esc_html_e('Bloqueio Temporário', 'dolutech-blacklist-protect'); ?></h1>
            <p><?php esc_html_e('Seu IP foi temporariamente bloqueado devido a múltiplas tentativas de login falhadas.', 'dolutech-blacklist-protect'); ?></p>
            
            <div class="time-remaining">
                <strong><?php esc_html_e('Tempo restante de bloqueio:', 'dolutech-blacklist-protect'); ?></strong><br>
                <?php 
                if ($minutes_remaining >= 60) {
                    $hours = floor($minutes_remaining / 60);
                    $mins = $minutes_remaining % 60;
                    echo esc_html(sprintf('%d h %d min', $hours, $mins));
                } else {
                    echo esc_html(sprintf(
                        /* translators: %d: number of minutes remaining */
                        _n('%d minuto', '%d minutos', $minutes_remaining, 'dolutech-blacklist-protect'),
                        $minutes_remaining
                    ));
                }
                ?>
            </div>
            
            <p style="margin-top: 30px; font-size: 14px; color: #999;">
                <?php esc_html_e('Por favor, aguarde o período de bloqueio terminar antes de tentar novamente.', 'dolutech-blacklist-protect'); ?>
            </p>
        </div>
    </body>
    </html>
    <?php
}

/**
 * Limpa IPs com bloqueio temporário expirado
 */
add_action('blwp_update_blacklist_hook', 'blwp_clean_expired_temp_blocks');
function blwp_clean_expired_temp_blocks() {
    $temp_blocks = get_option('blwp_temp_blocked_ips', []);
    $current_time = time();
    $cleaned = false;
    
    foreach ($temp_blocks as $ip => $expiration) {
        if ($expiration < $current_time) {
            unset($temp_blocks[$ip]);
            $cleaned = true;
        }
    }
    
    if ($cleaned) {
        update_option('blwp_temp_blocked_ips', $temp_blocks);
    }
}

/**
 * Proteção contra ataques via XML-RPC
 */
add_action('init', 'blwp_protect_xmlrpc', 1);
function blwp_protect_xmlrpc() {
    // Verifica se a proteção XML-RPC está habilitada
    if (!get_option('blwp_block_xmlrpc', 0)) {
        return;
    }
    
    // Verifica se é uma requisição ao xmlrpc.php
    if (isset($_SERVER['REQUEST_URI']) && strpos(sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])), 'xmlrpc.php') !== false) {
        $ip = blwp_get_client_ip();

        // Permite IPs na whitelist
        if ($ip && blwp_is_whitelisted($ip)) {
            return;
        }
        
        // Registra tentativa de acesso ao XML-RPC
        if ($ip && get_option('blwp_xmlrpc_log_attempts', 1)) {
            $log_key = 'blwp_xmlrpc_attempts_' . $ip;
            $attempts = (int) get_transient($log_key);
            $attempts++;
            set_transient($log_key, $attempts, HOUR_IN_SECONDS);
            
            // Se exceder o limite, adiciona ao bloqueio
            $max_xmlrpc_attempts = (int) get_option('blwp_max_xmlrpc_attempts', 5);
            if ($attempts >= $max_xmlrpc_attempts) {
                $temp_block_enabled = get_option('blwp_temp_block_enabled', 0);
                
                if ($temp_block_enabled) {
                    // Bloqueio temporário
                    $block_duration = (int) get_option('blwp_temp_block_duration', 60);
                    $temp_blocks = get_option('blwp_temp_blocked_ips', []);
                    $temp_blocks[$ip] = time() + ($block_duration * MINUTE_IN_SECONDS);
                    update_option('blwp_temp_blocked_ips', $temp_blocks);
                } else {
                    // Bloqueio permanente
                    $manual = get_option('blwp_manual_blocked_ips', []);
                    if (!in_array($ip, $manual, true)) {
                        $manual[] = $ip;
                        update_option('blwp_manual_blocked_ips', $manual);
                    }
                }
                
                // Envia denúncia
                blwp_send_abuse_report(
                    $ip,
                    sprintf('Bloqueio automático por %d tentativas de acesso ao XML-RPC', $max_xmlrpc_attempts)
                );
                
                delete_transient($log_key);
            }
        }
        
        // Bloqueia o acesso
        status_header(403);
        wp_die(
            esc_html__('Acesso ao XML-RPC bloqueado pelo Dolutech Blacklist Protect.', 'dolutech-blacklist-protect'),
            esc_html__('Acesso Negado', 'dolutech-blacklist-protect'),
            ['response' => 403]
        );
    }
}

/**
 * Desabilita métodos perigosos do XML-RPC se não estiver completamente bloqueado
 */
add_filter('xmlrpc_methods', 'blwp_disable_dangerous_xmlrpc_methods');
function blwp_disable_dangerous_xmlrpc_methods($methods) {
    if (get_option('blwp_disable_dangerous_xmlrpc', 1)) {
        // Remove métodos perigosos mas mantém pingback se necessário
        unset($methods['system.multicall']);
        unset($methods['wp.getUsersBlogs']);
        unset($methods['wp.getAuthors']);
    }
    return $methods;
}

/**
 * Verifica se o reCAPTCHA está configurado e ativo
 */
function blwp_is_recaptcha_enabled() {
    $enabled = get_option('blwp_recaptcha_enabled', 0);
    $site_key = get_option('blwp_recaptcha_site_key', '');
    $secret_key = get_option('blwp_recaptcha_secret_key', '');
    
    return $enabled && !empty($site_key) && !empty($secret_key);
}

/**
 * Valida a resposta do reCAPTCHA
 */
function blwp_verify_recaptcha($response) {
    if (!blwp_is_recaptcha_enabled()) {
        return true; // Se não está habilitado, passa na validação
    }
    
    if (empty($response)) {
        return false;
    }
    
    $secret_key = get_option('blwp_recaptcha_secret_key', '');
    $verify_url = 'https://www.google.com/recaptcha/api/siteverify';
    
    $data = [
        'secret' => $secret_key,
        'response' => $response,
        'remoteip' => blwp_get_client_ip()
    ];
    
    $args = [
        'body' => $data,
        'method' => 'POST',
        'timeout' => 10,
        'sslverify' => true
    ];
    
    $response = wp_remote_post($verify_url, $args);
    
    if (is_wp_error($response)) {
        return false;
    }
    
    $body = wp_remote_retrieve_body($response);
    $result = json_decode($body, true);
    
    return isset($result['success']) && $result['success'] === true;
}

/**
 * Renderiza o script e div do reCAPTCHA
 */
function blwp_render_recaptcha() {
    if (!blwp_is_recaptcha_enabled()) {
        return '';
    }

    $site_key = get_option('blwp_recaptcha_site_key', '');

    // As páginas de bloqueio/desbloqueio são HTML standalone (sem wp_head/wp_footer),
    // então o script do Google precisa ser impresso inline junto com o widget.
    return sprintf(
        '<script src="https://www.google.com/recaptcha/api.js" async defer></script>' .
        '<div class="g-recaptcha" data-sitekey="%s" style="margin: 20px 0;"></div>',
        esc_attr($site_key)
    );
}
<?php

if (!defined('ABSPATH')) {
    exit;
}

add_action('admin_menu', 'blwp_admin_menu');
function blwp_admin_menu() {
    add_options_page(
        'Dolutech Blacklist Protect',
        'Dolutech Blacklist Protect',
        'manage_options',
        'blacklist-wp-protect',
        'blwp_render_settings_page'
    );
}

function blwp_render_settings_page() {
    if (isset($_POST['blwp_manual_report']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $ip = isset($_POST['blwp_ip']) ? sanitize_text_field(wp_unslash($_POST['blwp_ip'])) : '';
        $reason = isset($_POST['blwp_reason']) ? sanitize_text_field(wp_unslash($_POST['blwp_reason'])) : '';
        if ($ip && $reason) {
            blwp_send_abuse_report($ip, $reason, true); // Ação explícita do admin: envia sempre.
            echo '<div class="notice notice-success"><p>' . esc_html__('IP denunciado com sucesso!', 'dolutech-blacklist-protect') . '</p></div>';
        }
    }

    if (isset($_POST['blwp_toggle_auto_report']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $auto_report = isset($_POST['auto_report']) ? 1 : 0;
        update_option('blwp_auto_report', $auto_report);
        echo '<div class="notice notice-success"><p>' . esc_html__('Configuração salva.', 'dolutech-blacklist-protect') . '</p></div>';
    }

    if (isset($_POST['blwp_toggle_blacklist']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $blacklist_enabled = isset($_POST['blacklist_enabled']) ? 1 : 0;
        update_option('blwp_blacklist_enabled', $blacklist_enabled);
        echo '<div class="notice notice-success"><p>' . esc_html__('Status da blacklist atualizado.', 'dolutech-blacklist-protect') . '</p></div>';
    }

    if (isset($_POST['blwp_save_whitelist']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $raw = '';
        if (isset($_POST['blwp_whitelist'])) {
            $raw = sanitize_textarea_field(wp_unslash($_POST['blwp_whitelist']));
        }

        $lines = explode("\n", $raw);
        $entries = [];

        foreach ($lines as $line) {
            $clean = sanitize_text_field(trim($line));
            if (!empty($clean)) {
                $entries[] = $clean;
            }
        }

        update_option('blwp_whitelist', $entries);
        echo '<div class="notice notice-success"><p>' . esc_html__('Whitelist atualizada.', 'dolutech-blacklist-protect') . '</p></div>';
    }

    // Salvar configurações de bloqueio CIDR e User-Agent
    if (isset($_POST['blwp_save_cidr_ua_settings']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $cidr_raw = isset($_POST['blwp_cidr_blocked']) ? sanitize_textarea_field(wp_unslash($_POST['blwp_cidr_blocked'])) : '';
        $ua_raw = isset($_POST['blwp_ua_blocked']) ? sanitize_textarea_field(wp_unslash($_POST['blwp_ua_blocked'])) : '';
        $ua_enabled = isset($_POST['blwp_ua_block_enabled']) ? 1 : 0;

        // Valida CIDRs, ignora inválidos
        $valid_cidrs = [];
        $invalid_cidrs = [];
        foreach (array_filter(array_map('trim', explode("\n", $cidr_raw))) as $cidr) {
            if (blwp_is_valid_cidr($cidr)) {
                $valid_cidrs[] = $cidr;
            } else {
                $invalid_cidrs[] = $cidr;
            }
        }

        $uas = array_values(array_filter(array_map('trim', explode("\n", $ua_raw))));

        update_option('blwp_cidr_blocked', $valid_cidrs);
        update_option('blwp_ua_blocked', $uas);
        update_option('blwp_ua_block_enabled', $ua_enabled);

        if (!empty($invalid_cidrs)) {
            echo '<div class="notice notice-warning"><p>' .
                 sprintf(
                     /* translators: %s: comma-separated list of invalid CIDRs */
                     esc_html__('CIDRs inválidos ignorados: %s', 'dolutech-blacklist-protect'),
                     implode(', ', array_map('esc_html', $invalid_cidrs))
                 ) .
                 '</p></div>';
        }

        echo '<div class="notice notice-success"><p>' . esc_html__('Configurações de CIDR e User-Agent salvas.', 'dolutech-blacklist-protect') . '</p></div>';
    }

    // Salvar configurações de notificações
    if (isset($_POST['blwp_save_notification_settings']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $telegram_enabled = isset($_POST['blwp_telegram_enabled']) ? 1 : 0;
        update_option('blwp_telegram_enabled', $telegram_enabled);

        if ($telegram_enabled) {
            $bot_token = isset($_POST['blwp_telegram_bot_token']) ? sanitize_text_field(wp_unslash($_POST['blwp_telegram_bot_token'])) : '';
            $chat_id = isset($_POST['blwp_telegram_chat_id']) ? sanitize_text_field(wp_unslash($_POST['blwp_telegram_chat_id'])) : '';
            // Só atualiza se o campo não estiver em branco (mantém a atual)
            if (!empty($bot_token)) {
                update_option('blwp_telegram_bot_token', $bot_token);
            }
            if (!empty($chat_id)) {
                update_option('blwp_telegram_chat_id', $chat_id);
            }
        }

        $webhook_enabled = isset($_POST['blwp_webhook_enabled']) ? 1 : 0;
        update_option('blwp_webhook_enabled', $webhook_enabled);

        if ($webhook_enabled) {
            $webhook_url = isset($_POST['blwp_webhook_url']) ? esc_url_raw(wp_unslash($_POST['blwp_webhook_url'])) : '';
            if (!empty($webhook_url)) {
                update_option('blwp_webhook_url', $webhook_url);
            }
        }

        // Eventos que disparam notificação
        $event_labels = blwp_get_event_labels();
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- cada elemento é sanitizado com sanitize_key abaixo.
        $notify_events_raw = isset($_POST['blwp_notify_events']) ? wp_unslash((array) $_POST['blwp_notify_events']) : [];
        $notify_events = array_values(array_filter(array_map('sanitize_key', $notify_events_raw), function ($key) use ($event_labels) {
            return isset($event_labels[$key]);
        }));
        update_option('blwp_notify_events', $notify_events);

        echo '<div class="notice notice-success"><p>' . esc_html__('Configurações de notificações salvas.', 'dolutech-blacklist-protect') . '</p></div>';
    }

    // Enviar notificação de teste
    if (isset($_POST['blwp_test_notification']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        blwp_test_notifications();
        echo '<div class="notice notice-success"><p>' . esc_html__('Notificação de teste enviada.', 'dolutech-blacklist-protect') . '</p></div>';
    }

    if (isset($_POST['blwp_add_manual_block']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $ip = isset($_POST['manual_ip']) ? sanitize_text_field(wp_unslash($_POST['manual_ip'])) : '';
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            $list = blwp_get_manual_blocked_ips();
            if (!in_array($ip, $list, true)) {
                $list[] = $ip;
                update_option('blwp_manual_blocked_ips', $list);
                blwp_log_event($ip, 'admin_block', 'Bloqueio manual pelo admin', 'admin');
                echo '<div class="notice notice-success"><p>' . esc_html__('IP bloqueado manualmente.', 'dolutech-blacklist-protect') . '</p></div>';
            } else {
                echo '<div class="notice notice-warning"><p>' . esc_html__('Este IP já está na lista de bloqueio manual.', 'dolutech-blacklist-protect') . '</p></div>';
            }
        } else {
            echo '<div class="notice notice-error"><p>' . esc_html__('IP inválido. Nenhum bloqueio realizado.', 'dolutech-blacklist-protect') . '</p></div>';
        }
    }

    if (isset($_POST['blwp_remove_manual_block']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $remove_ip = isset($_POST['remove_ip']) ? sanitize_text_field(wp_unslash($_POST['remove_ip'])) : '';
        if (filter_var($remove_ip, FILTER_VALIDATE_IP)) {
            $list = blwp_get_manual_blocked_ips();
            if (in_array($remove_ip, $list, true)) {
                $list = array_diff($list, [$remove_ip]);
                update_option('blwp_manual_blocked_ips', $list);
                blwp_log_event($remove_ip, 'admin_unblock', 'Desbloqueio manual pelo admin', 'admin');
                echo '<div class="notice notice-success"><p>' . esc_html__('IP desbloqueado.', 'dolutech-blacklist-protect') . '</p></div>';
            } else {
                echo '<div class="notice notice-warning"><p>' . esc_html__('Este IP não está na lista de bloqueio manual.', 'dolutech-blacklist-protect') . '</p></div>';
            }
        } else {
            echo '<div class="notice notice-error"><p>' . esc_html__('IP inválido. Nenhum desbloqueio realizado.', 'dolutech-blacklist-protect') . '</p></div>';
        }
    }

    if (isset($_POST['blwp_manual_update']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        blwp_fetch_blacklist();
        echo '<div class="notice notice-success"><p>' . esc_html__('Blacklist atualizada manualmente.', 'dolutech-blacklist-protect') . '</p></div>';
    }
    
    // Adicionar nova blacklist de terceiros
    if (isset($_POST['blwp_add_third_party']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $url = isset($_POST['third_party_url']) ? esc_url_raw(wp_unslash($_POST['third_party_url'])) : '';
        $name = isset($_POST['third_party_name']) ? sanitize_text_field(wp_unslash($_POST['third_party_name'])) : '';
        
        if ($url && blwp_add_third_party_blacklist($url, $name)) {
            echo '<div class="notice notice-success"><p>' . esc_html__('Blacklist de terceiros adicionada com sucesso!', 'dolutech-blacklist-protect') . '</p></div>';
        } else {
            echo '<div class="notice notice-error"><p>' . esc_html__('Erro ao adicionar blacklist. Verifique se a URL é válida e não está duplicada.', 'dolutech-blacklist-protect') . '</p></div>';
        }
    }
    
    // Remover blacklist de terceiros
    if (isset($_POST['blwp_remove_third_party']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $list_id = isset($_POST['list_id']) ? sanitize_text_field(wp_unslash($_POST['list_id'])) : '';
        
        if ($list_id && blwp_remove_third_party_blacklist($list_id)) {
            echo '<div class="notice notice-success"><p>' . esc_html__('Blacklist removida com sucesso!', 'dolutech-blacklist-protect') . '</p></div>';
        }
    }
    
    // Alternar status da blacklist de terceiros
    if (isset($_POST['blwp_toggle_third_party']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $list_id = isset($_POST['list_id']) ? sanitize_text_field(wp_unslash($_POST['list_id'])) : '';
        
        if ($list_id && blwp_toggle_third_party_blacklist($list_id)) {
            echo '<div class="notice notice-success"><p>' . esc_html__('Status da blacklist atualizado!', 'dolutech-blacklist-protect') . '</p></div>';
        }
    }

    // Nova funcionalidade: Salvar configuração de tentativas máximas
    if (isset($_POST['blwp_save_login_settings']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $max_attempts = isset($_POST['blwp_max_login_attempts']) ? absint($_POST['blwp_max_login_attempts']) : 3;
        if ($max_attempts < 1) {
            $max_attempts = 3;
        }
        update_option('blwp_max_login_attempts', $max_attempts);
        
        // Configurações de bloqueio temporário
        $temp_block_enabled = isset($_POST['blwp_temp_block_enabled']) ? 1 : 0;
        update_option('blwp_temp_block_enabled', $temp_block_enabled);
        
        if ($temp_block_enabled) {
            $temp_block_duration = isset($_POST['blwp_temp_block_duration']) ? absint($_POST['blwp_temp_block_duration']) : 60;
            if ($temp_block_duration < 1) {
                $temp_block_duration = 60;
            }
            update_option('blwp_temp_block_duration', $temp_block_duration);
        }
        
        // Configurações de chave secreta
        $secret_key_enabled = isset($_POST['blwp_secret_key_enabled']) ? 1 : 0;
        update_option('blwp_secret_key_enabled', $secret_key_enabled);
        
        if ($secret_key_enabled) {
            $secret_key = isset($_POST['blwp_secret_key']) ? sanitize_text_field(wp_unslash($_POST['blwp_secret_key'])) : '';
            if (!empty($secret_key)) {
                update_option('blwp_secret_key', wp_hash($secret_key));
            }
        }
        
        echo '<div class="notice notice-success"><p>' . esc_html__('Configuração de tentativas de login salva.', 'dolutech-blacklist-protect') . '</p></div>';
    }
    
    // Salvar configurações de bloqueio por usuário
    if (isset($_POST['blwp_save_user_block_settings']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $user_block_enabled = isset($_POST['blwp_user_block_enabled']) ? 1 : 0;
        update_option('blwp_user_block_enabled', $user_block_enabled);
        
        // Sempre processa a lista de usuários, mesmo se desativado
        $blocked_usernames = isset($_POST['blwp_blocked_usernames']) ? sanitize_textarea_field(wp_unslash($_POST['blwp_blocked_usernames'])) : '';
        $usernames = array_filter(array_map('trim', explode("\n", $blocked_usernames)));
        
        // Valida se os usuários existem
        $valid_usernames = [];
        $invalid_usernames = [];
        
        foreach ($usernames as $username) {
            if (!empty($username)) {
                if (!username_exists($username)) {
                    $valid_usernames[] = $username;
                } else {
                    $invalid_usernames[] = $username;
                }
            }
        }
        
        // Salva a lista mesmo se desativado (para manter configuração)
        update_option('blwp_blocked_usernames', $valid_usernames);
        
        // Mostra mensagens informativas
        if (!empty($invalid_usernames)) {
            echo '<div class="notice notice-warning"><p>' . 
                 sprintf(
                     /* translators: %s: comma-separated list of usernames */
                     esc_html__('Aviso: Os seguintes usuários existem no sistema e foram ignorados: %s', 'dolutech-blacklist-protect'),
                     implode(', ', array_map('esc_html', $invalid_usernames))
                 ) . 
                 '</p></div>';
        }
        
        if (!empty($valid_usernames)) {
            echo '<div class="notice notice-info"><p>' . 
                 sprintf(
                     /* translators: %s: comma-separated list of usernames */
                     esc_html__('Usuários inexistentes adicionados à lista de bloqueio: %s', 'dolutech-blacklist-protect'),
                     implode(', ', array_map('esc_html', $valid_usernames))
                 ) . 
                 '</p></div>';
        }
        
        echo '<div class="notice notice-success"><p>' . esc_html__('Configurações de bloqueio por usuário salvas.', 'dolutech-blacklist-protect') . '</p></div>';
    }
    
    // Salvar configurações reCAPTCHA
    if (isset($_POST['blwp_save_recaptcha_settings']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $recaptcha_enabled = isset($_POST['blwp_recaptcha_enabled']) ? 1 : 0;
        update_option('blwp_recaptcha_enabled', $recaptcha_enabled);
        
        if ($recaptcha_enabled) {
            $site_key = isset($_POST['blwp_recaptcha_site_key']) ? sanitize_text_field(wp_unslash($_POST['blwp_recaptcha_site_key'])) : '';
            $secret_key = isset($_POST['blwp_recaptcha_secret_key']) ? sanitize_text_field(wp_unslash($_POST['blwp_recaptcha_secret_key'])) : '';
            
            update_option('blwp_recaptcha_site_key', $site_key);
            // Só atualiza a secret key se o campo não estiver em branco (mantém a atual)
            if (!empty($secret_key)) {
                update_option('blwp_recaptcha_secret_key', $secret_key);
            }
        }
        
        echo '<div class="notice notice-success"><p>' . esc_html__('Configurações reCAPTCHA salvas.', 'dolutech-blacklist-protect') . '</p></div>';
    }
    
    // Salvar configurações XML-RPC
    if (isset($_POST['blwp_save_xmlrpc_settings']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $block_xmlrpc = isset($_POST['blwp_block_xmlrpc']) ? 1 : 0;
        update_option('blwp_block_xmlrpc', $block_xmlrpc);

        $xmlrpc_log_attempts = isset($_POST['blwp_xmlrpc_log_attempts']) ? 1 : 0;
        update_option('blwp_xmlrpc_log_attempts', $xmlrpc_log_attempts);

        $max_xmlrpc_attempts = isset($_POST['blwp_max_xmlrpc_attempts']) ? absint($_POST['blwp_max_xmlrpc_attempts']) : 5;
        if ($max_xmlrpc_attempts < 1) {
            $max_xmlrpc_attempts = 5;
        }
        update_option('blwp_max_xmlrpc_attempts', $max_xmlrpc_attempts);

        $disable_dangerous_xmlrpc = isset($_POST['blwp_disable_dangerous_xmlrpc']) ? 1 : 0;
        update_option('blwp_disable_dangerous_xmlrpc', $disable_dangerous_xmlrpc);

        echo '<div class="notice notice-success"><p>' . esc_html__('Configurações XML-RPC salvas.', 'dolutech-blacklist-protect') . '</p></div>';
    }

    // Salvar configurações MaxMind
    if (isset($_POST['blwp_save_maxmind_settings']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $maxmind_enabled = isset($_POST['blwp_maxmind_enabled']) ? 1 : 0;
        $account_id = isset($_POST['blwp_maxmind_account_id']) ? sanitize_text_field(wp_unslash($_POST['blwp_maxmind_account_id'])) : '';
        $api_key = isset($_POST['blwp_maxmind_api_key']) ? sanitize_text_field(wp_unslash($_POST['blwp_maxmind_api_key'])) : '';

        // Valida as credenciais se estiver habilitando
        if ($maxmind_enabled && !empty($account_id) && !empty($api_key)) {
            $validation = blwp_validate_maxmind_credentials($account_id, $api_key);

            if ($validation['valid']) {
                update_option('blwp_maxmind_enabled', $maxmind_enabled);
                update_option('blwp_maxmind_account_id', $account_id);
                update_option('blwp_maxmind_api_key', $api_key);

                echo '<div class="notice notice-success"><p>' . esc_html($validation['message']) . '</p></div>';
            } else {
                echo '<div class="notice notice-error"><p>' . esc_html($validation['message']) . '</p></div>';
            }
        } else {
            // Se estiver desabilitando ou campos vazios
            update_option('blwp_maxmind_enabled', $maxmind_enabled);
            if (!empty($account_id)) {
                update_option('blwp_maxmind_account_id', $account_id);
            }
            if (!empty($api_key)) {
                update_option('blwp_maxmind_api_key', $api_key);
            }

            echo '<div class="notice notice-success"><p>' . esc_html__('Configurações MaxMind salvas.', 'dolutech-blacklist-protect') . '</p></div>';
        }
    }

    // Salvar países bloqueados
    if (isset($_POST['blwp_save_blocked_countries']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $blocked_countries_raw = isset($_POST['blwp_blocked_countries']) ? sanitize_textarea_field(wp_unslash($_POST['blwp_blocked_countries'])) : '';
        $countries = array_filter(array_map('trim', array_map('strtoupper', explode("\n", $blocked_countries_raw))));

        // Valida códigos de país (2 letras)
        $valid_countries = [];
        $invalid_countries = [];

        foreach ($countries as $country) {
            if (preg_match('/^[A-Z]{2}$/', $country)) {
                $valid_countries[] = $country;
            } else {
                $invalid_countries[] = $country;
            }
        }

        update_option('blwp_blocked_countries', $valid_countries);

        if (!empty($invalid_countries)) {
            echo '<div class="notice notice-warning"><p>' .
                 sprintf(
                     /* translators: %s: comma-separated list of invalid country codes */
                     esc_html__('Códigos inválidos ignorados (use 2 letras): %s', 'dolutech-blacklist-protect'),
                     implode(', ', array_map('esc_html', $invalid_countries))
                 ) .
                 '</p></div>';
        }

        echo '<div class="notice notice-success"><p>' . esc_html__('Países bloqueados salvos com sucesso.', 'dolutech-blacklist-protect') . '</p></div>';
    }

    // Processar envio de feedback
    if (isset($_POST['blwp_send_feedback']) && check_admin_referer('blwp_nonce_action', 'blwp_nonce_field')) {
        $feedback_message = isset($_POST['blwp_feedback_message']) ? sanitize_textarea_field(wp_unslash($_POST['blwp_feedback_message'])) : '';

        if (!empty($feedback_message)) {
            $to = 'feedback@dolutech.com';
            $subject = sprintf('[%s] Feedback do Plugin Dolutech Blacklist Protect', get_bloginfo('name'));

            $site_url = get_site_url();
            $admin_email = get_option('admin_email');
            $wordpress_version = get_bloginfo('version');
            $plugin_version = BLWP_VERSION;

            $message = sprintf(
                "Novo feedback recebido do plugin Dolutech Blacklist Protect:\n\n" .
                "Site: %s\n" .
                "Email do Administrador: %s\n" .
                "Versão do WordPress: %s\n" .
                "Versão do Plugin: %s\n" .
                "Data/Hora: %s\n\n" .
                "Mensagem:\n%s",
                $site_url,
                $admin_email,
                $wordpress_version,
                $plugin_version,
                current_time('mysql'),
                $feedback_message
            );

            $headers = ['Content-Type: text/plain; charset=UTF-8'];
            $from_name = get_bloginfo('name');
            $headers[] = 'From: ' . sanitize_text_field($from_name) . ' <' . sanitize_email($admin_email) . '>';

            $mail_sent = wp_mail($to, $subject, $message, $headers);

            if ($mail_sent) {
                echo '<div class="notice notice-success"><p>' . esc_html__('Feedback enviado com sucesso! Obrigado pela sua contribuição.', 'dolutech-blacklist-protect') . '</p></div>';
            } else {
                echo '<div class="notice notice-error"><p>' . esc_html__('Erro ao enviar feedback. Por favor, tente novamente.', 'dolutech-blacklist-protect') . '</p></div>';
            }
        } else {
            echo '<div class="notice notice-warning"><p>' . esc_html__('Por favor, escreva uma mensagem antes de enviar o feedback.', 'dolutech-blacklist-protect') . '</p></div>';
        }
    }

    $manual_blocked = blwp_get_manual_blocked_ips();
    $last_update = blwp_get_last_update();
    
    // Estatísticas das blacklists (persistidas no último fetch — sem refetch no render)
    $fetch_stats = get_option('blwp_last_fetch_stats', ['dolutech' => 0, 'third_party' => 0, 'total' => 0]);
    $third_party_lists = get_option('blwp_third_party_blacklists', []);
    $third_party_total = 0;
    foreach ($third_party_lists as $list) {
        if ($list['enabled']) {
            $third_party_total += $list['ip_count'];
        }
    }
    $auto_report = get_option('blwp_auto_report', 0);
    $blacklist_enabled = get_option('blwp_blacklist_enabled', 1);
    $whitelist = get_option('blwp_whitelist', []);
    $cidr_blocked = get_option('blwp_cidr_blocked', []);
    $ua_blocked = get_option('blwp_ua_blocked', []);
    $ua_block_enabled = get_option('blwp_ua_block_enabled', 0);
    $telegram_enabled = get_option('blwp_telegram_enabled', 0);
    $telegram_bot_token = get_option('blwp_telegram_bot_token', '');
    $telegram_chat_id = get_option('blwp_telegram_chat_id', '');
    $webhook_enabled = get_option('blwp_webhook_enabled', 0);
    $webhook_url = get_option('blwp_webhook_url', '');
    $notify_events = get_option('blwp_notify_events', []);
    $max_attempts = get_option('blwp_max_login_attempts', 3);
    $temp_block_enabled = get_option('blwp_temp_block_enabled', 0);
    $temp_block_duration = get_option('blwp_temp_block_duration', 60);
    $secret_key_enabled = get_option('blwp_secret_key_enabled', 0);
    $secret_key = get_option('blwp_secret_key', '');
    $user_block_enabled = get_option('blwp_user_block_enabled', 0);
    $blocked_usernames = get_option('blwp_blocked_usernames', []);
    $recaptcha_enabled = get_option('blwp_recaptcha_enabled', 0);
    $recaptcha_site_key = get_option('blwp_recaptcha_site_key', '');
    $recaptcha_secret_key = get_option('blwp_recaptcha_secret_key', '');
    $block_xmlrpc = get_option('blwp_block_xmlrpc', 0);
    $xmlrpc_log_attempts = get_option('blwp_xmlrpc_log_attempts', 1);
    $max_xmlrpc_attempts = get_option('blwp_max_xmlrpc_attempts', 5);
    $disable_dangerous_xmlrpc = get_option('blwp_disable_dangerous_xmlrpc', 1);
    $maxmind_enabled = get_option('blwp_maxmind_enabled', 0);
    $maxmind_account_id = get_option('blwp_maxmind_account_id', '');
    $maxmind_api_key = get_option('blwp_maxmind_api_key', '');
    $blocked_countries = get_option('blwp_blocked_countries', []);
    ?>

    <div class="wrap">
        <h1><?php esc_html_e('Dolutech Blacklist Protect', 'dolutech-blacklist-protect'); ?></h1>

        <p><strong><?php esc_html_e('Status da Blacklist:', 'dolutech-blacklist-protect'); ?></strong>
            <?php echo $blacklist_enabled ? '<span style="color:green;">' . esc_html__('Ativa', 'dolutech-blacklist-protect') . '</span>' : '<span style="color:red;">' . esc_html__('Desativada', 'dolutech-blacklist-protect') . '</span>'; ?>
        </p>
        <p><strong><?php esc_html_e('Total de IPs Bloqueados:', 'dolutech-blacklist-protect'); ?></strong> <?php echo esc_html($fetch_stats['total']); ?></p>
        
        <div style="margin: 15px 0; padding: 15px; background: #f9f9f9; border-left: 4px solid #0073aa;">
            <p style="margin: 5px 0;"><strong><?php esc_html_e('Detalhamento:', 'dolutech-blacklist-protect'); ?></strong></p>
            <p style="margin: 5px 0;">• <?php esc_html_e('Blacklist Dolutech:', 'dolutech-blacklist-protect'); ?> <?php echo esc_html($fetch_stats['dolutech']); ?> IPs</p>
            <p style="margin: 5px 0;">• <?php esc_html_e('Blacklists de Terceiros:', 'dolutech-blacklist-protect'); ?> <?php echo esc_html((string) $third_party_total); ?> IPs</p>
            <p style="margin: 5px 0;">• <?php esc_html_e('IPs Bloqueados Manualmente:', 'dolutech-blacklist-protect'); ?> <?php echo esc_html((string) count($manual_blocked)); ?></p>
        </div>
        
        <p><strong><?php esc_html_e('Última atualização:', 'dolutech-blacklist-protect'); ?></strong> <?php echo esc_html($last_update); ?></p>

        <form method="post">
            <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
            <input type="submit" name="blwp_manual_update" class="button button-secondary" value="<?php esc_attr_e('Atualizar Blacklist Manualmente', 'dolutech-blacklist-protect'); ?>" />
        </form>

        <hr>

        <h2><?php esc_html_e('Ativar/Desativar Blacklist', 'dolutech-blacklist-protect'); ?></h2>
        <form method="post">
            <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
            <label><input type="checkbox" name="blacklist_enabled" <?php checked($blacklist_enabled, 1); ?> /> <?php esc_html_e('Ativar bloqueio automático de IPs', 'dolutech-blacklist-protect'); ?></label><br><br>
            <input type="submit" name="blwp_toggle_blacklist" value="<?php esc_attr_e('Salvar Configuração', 'dolutech-blacklist-protect'); ?>" class="button button-secondary" />
        </form>

        <hr>

        <h2><?php esc_html_e('Configurações de Proteção de Login', 'dolutech-blacklist-protect'); ?></h2>
        <form method="post">
            <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
            <table class="form-table">
            <tr>
                <th scope="row">
                    <label for="blwp_max_login_attempts">
                        <?php esc_html_e('Número máximo de tentativas de login', 'dolutech-blacklist-protect'); ?>
                    </label>
                </th>
                <td>
                    <input type="number" id="blwp_max_login_attempts" name="blwp_max_login_attempts" 
                           value="<?php echo esc_attr($max_attempts); ?>" min="1" max="10" />
                    <p class="description">
                        <?php esc_html_e('Número de tentativas de login falhadas antes de bloquear o IP (padrão: 3)', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row">
                    <?php esc_html_e('Tipo de Bloqueio', 'dolutech-blacklist-protect'); ?>
                </th>
                <td>
                    <label>
                        <input type="checkbox" name="blwp_temp_block_enabled" id="blwp_temp_block_enabled" 
                               <?php checked($temp_block_enabled, 1); ?> />
                        <?php esc_html_e('Ativar bloqueio temporário', 'dolutech-blacklist-protect'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html_e('Quando ativado, os IPs serão bloqueados temporariamente. Quando desativado, o bloqueio será permanente.', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            <tr id="temp_block_duration_row" style="<?php echo $temp_block_enabled ? '' : 'display:none;'; ?>">
                <th scope="row">
                    <label for="blwp_temp_block_duration">
                        <?php esc_html_e('Duração do bloqueio temporário', 'dolutech-blacklist-protect'); ?>
                    </label>
                </th>
                <td>
                    <input type="number" id="blwp_temp_block_duration" name="blwp_temp_block_duration" 
                           value="<?php echo esc_attr($temp_block_duration); ?>" min="1" max="10080" />
                    <span><?php esc_html_e('minutos', 'dolutech-blacklist-protect'); ?></span>
                    <p class="description">
                        <?php esc_html_e('Tempo que o IP ficará bloqueado em minutos (padrão: 60 minutos)', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row">
                    <?php esc_html_e('Chave Secreta para Desbloqueio', 'dolutech-blacklist-protect'); ?>
                </th>
                <td>
                    <label>
                        <input type="checkbox" name="blwp_secret_key_enabled" id="blwp_secret_key_enabled" 
                               <?php checked($secret_key_enabled, 1); ?> />
                        <?php esc_html_e('Ativar chave secreta', 'dolutech-blacklist-protect'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html_e('Quando ativado, será necessário inserir uma chave secreta para desbloquear IPs.', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            <tr id="secret_key_row" style="<?php echo $secret_key_enabled ? '' : 'display:none;'; ?>">
                <th scope="row">
                    <label for="blwp_secret_key">
                        <?php esc_html_e('Chave Secreta', 'dolutech-blacklist-protect'); ?>
                    </label>
                </th>
                <td>
                    <div style="position: relative; display: inline-block; width: 100%; max-width: 400px;">
                        <input type="password" id="blwp_secret_key" name="blwp_secret_key" 
                               value="" 
                               placeholder="<?php esc_attr_e('Deixe em branco para manter a chave atual', 'dolutech-blacklist-protect'); ?>" 
                               style="width: 100%; padding-right: 45px;" />
                        <button type="button" id="toggle_secret_key" 
                                style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); 
                                       background: none; border: none; cursor: pointer; padding: 5px; 
                                       color: #666; font-size: 16px;" 
                                title="<?php esc_attr_e('Mostrar/Ocultar chave', 'dolutech-blacklist-protect'); ?>">
                            👁️
                        </button>
                    </div>
                    <p class="description">
                        <?php esc_html_e('Esta chave será solicitada ao tentar desbloquear um IP pelo link de e-mail.', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            </table>
            <p>
                <input type="submit" name="blwp_save_login_settings" value="<?php esc_attr_e('Salvar Configurações de Login', 'dolutech-blacklist-protect'); ?>" class="button button-primary" />
            </p>
        </form>
        <script>
            document.getElementById('blwp_temp_block_enabled').addEventListener('change', function() {
                var durationRow = document.getElementById('temp_block_duration_row');
                if (this.checked) {
                    durationRow.style.display = '';
                } else {
                    durationRow.style.display = 'none';
                }
            });
            
            document.getElementById('blwp_secret_key_enabled').addEventListener('change', function() {
                var secretRow = document.getElementById('secret_key_row');
                if (this.checked) {
                    secretRow.style.display = '';
                } else {
                    secretRow.style.display = 'none';
                }
            });
            
            // Toggle para mostrar/ocultar chave secreta
            document.addEventListener('DOMContentLoaded', function() {
                var toggleBtn = document.getElementById('toggle_secret_key');
                var secretInput = document.getElementById('blwp_secret_key');
                
                if (toggleBtn && secretInput) {
                    toggleBtn.addEventListener('click', function() {
                        if (secretInput.type === 'password') {
                            secretInput.type = 'text';
                            toggleBtn.innerHTML = '🙈';
                            toggleBtn.title = '<?php esc_attr_e('Ocultar chave', 'dolutech-blacklist-protect'); ?>';
                        } else {
                            secretInput.type = 'password';
                            toggleBtn.innerHTML = '👁️';
                            toggleBtn.title = '<?php esc_attr_e('Mostrar chave', 'dolutech-blacklist-protect'); ?>';
                        }
                    });
                }
            });
        </script>

        <hr>

        <h2><?php esc_html_e('Bloqueio por Usuários Específicos', 'dolutech-blacklist-protect'); ?></h2>
        <p><?php esc_html_e('Configure usuários inexistentes (como "admin", "root", "administrator") que resultarão em bloqueio imediato do IP ao serem utilizados em tentativas de login.', 'dolutech-blacklist-protect'); ?></p>
        <div class="notice notice-info inline">
            <p><?php esc_html_e('⚠️ Importante: Apenas usuários que NÃO existem no sistema serão bloqueados. Usuários existentes são ignorados para evitar bloqueios acidentais de usuários legítimos.', 'dolutech-blacklist-protect'); ?></p>
        </div>
        
        <form method="post">
            <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
            <table class="form-table">
            <tr>
                <th scope="row">
                    <?php esc_html_e('Ativar Bloqueio por Usuário', 'dolutech-blacklist-protect'); ?>
                </th>
                <td>
                    <label>
                        <input type="checkbox" name="blwp_user_block_enabled" id="blwp_user_block_enabled" 
                               <?php checked($user_block_enabled, 1); ?> />
                        <?php esc_html_e('Bloquear IPs ao tentar fazer login com usuários específicos', 'dolutech-blacklist-protect'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html_e('Quando ativado, qualquer tentativa de login com os usuários listados abaixo resultará em bloqueio imediato do IP.', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            <tr id="blocked_usernames_row" style="<?php echo $user_block_enabled ? '' : 'display:none;'; ?>">
                <th scope="row">
                    <label for="blwp_blocked_usernames">
                        <?php esc_html_e('Usuários Bloqueados', 'dolutech-blacklist-protect'); ?>
                    </label>
                </th>
                <td>
                    <textarea id="blwp_blocked_usernames" name="blwp_blocked_usernames" 
                              rows="8" cols="50" style="width: 100%; max-width: 400px;"><?php echo esc_textarea(implode("\n", $blocked_usernames)); ?></textarea>
                    <p class="description">
                        <?php esc_html_e('Digite um nome de usuário por linha. Apenas usuários que NÃO existem no sistema serão bloqueados (ex: admin, root, administrator).', 'dolutech-blacklist-protect'); ?>
                    </p>
                    <p class="description">
                        <strong><?php esc_html_e('Exemplos:', 'dolutech-blacklist-protect'); ?></strong><br>
                        admin<br>
                        root<br>
                        administrator
                    </p>
                    <?php if (!empty($blocked_usernames)) : ?>
                        <div style="margin-top: 15px; padding: 10px; background: #f0f8ff; border-left: 4px solid #0073aa;">
                            <strong><?php esc_html_e('Usuários ativos na lista:', 'dolutech-blacklist-protect'); ?></strong>
                            <?php echo esc_html((string) count($blocked_usernames)); ?>
                            <ul style="margin: 5px 0 0 20px;">
                                <?php foreach ($blocked_usernames as $username) : ?>
                                    <li><?php echo esc_html($username); ?></li>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                    <?php endif; ?>
                </td>
            </tr>
            </table>
            <p>
                <input type="submit" name="blwp_save_user_block_settings" 
                       value="<?php esc_attr_e('Salvar Configurações de Bloqueio', 'dolutech-blacklist-protect'); ?>" 
                       class="button button-primary" />
            </p>
        </form>
        
        <script>
            document.getElementById('blwp_user_block_enabled').addEventListener('change', function() {
                var usernamesRow = document.getElementById('blocked_usernames_row');
                if (this.checked) {
                    usernamesRow.style.display = '';
                } else {
                    usernamesRow.style.display = 'none';
                }
            });
        </script>

        <hr>

        <h2><?php esc_html_e('Configurações do Google reCAPTCHA v2', 'dolutech-blacklist-protect'); ?></h2>
        <p><?php esc_html_e('Configure o reCAPTCHA v2 para adicionar uma camada extra de segurança no processo de desbloqueio de IPs.', 'dolutech-blacklist-protect'); ?></p>
        
        <form method="post">
            <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
            <table class="form-table">
            <tr>
                <th scope="row">
                    <?php esc_html_e('Ativar reCAPTCHA', 'dolutech-blacklist-protect'); ?>
                </th>
                <td>
                    <label>
                        <input type="checkbox" name="blwp_recaptcha_enabled" id="blwp_recaptcha_enabled" 
                               <?php checked($recaptcha_enabled, 1); ?> />
                        <?php esc_html_e('Ativar Google reCAPTCHA v2', 'dolutech-blacklist-protect'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html_e('Quando ativado, o reCAPTCHA será exibido nos formulários de desbloqueio de IP.', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            <tbody id="recaptcha_settings" style="<?php echo $recaptcha_enabled ? '' : 'display:none;'; ?>">
            <tr>
                <th scope="row">
                    <label for="blwp_recaptcha_site_key">
                        <?php esc_html_e('Site Key', 'dolutech-blacklist-protect'); ?>
                    </label>
                </th>
                <td>
                    <input type="text" id="blwp_recaptcha_site_key" name="blwp_recaptcha_site_key" 
                           value="<?php echo esc_attr($recaptcha_site_key); ?>" 
                           placeholder="6Lc..." style="width: 400px;" />
                    <p class="description">
                        <?php esc_html_e('Chave pública do site (Site Key) fornecida pelo Google reCAPTCHA.', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row">
                    <label for="blwp_recaptcha_secret_key">
                        <?php esc_html_e('Secret Key', 'dolutech-blacklist-protect'); ?>
                    </label>
                </th>
                <td>
                    <input type="password" id="blwp_recaptcha_secret_key" name="blwp_recaptcha_secret_key" 
                           value="" 
                           placeholder="<?php esc_attr_e('Deixe em branco para manter a chave atual', 'dolutech-blacklist-protect'); ?>" style="width: 400px;" />
                    <p class="description">
                        <?php esc_html_e('Chave secreta (Secret Key) fornecida pelo Google reCAPTCHA.', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div style="background: #f0f8ff; padding: 15px; border-left: 4px solid #0073aa;">
                        <strong><?php esc_html_e('Como obter as chaves:', 'dolutech-blacklist-protect'); ?></strong>
                        <ol style="margin-top: 10px;">
                            <li><?php echo wp_kses(__('Acesse <a href="https://www.google.com/recaptcha/admin" target="_blank">Google reCAPTCHA Admin</a>', 'dolutech-blacklist-protect'), ['a' => ['href' => [], 'target' => []]]); ?></li>
                            <li><?php esc_html_e('Escolha reCAPTCHA v2 → "Não sou um robô"', 'dolutech-blacklist-protect'); ?></li>
                            <li><?php esc_html_e('Adicione seu domínio', 'dolutech-blacklist-protect'); ?></li>
                            <li><?php esc_html_e('Copie as chaves fornecidas', 'dolutech-blacklist-protect'); ?></li>
                        </ol>
                    </div>
                </td>
            </tr>
            </tbody>
            </table>
            <p>
                <input type="submit" name="blwp_save_recaptcha_settings" 
                       value="<?php esc_attr_e('Salvar Configurações reCAPTCHA', 'dolutech-blacklist-protect'); ?>" 
                       class="button button-primary" />
            </p>
        </form>
        
        <script>
            document.getElementById('blwp_recaptcha_enabled').addEventListener('change', function() {
                var settings = document.getElementById('recaptcha_settings');
                if (this.checked) {
                    settings.style.display = '';
                } else {
                    settings.style.display = 'none';
                }
            });
        </script>

        <hr>

        <h2><?php esc_html_e('Proteção XML-RPC', 'dolutech-blacklist-protect'); ?></h2>
        <form method="post">
            <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
            <table class="form-table">
            <tr>
                <th scope="row">
                    <?php esc_html_e('Modo de Proteção XML-RPC', 'dolutech-blacklist-protect'); ?>
                </th>
                <td>
                    <label>
                        <input type="checkbox" name="blwp_block_xmlrpc" id="blwp_block_xmlrpc" <?php checked($block_xmlrpc, 1); ?> />
                        <?php esc_html_e('Bloquear COMPLETAMENTE o acesso ao xmlrpc.php', 'dolutech-blacklist-protect'); ?>
                    </label>
                    <p class="description">
                        <strong><?php esc_html_e('⚠️ Atenção:', 'dolutech-blacklist-protect'); ?></strong>
                        <?php esc_html_e('Quando ativado, bloqueia TOTALMENTE o XML-RPC. As opções abaixo só funcionam quando este bloqueio completo está DESATIVADO.', 'dolutech-blacklist-protect'); ?>
                    </p>
                    <p class="description">
                        <?php esc_html_e('Use esta opção se você não precisa de XML-RPC (recomendado para a maioria dos sites).', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            </table>
            
            <div id="xmlrpc_partial_options" style="<?php echo $block_xmlrpc ? 'opacity: 0.5; pointer-events: none;' : ''; ?>">
                <h3><?php esc_html_e('Opções de Proteção Parcial', 'dolutech-blacklist-protect'); ?></h3>
                <p style="background: #f0f8ff; padding: 10px; border-left: 4px solid #0073aa;">
                    <?php esc_html_e('💡 Estas opções só funcionam quando o bloqueio completo está DESATIVADO. Use-as se você precisa manter o XML-RPC ativo mas quer proteção adicional.', 'dolutech-blacklist-protect'); ?>
                </p>
                
                <table class="form-table">
                <tr>
                    <th scope="row">
                        <?php esc_html_e('Registrar tentativas', 'dolutech-blacklist-protect'); ?>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" name="blwp_xmlrpc_log_attempts" <?php checked($xmlrpc_log_attempts, 1); ?> 
                                   <?php echo $block_xmlrpc ? 'disabled' : ''; ?> />
                            <?php esc_html_e('Registrar e bloquear IPs após múltiplas tentativas', 'dolutech-blacklist-protect'); ?>
                        </label>
                        <p class="description">
                            <?php esc_html_e('Monitora tentativas de acesso ao XML-RPC e bloqueia IPs suspeitos.', 'dolutech-blacklist-protect'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="blwp_max_xmlrpc_attempts">
                            <?php esc_html_e('Máximo de tentativas', 'dolutech-blacklist-protect'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="number" id="blwp_max_xmlrpc_attempts" name="blwp_max_xmlrpc_attempts" 
                               value="<?php echo esc_attr($max_xmlrpc_attempts); ?>" min="1" max="20" 
                               <?php echo $block_xmlrpc ? 'disabled' : ''; ?> />
                        <p class="description">
                            <?php esc_html_e('Número de tentativas antes de bloquear o IP (padrão: 5)', 'dolutech-blacklist-protect'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <?php esc_html_e('Métodos perigosos', 'dolutech-blacklist-protect'); ?>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" name="blwp_disable_dangerous_xmlrpc" <?php checked($disable_dangerous_xmlrpc, 1); ?> 
                                   <?php echo $block_xmlrpc ? 'disabled' : ''; ?> />
                            <?php esc_html_e('Desabilitar métodos XML-RPC perigosos', 'dolutech-blacklist-protect'); ?>
                        </label>
                        <p class="description">
                            <?php esc_html_e('Remove métodos como system.multicall, wp.getUsersBlogs que são frequentemente usados em ataques.', 'dolutech-blacklist-protect'); ?>
                        </p>
                        <p class="description">
                            <?php esc_html_e('Mantém apenas métodos essenciais como pingback (se necessário).', 'dolutech-blacklist-protect'); ?>
                        </p>
                    </td>
                </tr>
                </table>
            </div>
            
            <p>
                <input type="submit" name="blwp_save_xmlrpc_settings" value="<?php esc_attr_e('Salvar Configurações XML-RPC', 'dolutech-blacklist-protect'); ?>" class="button button-primary" />
            </p>
        </form>
        
        <script>
            document.getElementById('blwp_block_xmlrpc').addEventListener('change', function() {
                var partialOptions = document.getElementById('xmlrpc_partial_options');
                var inputs = partialOptions.querySelectorAll('input');
                
                if (this.checked) {
                    partialOptions.style.opacity = '0.5';
                    partialOptions.style.pointerEvents = 'none';
                    inputs.forEach(function(input) {
                        input.disabled = true;
                    });
                } else {
                    partialOptions.style.opacity = '1';
                    partialOptions.style.pointerEvents = '';
                    inputs.forEach(function(input) {
                        input.disabled = false;
                    });
                }
            });
        </script>

        <hr>

        <h2><?php esc_html_e('Bloqueio por Geolocalização (MaxMind GeoIP2)', 'dolutech-blacklist-protect'); ?></h2>
        <p><?php esc_html_e('Configure a integração com MaxMind GeoIP2 para bloquear acessos de países específicos.', 'dolutech-blacklist-protect'); ?></p>

        <form method="post">
            <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
            <table class="form-table">
            <tr>
                <th scope="row">
                    <?php esc_html_e('Ativar MaxMind GeoIP2', 'dolutech-blacklist-protect'); ?>
                </th>
                <td>
                    <label>
                        <input type="checkbox" name="blwp_maxmind_enabled" id="blwp_maxmind_enabled"
                               <?php checked($maxmind_enabled, 1); ?> />
                        <?php esc_html_e('Ativar bloqueio por geolocalização', 'dolutech-blacklist-protect'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html_e('Quando ativado, IPs de países bloqueados não poderão acessar o site.', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            <tbody id="maxmind_credentials" style="<?php echo $maxmind_enabled ? '' : 'display:none;'; ?>">
            <tr>
                <th scope="row">
                    <label for="blwp_maxmind_account_id">
                        <?php esc_html_e('Account ID', 'dolutech-blacklist-protect'); ?>
                    </label>
                </th>
                <td>
                    <input type="text" id="blwp_maxmind_account_id" name="blwp_maxmind_account_id"
                           value="<?php echo esc_attr($maxmind_account_id); ?>"
                           placeholder="123456" style="width: 400px;" />
                    <p class="description">
                        <?php esc_html_e('Account ID fornecido pela MaxMind.', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row">
                    <label for="blwp_maxmind_api_key">
                        <?php esc_html_e('License Key', 'dolutech-blacklist-protect'); ?>
                    </label>
                </th>
                <td>
                    <div style="position: relative; display: inline-block; width: 100%; max-width: 400px;">
                        <input type="password" id="blwp_maxmind_api_key" name="blwp_maxmind_api_key"
                               value=""
                               placeholder="<?php esc_attr_e('Deixe em branco para manter a chave atual', 'dolutech-blacklist-protect'); ?>"
                               style="width: 100%; padding-right: 45px;" />
                        <button type="button" id="toggle_maxmind_key"
                                style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%);
                                       background: none; border: none; cursor: pointer; padding: 5px;
                                       color: #666; font-size: 16px;"
                                title="<?php esc_attr_e('Mostrar/Ocultar chave', 'dolutech-blacklist-protect'); ?>">
                            👁️
                        </button>
                    </div>
                    <p class="description">
                        <?php esc_html_e('License Key fornecida pela MaxMind (será validada ao salvar).', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div style="background: #f0f8ff; padding: 15px; border-left: 4px solid #0073aa;">
                        <strong><?php esc_html_e('Como obter as credenciais:', 'dolutech-blacklist-protect'); ?></strong>
                        <ol style="margin-top: 10px;">
                            <li><?php echo wp_kses(__('Acesse <a href="https://www.maxmind.com/en/geolite2/signup" target="_blank">MaxMind</a> e crie uma conta', 'dolutech-blacklist-protect'), ['a' => ['href' => [], 'target' => []]]); ?></li>
                            <li><?php esc_html_e('Vá em "Manage License Keys" e crie uma nova License Key', 'dolutech-blacklist-protect'); ?></li>
                            <li><?php esc_html_e('Copie o Account ID e a License Key', 'dolutech-blacklist-protect'); ?></li>
                            <li><?php esc_html_e('Cole aqui e clique em Salvar para validar', 'dolutech-blacklist-protect'); ?></li>
                        </ol>
                    </div>
                </td>
            </tr>
            </tbody>
            </table>
            <p>
                <input type="submit" name="blwp_save_maxmind_settings"
                       value="<?php esc_attr_e('Salvar Configurações MaxMind', 'dolutech-blacklist-protect'); ?>"
                       class="button button-primary" />
            </p>
        </form>

        <script>
            document.getElementById('blwp_maxmind_enabled').addEventListener('change', function() {
                var credentials = document.getElementById('maxmind_credentials');
                if (this.checked) {
                    credentials.style.display = '';
                } else {
                    credentials.style.display = 'none';
                }
            });

            document.addEventListener('DOMContentLoaded', function() {
                var toggleBtn = document.getElementById('toggle_maxmind_key');
                var keyInput = document.getElementById('blwp_maxmind_api_key');

                if (toggleBtn && keyInput) {
                    toggleBtn.addEventListener('click', function() {
                        if (keyInput.type === 'password') {
                            keyInput.type = 'text';
                            toggleBtn.textContent = '🙈';
                            toggleBtn.title = '<?php esc_attr_e('Ocultar chave', 'dolutech-blacklist-protect'); ?>';
                        } else {
                            keyInput.type = 'password';
                            toggleBtn.textContent = '👁️';
                            toggleBtn.title = '<?php esc_attr_e('Mostrar chave', 'dolutech-blacklist-protect'); ?>';
                        }
                    });
                }
            });
        </script>

        <?php if ($maxmind_enabled && !empty($maxmind_account_id) && !empty($maxmind_api_key)) : ?>
            <hr>

            <h2><?php esc_html_e('Países Bloqueados', 'dolutech-blacklist-protect'); ?></h2>
            <p><?php esc_html_e('Digite os códigos ISO de 2 letras dos países que deseja bloquear (um por linha).', 'dolutech-blacklist-protect'); ?></p>

            <form method="post">
                <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
                <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="blwp_blocked_countries">
                            <?php esc_html_e('Códigos de Países', 'dolutech-blacklist-protect'); ?>
                        </label>
                    </th>
                    <td>
                        <textarea id="blwp_blocked_countries" name="blwp_blocked_countries"
                                  rows="10" cols="50" style="width: 100%; max-width: 400px;"><?php echo esc_textarea(implode("\n", $blocked_countries)); ?></textarea>
                        <p class="description">
                            <?php esc_html_e('Use códigos ISO 3166-1 alpha-2 (2 letras maiúsculas). Exemplos: CN (China), RU (Rússia), BR (Brasil)', 'dolutech-blacklist-protect'); ?>
                        </p>

                        <div style="margin-top: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107;">
                            <strong><?php esc_html_e('Países comumente bloqueados:', 'dolutech-blacklist-protect'); ?></strong>
                            <div style="margin-top: 10px; display: grid; grid-template-columns: repeat(2, 1fr); gap: 5px;">
                                <?php
                                $common = blwp_get_common_blocked_countries();
                                foreach ($common as $code => $name) {
                                    echo '<span style="font-family: monospace;"><strong>' . esc_html($code) . '</strong> - ' . esc_html($name) . '</span>';
                                }
                                ?>
                            </div>
                        </div>

                        <?php if (!empty($blocked_countries)) : ?>
                            <div style="margin-top: 15px; padding: 10px; background: #ffebee; border-left: 4px solid #dc3545;">
                                <strong><?php esc_html_e('⚠️ Atenção:', 'dolutech-blacklist-protect'); ?></strong>
                                <?php
                                echo esc_html(
                                    sprintf(
                                        /* translators: %d: number of blocked countries */
                                        _n('%d país está bloqueado', '%d países estão bloqueados', count($blocked_countries), 'dolutech-blacklist-protect'),
                                        count($blocked_countries)
                                    )
                                );
                                ?>
                                <ul style="margin: 5px 0 0 20px;">
                                    <?php foreach ($blocked_countries as $country) : ?>
                                        <li><?php echo esc_html($country); ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        <?php endif; ?>
                    </td>
                </tr>
                </table>
                <p>
                    <input type="submit" name="blwp_save_blocked_countries"
                           value="<?php esc_attr_e('Salvar Países Bloqueados', 'dolutech-blacklist-protect'); ?>"
                           class="button button-primary" />
                </p>
            </form>
        <?php endif; ?>

        <hr>

        <h2><?php esc_html_e('Denunciar IP Manualmente', 'dolutech-blacklist-protect'); ?></h2>
        <form method="post">
            <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
            <input type="text" name="blwp_ip" placeholder="IP" required />
            <input type="text" name="blwp_reason" placeholder="Motivo" required />
            <input type="submit" name="blwp_manual_report" value="<?php esc_attr_e('Denunciar IP', 'dolutech-blacklist-protect'); ?>" class="button button-primary" />
        </form>

        <hr>

        <h2><?php esc_html_e('Relato Automático', 'dolutech-blacklist-protect'); ?></h2>
        <form method="post">
            <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
            <label><input type="checkbox" name="auto_report" <?php checked($auto_report, 1); ?> /> <?php esc_html_e('Ativar envio automático de IPs bloqueados', 'dolutech-blacklist-protect'); ?></label><br><br>
            <input type="submit" name="blwp_toggle_auto_report" value="<?php esc_attr_e('Salvar Configuração', 'dolutech-blacklist-protect'); ?>" class="button button-secondary" />
        </form>

        <hr>

        <h2><?php esc_html_e('Whitelist (IP fixo ou domínio DDNS)', 'dolutech-blacklist-protect'); ?></h2>
        <form method="post">
            <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
            <textarea name="blwp_whitelist" rows="6" cols="60"><?php echo esc_textarea(implode("\n", $whitelist)); ?></textarea><br>
            <small><?php esc_html_e('Um IP ou domínio por linha.', 'dolutech-blacklist-protect'); ?></small><br><br>
            <input type="submit" name="blwp_save_whitelist" value="<?php esc_attr_e('Salvar Whitelist', 'dolutech-blacklist-protect'); ?>" class="button button-secondary" />
        </form>

        <hr>

        <h2><?php esc_html_e('Bloqueio Manual de IP', 'dolutech-blacklist-protect'); ?></h2>
        <form method="post">
            <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
            <input type="text" name="manual_ip" placeholder="IP para bloquear" />
            <input type="submit" name="blwp_add_manual_block" class="button" value="<?php esc_attr_e('Adicionar IP Manual', 'dolutech-blacklist-protect'); ?>" />
        </form>

        <?php if (!empty($manual_blocked)) : ?>
            <h3><?php esc_html_e('IPs Manuais Bloqueados', 'dolutech-blacklist-protect'); ?></h3>
            <ul>
                <?php foreach ($manual_blocked as $ip) : ?>
                    <li>
                        <?php echo esc_html($ip); ?>
                        <form method="post" style="display:inline;">
                            <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
                            <input type="hidden" name="remove_ip" value="<?php echo esc_attr($ip); ?>" />
                            <input type="submit" name="blwp_remove_manual_block" class="button-link-delete" value="<?php esc_attr_e('Remover', 'dolutech-blacklist-protect'); ?>" />
                        </form>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>

        <hr>

        <h2><?php esc_html_e('Bloqueio por Faixa CIDR e User-Agent', 'dolutech-blacklist-protect'); ?></h2>
        <p><?php esc_html_e('Bloqueie faixas inteiras de IPs (CIDR) e user-agents suspeitos. Suporta IPv4 e IPv6.', 'dolutech-blacklist-protect'); ?></p>
        <form method="post">
            <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
            <table class="form-table">
            <tr>
                <th scope="row">
                    <label for="blwp_cidr_blocked">
                        <?php esc_html_e('Faixas CIDR bloqueadas', 'dolutech-blacklist-protect'); ?>
                    </label>
                </th>
                <td>
                    <textarea id="blwp_cidr_blocked" name="blwp_cidr_blocked"
                              rows="6" cols="50" style="width: 100%; max-width: 400px;"><?php echo esc_textarea(implode("\n", $cidr_blocked)); ?></textarea>
                    <p class="description">
                        <?php esc_html_e('Um CIDR por linha. Exemplos: 203.0.113.0/24 (IPv4), 2001:db8::/32 (IPv6).', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row">
                    <?php esc_html_e('Bloqueio por User-Agent', 'dolutech-blacklist-protect'); ?>
                </th>
                <td>
                    <label>
                        <input type="checkbox" name="blwp_ua_block_enabled" id="blwp_ua_block_enabled" <?php checked($ua_block_enabled, 1); ?> />
                        <?php esc_html_e('Ativar bloqueio por user-agent', 'dolutech-blacklist-protect'); ?>
                    </label>
                </td>
            </tr>
            <tr id="ua_blocked_row" style="<?php echo $ua_block_enabled ? '' : 'display:none;'; ?>">
                <th scope="row">
                    <label for="blwp_ua_blocked">
                        <?php esc_html_e('User-Agents bloqueados', 'dolutech-blacklist-protect'); ?>
                    </label>
                </th>
                <td>
                    <textarea id="blwp_ua_blocked" name="blwp_ua_blocked"
                              rows="6" cols="50" style="width: 100%; max-width: 400px;"><?php echo esc_textarea(implode("\n", $ua_blocked)); ?></textarea>
                    <p class="description">
                        <?php esc_html_e('Um padrão por linha (substring, sem diferenciar maiúsculas). Ex.: sqlmap, nikto, python-requests.', 'dolutech-blacklist-protect'); ?>
                    </p>
                    <p class="description" style="color: #b36b00;">
                        <?php esc_html_e('⚠️ User-agent pode ser falsificado — use como camada extra, não como única proteção.', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            </table>
            <p>
                <input type="submit" name="blwp_save_cidr_ua_settings" value="<?php esc_attr_e('Salvar Configurações CIDR/UA', 'dolutech-blacklist-protect'); ?>" class="button button-primary" />
            </p>
        </form>
        <script>
            document.getElementById('blwp_ua_block_enabled').addEventListener('change', function() {
                var row = document.getElementById('ua_blocked_row');
                if (this.checked) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        </script>

        <hr>

        <h2><?php esc_html_e('Blacklists de Terceiros', 'dolutech-blacklist-protect'); ?></h2>
        <p><?php esc_html_e('Adicione URLs de blacklists externas (arquivos .txt) que serão atualizadas automaticamente junto com a blacklist principal.', 'dolutech-blacklist-protect'); ?></p>
        
        <form method="post" style="background: #f9f9f9; padding: 20px; border: 1px solid #ddd; border-radius: 4px; margin-bottom: 20px;">
            <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="third_party_name"><?php esc_html_e('Nome da Lista', 'dolutech-blacklist-protect'); ?></label>
                    </th>
                    <td>
                        <input type="text" id="third_party_name" name="third_party_name" 
                               placeholder="<?php esc_attr_e('Ex: SpamHaus, AbuseIPDB', 'dolutech-blacklist-protect'); ?>" 
                               style="width: 300px;" />
                        <p class="description"><?php esc_html_e('Opcional: Nome descritivo para identificar a lista', 'dolutech-blacklist-protect'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="third_party_url"><?php esc_html_e('URL da Blacklist', 'dolutech-blacklist-protect'); ?></label>
                    </th>
                    <td>
                        <input type="url" id="third_party_url" name="third_party_url" 
                               placeholder="https://exemplo.com/blacklist.txt" 
                               required style="width: 400px;" />
                        <p class="description"><?php esc_html_e('URL completa do arquivo .txt contendo os IPs (um por linha)', 'dolutech-blacklist-protect'); ?></p>
                    </td>
                </tr>
            </table>
            <p>
                <input type="submit" name="blwp_add_third_party" 
                       value="<?php esc_attr_e('Adicionar Blacklist', 'dolutech-blacklist-protect'); ?>" 
                       class="button button-primary" />
            </p>
        </form>

        <?php
        $third_party_lists = get_option('blwp_third_party_blacklists', []);
        
        if (!empty($third_party_lists)) : ?>
            <h3><?php esc_html_e('Blacklists Configuradas', 'dolutech-blacklist-protect'); ?></h3>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php esc_html_e('Nome', 'dolutech-blacklist-protect'); ?></th>
                        <th><?php esc_html_e('URL', 'dolutech-blacklist-protect'); ?></th>
                        <th><?php esc_html_e('Status', 'dolutech-blacklist-protect'); ?></th>
                        <th><?php esc_html_e('IPs', 'dolutech-blacklist-protect'); ?></th>
                        <th><?php esc_html_e('Última Atualização', 'dolutech-blacklist-protect'); ?></th>
                        <th><?php esc_html_e('Ações', 'dolutech-blacklist-protect'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($third_party_lists as $list_id => $list) : ?>
                        <tr>
                            <td><strong><?php echo esc_html($list['name']); ?></strong></td>
                            <td>
                                <a href="<?php echo esc_url($list['url']); ?>" target="_blank" rel="noopener">
                                    <?php echo esc_html(substr($list['url'], 0, 50)); ?>
                                    <?php echo strlen($list['url']) > 50 ? '...' : ''; ?>
                                </a>
                            </td>
                            <td>
                                <?php if ($list['enabled']) : ?>
                                    <?php if ($list['status'] === 'active') : ?>
                                        <span style="color: green;">● <?php esc_html_e('Ativa', 'dolutech-blacklist-protect'); ?></span>
                                    <?php elseif ($list['status'] === 'error') : ?>
                                        <span style="color: red;">● <?php esc_html_e('Erro', 'dolutech-blacklist-protect'); ?></span>
                                    <?php else : ?>
                                        <span style="color: orange;">● <?php esc_html_e('Pendente', 'dolutech-blacklist-protect'); ?></span>
                                    <?php endif; ?>
                                <?php else : ?>
                                    <span style="color: gray;">● <?php esc_html_e('Desativada', 'dolutech-blacklist-protect'); ?></span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo esc_html($list['ip_count']); ?></td>
                            <td>
                                <?php 
                                if ($list['last_update']) {
                                    echo esc_html(wp_date('d/m/Y H:i', strtotime($list['last_update'])));
                                } else {
                                    esc_html_e('Nunca', 'dolutech-blacklist-protect');
                                }
                                ?>
                            </td>
                            <td>
                                <form method="post" style="display: inline;">
                                    <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
                                    <input type="hidden" name="list_id" value="<?php echo esc_attr($list_id); ?>" />
                                    <input type="submit" name="blwp_toggle_third_party" 
                                           value="<?php echo $list['enabled'] ? esc_attr__('Desativar', 'dolutech-blacklist-protect') : esc_attr__('Ativar', 'dolutech-blacklist-protect'); ?>" 
                                           class="button button-small" />
                                </form>
                                <form method="post" style="display: inline;">
                                    <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
                                    <input type="hidden" name="list_id" value="<?php echo esc_attr($list_id); ?>" />
                                    <input type="submit" name="blwp_remove_third_party" 
                                           value="<?php esc_attr_e('Remover', 'dolutech-blacklist-protect'); ?>" 
                                           class="button button-small button-link-delete" 
                                           onclick="return confirm('<?php esc_attr_e('Tem certeza que deseja remover esta blacklist?', 'dolutech-blacklist-protect'); ?>');" />
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            
            <div style="margin-top: 10px; padding: 10px; background: #f0f8ff; border-left: 4px solid #0073aa;">
                <strong><?php esc_html_e('Informação:', 'dolutech-blacklist-protect'); ?></strong>
                <?php esc_html_e('As blacklists de terceiros são atualizadas automaticamente duas vezes ao dia junto com a blacklist principal da Dolutech.', 'dolutech-blacklist-protect'); ?>
            </div>
        <?php else : ?>
            <p style="padding: 20px; background: #f9f9f9; border-left: 4px solid #0073aa;">
                <?php esc_html_e('Nenhuma blacklist de terceiros configurada. Adicione URLs de blacklists externas para aumentar a proteção do seu site.', 'dolutech-blacklist-protect'); ?>
            </p>
        <?php endif; ?>

        <hr>

        <h2><?php esc_html_e('IPs com Bloqueio Temporário', 'dolutech-blacklist-protect'); ?></h2>
        <?php
        $temp_blocks = get_option('blwp_temp_blocked_ips', []);
        $active_temp_blocks = array_filter($temp_blocks, function($expiration) {
            return $expiration > time();
        });
        
        if (!empty($active_temp_blocks)) : ?>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php esc_html_e('IP', 'dolutech-blacklist-protect'); ?></th>
                        <th><?php esc_html_e('Expira em', 'dolutech-blacklist-protect'); ?></th>
                        <th><?php esc_html_e('Tempo restante', 'dolutech-blacklist-protect'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($active_temp_blocks as $ip => $expiration) : 
                        $remaining = $expiration - time();
                        $minutes = ceil($remaining / 60);
                    ?>
                        <tr>
                            <td><?php echo esc_html($ip); ?></td>
                            <td><?php echo esc_html(wp_date('d/m/Y H:i:s', $expiration)); ?></td>
                            <td>
                                <?php 
                                if ($minutes >= 60) {
                                    $hours = floor($minutes / 60);
                                    $mins = $minutes % 60;
                                    echo esc_html(sprintf('%d h %d min', $hours, $mins));
                                } else {
                                    echo esc_html(sprintf(
                                        /* translators: %d: number of minutes remaining */
                                        _n('%d minuto', '%d minutos', (int) $minutes, 'dolutech-blacklist-protect'),
                                        (int) $minutes
                                    ));
                                }
                                ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php else : ?>
            <p><?php esc_html_e('Nenhum IP com bloqueio temporário ativo.', 'dolutech-blacklist-protect'); ?></p>
        <?php endif; ?>

        <hr>

        <h2><?php esc_html_e('Tokens de Desbloqueio Pendentes', 'dolutech-blacklist-protect'); ?></h2>
        <?php
        $tokens = get_option('blwp_unblock_tokens', []);
        $active_tokens = array_filter($tokens, function($token) {
            return !$token['used'] && $token['expiration'] > time();
        });
        
        if (!empty($active_tokens)) : ?>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php esc_html_e('IP', 'dolutech-blacklist-protect'); ?></th>
                        <th><?php esc_html_e('Expira em', 'dolutech-blacklist-protect'); ?></th>
                        <th><?php esc_html_e('Status', 'dolutech-blacklist-protect'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($active_tokens as $token => $data) : ?>
                        <tr>
                            <td><?php echo esc_html($data['ip']); ?></td>
                            <td><?php echo esc_html(wp_date('d/m/Y H:i:s', $data['expiration'])); ?></td>
                            <td><span style="color: orange;"><?php esc_html_e('Pendente', 'dolutech-blacklist-protect'); ?></span></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php else : ?>
            <p><?php esc_html_e('Nenhum token de desbloqueio pendente.', 'dolutech-blacklist-protect'); ?></p>
        <?php endif; ?>

        <hr>

        <h2><?php esc_html_e('Enviar Feedback', 'dolutech-blacklist-protect'); ?></h2>
        <p><?php esc_html_e('Sua opinião é muito importante para nós! Envie sugestões, reporte bugs ou compartilhe sua experiência com o plugin.', 'dolutech-blacklist-protect'); ?></p>

        <div style="background: #f9f9f9; padding: 20px; border: 1px solid #ddd; border-radius: 4px;">
            <button type="button" id="blwp_toggle_feedback_form" class="button button-secondary" style="margin-bottom: 15px;">
                <?php esc_html_e('Clique aqui para enviar feedback', 'dolutech-blacklist-protect'); ?>
            </button>

            <div id="blwp_feedback_form_container" style="display: none;">
                <form method="post">
                    <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
                    <table class="form-table">
                        <tr>
                            <th scope="row">
                                <label for="blwp_feedback_message">
                                    <?php esc_html_e('Sua Mensagem', 'dolutech-blacklist-protect'); ?>
                                </label>
                            </th>
                            <td>
                                <textarea id="blwp_feedback_message" name="blwp_feedback_message"
                                          rows="8" cols="50"
                                          style="width: 100%; max-width: 600px;"
                                          placeholder="<?php esc_attr_e('Digite aqui suas sugestões, comentários ou reporte de bugs...', 'dolutech-blacklist-protect'); ?>"
                                          required></textarea>
                                <p class="description">
                                    <?php esc_html_e('Descreva sua sugestão, problema encontrado ou qualquer feedback que você gostaria de compartilhar.', 'dolutech-blacklist-protect'); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                    <p>
                        <input type="submit" name="blwp_send_feedback"
                               value="<?php esc_attr_e('Enviar Feedback', 'dolutech-blacklist-protect'); ?>"
                               class="button button-primary" />
                        <button type="button" id="blwp_cancel_feedback" class="button button-secondary">
                            <?php esc_html_e('Cancelar', 'dolutech-blacklist-protect'); ?>
                        </button>
                    </p>
                </form>

                <div style="margin-top: 15px; padding: 15px; background: #f0f8ff; border-left: 4px solid #0073aa;">
                    <strong><?php esc_html_e('Informação:', 'dolutech-blacklist-protect'); ?></strong>
                    <?php esc_html_e('Seu feedback será enviado junto com informações básicas do site (URL, versão do WordPress e do plugin) para nos ajudar a melhorar o plugin.', 'dolutech-blacklist-protect'); ?>
                </div>
            </div>
        </div>

        <script>
            (function() {
                var toggleBtn = document.getElementById('blwp_toggle_feedback_form');
                var formContainer = document.getElementById('blwp_feedback_form_container');
                var cancelBtn = document.getElementById('blwp_cancel_feedback');

                if (toggleBtn && formContainer) {
                    toggleBtn.addEventListener('click', function() {
                        if (formContainer.style.display === 'none') {
                            formContainer.style.display = 'block';
                            toggleBtn.style.display = 'none';
                        }
                    });
                }

                if (cancelBtn && formContainer) {
                    cancelBtn.addEventListener('click', function() {
                        formContainer.style.display = 'none';
                        toggleBtn.style.display = 'inline-block';
                        document.getElementById('blwp_feedback_message').value = '';
                    });
                }
            })();
        </script>

        <hr>

        <h2><?php esc_html_e('Notificações (Telegram e Webhook)', 'dolutech-blacklist-protect'); ?></h2>
        <p><?php esc_html_e('Receba alertas instantâneos quando o plugin bloquear acessos. Os eventos selecionados disparam notificações nos canais configurados.', 'dolutech-blacklist-protect'); ?></p>

        <form method="post">
            <?php wp_nonce_field('blwp_nonce_action', 'blwp_nonce_field'); ?>
            <table class="form-table">
            <tr>
                <th scope="row">
                    <?php esc_html_e('Telegram', 'dolutech-blacklist-protect'); ?>
                </th>
                <td>
                    <label>
                        <input type="checkbox" name="blwp_telegram_enabled" id="blwp_telegram_enabled" <?php checked($telegram_enabled, 1); ?> />
                        <?php esc_html_e('Ativar notificações via Telegram', 'dolutech-blacklist-protect'); ?>
                    </label>
                </td>
            </tr>
            <tbody id="telegram_settings" style="<?php echo $telegram_enabled ? '' : 'display:none;'; ?>">
            <tr>
                <th scope="row">
                    <label for="blwp_telegram_bot_token">
                        <?php esc_html_e('Bot Token', 'dolutech-blacklist-protect'); ?>
                    </label>
                </th>
                <td>
                    <input type="password" id="blwp_telegram_bot_token" name="blwp_telegram_bot_token"
                           value="" placeholder="<?php esc_attr_e('Deixe em branco para manter o atual', 'dolutech-blacklist-protect'); ?>"
                           style="width: 400px;" />
                    <p class="description">
                        <?php esc_html_e('Token do bot criado com @BotFather no Telegram.', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row">
                    <label for="blwp_telegram_chat_id">
                        <?php esc_html_e('Chat ID', 'dolutech-blacklist-protect'); ?>
                    </label>
                </th>
                <td>
                    <input type="text" id="blwp_telegram_chat_id" name="blwp_telegram_chat_id"
                           value="<?php echo esc_attr($telegram_chat_id); ?>"
                           placeholder="-1001234567890" style="width: 400px;" />
                    <p class="description">
                        <?php esc_html_e('ID do chat ou grupo que receberá os alertas.', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            </tbody>
            <tr>
                <th scope="row">
                    <?php esc_html_e('Webhook', 'dolutech-blacklist-protect'); ?>
                </th>
                <td>
                    <label>
                        <input type="checkbox" name="blwp_webhook_enabled" id="blwp_webhook_enabled" <?php checked($webhook_enabled, 1); ?> />
                        <?php esc_html_e('Ativar notificações via Webhook (Slack, Discord, Zapier...)', 'dolutech-blacklist-protect'); ?>
                    </label>
                </td>
            </tr>
            <tbody id="webhook_settings" style="<?php echo $webhook_enabled ? '' : 'display:none;'; ?>">
            <tr>
                <th scope="row">
                    <label for="blwp_webhook_url">
                        <?php esc_html_e('Webhook URL', 'dolutech-blacklist-protect'); ?>
                    </label>
                </th>
                <td>
                    <input type="url" id="blwp_webhook_url" name="blwp_webhook_url"
                           value="<?php echo esc_attr($webhook_url); ?>"
                           placeholder="https://hooks.slack.com/services/..." style="width: 400px;" />
                    <p class="description">
                        <?php esc_html_e('URL que receberá um POST JSON com os dados do evento.', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            </tbody>
            <tr>
                <th scope="row">
                    <?php esc_html_e('Eventos que disparam notificação', 'dolutech-blacklist-protect'); ?>
                </th>
                <td>
                    <?php
                    $event_labels = blwp_get_event_labels();
                    unset($event_labels['test']); // Teste não é selecionável
                    foreach ($event_labels as $key => $label) : ?>
                        <label style="display: block; margin-bottom: 4px;">
                            <input type="checkbox" name="blwp_notify_events[]" value="<?php echo esc_attr($key); ?>"
                                   <?php checked(in_array($key, $notify_events, true)); ?> />
                            <?php echo esc_html($label); ?>
                        </label>
                    <?php endforeach; ?>
                    <p class="description">
                        <?php esc_html_e('Deixe todos desmarcados para notificar em todos os eventos.', 'dolutech-blacklist-protect'); ?>
                    </p>
                </td>
            </tr>
            </table>
            <p>
                <input type="submit" name="blwp_save_notification_settings" value="<?php esc_attr_e('Salvar Configurações de Notificações', 'dolutech-blacklist-protect'); ?>" class="button button-primary" />
                <input type="submit" name="blwp_test_notification" value="<?php esc_attr_e('Enviar Notificação de Teste', 'dolutech-blacklist-protect'); ?>" class="button button-secondary" />
            </p>
        </form>

        <script>
            document.getElementById('blwp_telegram_enabled').addEventListener('change', function() {
                var settings = document.getElementById('telegram_settings');
                settings.style.display = this.checked ? '' : 'none';
            });
            document.getElementById('blwp_webhook_enabled').addEventListener('change', function() {
                var settings = document.getElementById('webhook_settings');
                settings.style.display = this.checked ? '' : 'none';
            });
        </script>
    </div>

    <?php
}
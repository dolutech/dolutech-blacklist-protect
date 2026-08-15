<?php
/**
 * Bootstrap dos testes unitários — stubs mínimos das funções WP usadas.
 *
 * @package Dolutech_Blacklist_Protect
 */

define('ABSPATH', __DIR__ . '/');
define('BLWP_VERSION', '0.9.0');
define('DAY_IN_SECONDS', 86400);
define('HOUR_IN_SECONDS', 3600);
define('MINUTE_IN_SECONDS', 60);
define('ARRAY_A', 'ARRAY_A');

require_once __DIR__ . '/stubs/wp-stubs.php';

// Carrega apenas os includes com lógica pura testável.
require_once dirname(__DIR__) . '/includes/cidr-ua.php';

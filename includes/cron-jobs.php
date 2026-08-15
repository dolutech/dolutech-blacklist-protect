<?php

if (!defined('ABSPATH')) {
    exit;
}

add_action('blwp_update_blacklist_hook', 'blwp_fetch_blacklist');
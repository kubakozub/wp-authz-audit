<?php
/** Guard wrappers, deliberately in a separate file from their callers. */

function demo_current_user_can_admin() {
    return current_user_can( 'manage_options' );
}

function demo_verify_ajax() {
    return check_ajax_referer( 'demo', 'nonce', false );
}

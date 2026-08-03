<?php
/**
 * The shape that produced a false positive against a real 2M-install plugin:
 * the capability check lives in a plugin-defined wrapper in ANOTHER file.
 * Nothing here may be reported.
 */

class Demo_Wrapped {

    public function __construct() {
        add_action( 'wp_ajax_demo_wrapped', array( $this, 'ajax_set_state' ) );
    }

    public function ajax_set_state() {
        if ( ! demo_verify_ajax() || ! demo_current_user_can_admin() ) {
            wp_send_json_error();
        }
        update_option( 'demo_state', sanitize_text_field( $_POST['state'] ) );
        wp_send_json_success();
    }
}

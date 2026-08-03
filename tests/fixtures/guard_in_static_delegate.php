<?php
/**
 * NEGATIVE — must not be reported.
 *
 * From wp-fastest-cache 1.5.0. The AJAX callback is a two-line wrapper that
 * include_once's a file and delegates to a STATIC method; the nonce check lives
 * there. That is a third level of indirection: callback -> include -> static
 * call. The documented depth-2 chain walk stops one level short.
 *
 * My own ad-hoc enumerator produced eight false "no guard at all" rows on this
 * plugin for exactly this reason before I read the delegates.
 *
 * Rule to add: follow Class::method() delegation, and treat a callback whose
 * entire body is include_once + a single static call as a pass-through.
 */

class Demo_Delegate {

    public function __construct() {
        add_action( 'wp_ajax_demo_save_backend', array( $this, 'demo_save_backend_callback' ) );
    }

    public function demo_save_backend_callback() {
        include_once( 'inc/backend.php' );
        DemoBackend::save();
    }
}

/* inc/backend.php */
class DemoBackend {
    public static function save() {
        if ( ! wp_verify_nonce( $_POST['security'], 'demo-backend-ajax-nonce' ) ) {
            die( 'Security check' );
        }
        update_option( 'demo_backend', sanitize_text_field( $_POST['server'] ) );
        wp_send_json_success();
    }
}

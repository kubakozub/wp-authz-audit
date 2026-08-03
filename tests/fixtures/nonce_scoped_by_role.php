<?php
/**
 * NEGATIVE for the "subscriber" label — required privilege is administrator.
 *
 * From wp-fastest-cache 1.5.0. The handler's only guard is a nonce, which reads
 * as CWE-862 [subscriber]. But the nonce is minted solely inside an admin-bar
 * node that is added only when the current user's roles intersect
 * array('administrator'). A subscriber is never issued a nonce for this action
 * and cannot forge one for their own session, so the handler is admin-only in
 * default configuration — which the Wordfence program excludes.
 *
 * Rule to add: resolve where wp_create_nonce(<action>) is emitted. If every
 * emission site is inside a role/capability-gated branch, raise the reported
 * required_privilege to that level instead of "subscriber".
 */

class Demo_Nonce_Scope {

    public function __construct() {
        add_action( 'wp_ajax_demo_purge', array( $this, 'purge' ) );
        add_action( 'wp_before_admin_bar_render', array( $this, 'maybe_add_node' ) );
    }

    public function maybe_add_node() {
        $user          = wp_get_current_user();
        $allowed_roles = array( 'administrator' );
        if ( array_intersect( $allowed_roles, $user->roles ) ) {
            echo "<script>var demo_nonce = '" . wp_create_nonce( 'demo' ) . "';</script>";
        }
    }

    public function purge() {
        if ( ! wp_verify_nonce( $_GET['nonce'], 'demo' ) ) {
            die( 'Security check' );
        }
        $this->delete_cache_files();
    }

    private function delete_cache_files() {}
}

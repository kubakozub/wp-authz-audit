<?php
/**
 * The same plugin written correctly. Nothing here may be reported.
 *
 * This is the half of the corpus that decides whether the tool is usable: a
 * scanner that flags correct code trains you to ignore it.
 */

class Demo_Hardened {

    public function __construct() {
        add_action( 'wp_ajax_demo_save', array( $this, 'save_settings' ) );
        add_action( 'wp_ajax_demo_meta', array( $this, 'object_scoped_cap' ) );
        add_action( 'admin_init', array( $this, 'admin_init_handler' ) );
        add_action( 'rest_api_init', array( $this, 'routes' ) );

        // auth_callback omitted: core defaults to a capability check.
        register_post_meta( 'post', '_demo_licence_key', array(
            'show_in_rest' => true,
            'single'       => true,
        ) );
    }

    public function save_settings() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( null, 403 );
        }
        check_ajax_referer( 'demo_action', 'nonce' );
        update_option( 'demo_api_endpoint', sanitize_text_field( $_POST['endpoint'] ) );
        wp_send_json_success();
    }

    public function object_scoped_cap() {
        $post_id = absint( $_POST['post_id'] );
        // The meta capability resolves ownership through map_meta_cap().
        if ( ! current_user_can( 'edit_post', $post_id ) ) {
            wp_send_json_error( null, 403 );
        }
        update_post_meta( $post_id, '_demo_note', sanitize_text_field( $_POST['note'] ) );
        wp_send_json_success();
    }

    public function admin_init_handler() {
        // Guard delegated to a helper: the tool must inherit it.
        if ( ! $this->may_export() ) {
            return;
        }
        if ( isset( $_GET['demo_export'] ) ) {
            update_option( 'demo_exported_at', time() );
        }
    }

    private function may_export() {
        return current_user_can( 'manage_options' );
    }

    public function routes() {
        register_rest_route( 'demo/v1', '/import', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'rest_import' ),
            'permission_callback' => array( $this, 'may_import' ),
        ) );

        register_rest_route( 'demo/v1', '/status', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'rest_status' ),
            'permission_callback' => '__return_true',
        ) );
    }

    public function may_import() {
        return current_user_can( 'manage_options' );
    }

    public function rest_import( $request ) {
        update_option( 'demo_imported', $request['payload'] );
    }

    public function rest_status( $request ) {
        return array( 'version' => '1.0.0' );
    }
}

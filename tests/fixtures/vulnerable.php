<?php
/**
 * Synthetic plugin exercising each authorization defect the tool targets.
 * Every shape here is a pattern, not a copy of any real plugin's code.
 *
 * This docblock deliberately mentions current_user_can( 'manage_options' ) so a
 * detector that matches inside comments will visibly over-report.
 */

class Demo_Vulnerable {

    public function __construct() {
        // CWE-862: reachable with no credentials, writes an option.
        add_action( 'wp_ajax_nopriv_demo_save', array( $this, 'save_settings' ) );

        // CWE-862: any logged-in user, including a subscriber. A nonce is not
        // an authorization check.
        add_action( 'wp_ajax_demo_nonce_only', array( $this, 'nonce_only' ) );

        // CWE-863: primitive capability guarding a write to a supplied object.
        add_action( 'wp_ajax_demo_meta', array( $this, 'primitive_cap' ) );

        // Reachable unauthenticated despite the hook's name.
        add_action( 'admin_init', array( $this, 'admin_init_handler' ) );

        add_action( 'rest_api_init', array( $this, 'routes' ) );

        register_post_meta( 'post', '_demo_licence_key', array(
            'show_in_rest'  => true,
            'single'        => true,
            'auth_callback' => '__return_true',
        ) );
    }

    public function save_settings() {
        update_option( 'demo_api_endpoint', $_POST['endpoint'] );
        wp_send_json_success();
    }

    public function nonce_only() {
        check_ajax_referer( 'demo_action', 'nonce' );
        update_option( 'demo_licence', $_POST['licence'] );
        wp_send_json_success();
    }

    public function primitive_cap() {
        if ( ! current_user_can( 'edit_posts' ) ) {
            wp_send_json_error();
        }
        update_post_meta( $_POST['post_id'], '_demo_note', $_POST['note'] );
        wp_send_json_success();
    }

    public function admin_init_handler() {
        if ( isset( $_GET['demo_export'] ) ) {
            update_option( 'demo_exported_at', time() );
        }
    }

    public function routes() {
        // No permission_callback at all; core only warns and still serves it.
        register_rest_route( 'demo/v1', '/import', array(
            'methods'  => 'POST',
            'callback' => array( $this, 'rest_import' ),
        ) );

        // Explicitly public and state-changing.
        register_rest_route( 'demo/v1', '/reset', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'rest_reset' ),
            'permission_callback' => '__return_true',
        ) );

        // Public READ route: legitimate design, must NOT be reported.
        register_rest_route( 'demo/v1', '/status', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'rest_status' ),
            'permission_callback' => '__return_true',
        ) );
    }

    public function rest_import( $request ) {
        update_option( 'demo_imported', $request['payload'] );
    }

    public function rest_reset( $request ) {
        delete_option( 'demo_licence' );
    }

    public function rest_status( $request ) {
        return array( 'version' => '1.0.0' );
    }
}

/**
 * A permissive auth_callback on a key with no security meaning. The pattern is
 * identical to the licence-key case above; the consequence is not. Severity
 * must reflect that, otherwise every plugin using a dirty-flag reads as critical.
 */
function demo_register_flag_meta() {
    register_post_meta( 'post', '_demo_changed', array(
        'type'          => 'boolean',
        'single'        => true,
        'show_in_rest'  => true,
        'auth_callback' => '__return_true',
    ) );
}

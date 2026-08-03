<?php
/**
 * POSITIVE — the shape that produced the only confirmed finding of the day.
 *
 * A nopriv endpoint hands out a nonce; another handler is guarded by nothing
 * but that same nonce. An anonymous caller fetches a valid token from the
 * public vendor and replays it, so the second handler is unauthenticated in
 * practice even though it is registered on wp_ajax_ only.
 *
 * Seen in the wild as wpforms_get_token, forminator_get_nonce,
 * nf_ajax_get_new_nonce and pmpro_get_checkout_nonce.
 */

class Demo_Vendor {

    public function __construct() {
        add_action( 'wp_ajax_nopriv_demo_get_token', array( $this, 'issue_token' ) );
        add_action( 'wp_ajax_demo_vendor_save', array( $this, 'save' ) );
    }

    public function issue_token() {
        wp_send_json_success( array( 'nonce' => wp_create_nonce( 'demo_vendor' ) ) );
    }

    public function save() {
        if ( ! wp_verify_nonce( $_POST['nonce'], 'demo_vendor' ) ) {
            wp_send_json_error();
        }
        update_option( 'demo_smtp_password', $_POST['value'] );
        wp_send_json_success();
    }
}

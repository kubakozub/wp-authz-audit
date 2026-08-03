<?php
/**
 * The inheritance chain that produced four false positives.
 *
 * Ground truth: a $wp_filter dump from a live install listed the nopriv action
 * for the users subclass and NOT for the ones that inherit or declare
 * public = false. Ignoring the `if ( $this->public )` condition invents them.
 *
 * The dispatcher line below is the one every finding pointed at. Only the
 * subclass that both sets public = true and contains WP_User_Query may produce
 * a user-disclosure finding.
 */

class Demo_Base {

    var $action = '';
    var $public = false;

    public function add_actions() {
        add_action( "wp_ajax_{$this->action}", array( $this, 'request' ) );
        if ( $this->public ) {
            add_action( "wp_ajax_nopriv_{$this->action}", array( $this, 'request' ) );
        }
    }

    public function request() {
        if ( ! wp_verify_nonce( $_REQUEST['nonce'], 'demo_generic' ) ) {
            wp_send_json_error();
        }
        wp_send_json( $this->get_results() );
    }

    public function get_results() {
        return array();
    }
}

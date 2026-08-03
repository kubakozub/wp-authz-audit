<?php
/**
 * POSITIVE — currently MISSED. This is the false negative to close.
 *
 * From advanced-custom-fields 6.8.6 / secure-custom-fields 6.9.4. The base class
 * registers its hook from a property: add_action( "wp_ajax_nopriv_{$this->action}" ).
 * The literal hook name never appears in source, so the entry point is invisible
 * and `map` does not list it at all.
 *
 * Confirmed reachable and exploitable in a local lab: unauthenticated, returns
 * the complete user list grouped by role. Its only guard is a nonce, and that
 * nonce is not bound to the field type, so a nonce emitted for an unrelated
 * public field is accepted here.
 *
 * Two rules to add:
 *   1. Resolve interpolated hook names when the interpolated part is a class
 *      property assigned a literal in the same class (var $action = '...').
 *   2. Add a read-sink category. Today only state-changing sinks rank high, so a
 *      handler that merely RETURNS get_users()/WP_User_Query/get_user_meta data
 *      behind a nonce-only guard is under-ranked. Missing authorization on a read
 *      is still CWE-862.
 */

class Demo_Ajax_Base {

    var $action = '';
    var $public = false;

    public function add_actions() {
        add_action( "wp_ajax_{$this->action}", array( $this, 'request' ) );
        if ( $this->public ) {
            add_action( "wp_ajax_nopriv_{$this->action}", array( $this, 'request' ) );
        }
    }

    public function request() {
        if ( ! $this->verify_request( $_REQUEST ) ) {
            wp_send_json_error();
        }
        wp_send_json( $this->get_results() );
    }
}

class Demo_Ajax_Query_Users extends Demo_Ajax_Base {

    var $action = 'demo/ajax/query_users';
    var $public = true;

    public function verify_request( $request ) {
        /* nonce only — no capability check anywhere on this path */
        return wp_verify_nonce( $request['nonce'], 'demo_field_' . $request['field_key'] );
    }

    public function get_results() {
        $query = new WP_User_Query( array( 'number' => 100 ) );
        return $query->get_results();
    }
}

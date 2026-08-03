<?php
/**
 * NEGATIVE — reachable unauthenticated, but must not be ranked high.
 *
 * From ml-slider 3.111.1 (ml-slider.php:322). admin_init does fire before the
 * authentication branch, so reachability is real. The sink deletes a one-shot
 * activation flag that only exists between activation and the first admin page
 * load, and whose sole effect is suppressing an onboarding redirect.
 *
 * Same family as the _acf_changed case already documented in the README.
 * Rule to add: delete_option/update_option on an option that is only ever
 * written with a boolean/flag value carries no impact — report at most INFO.
 */

class Demo_Flag {

    public function __construct() {
        add_action( 'admin_init', array( $this, 'redirect_on_activate' ) );
    }

    public function redirect_on_activate() {
        if ( get_option( 'demo_activate' ) ) {
            delete_option( 'demo_activate' );
            if ( ! isset( $_GET['activate-multi'] ) ) {
                wp_redirect( admin_url( 'admin.php?page=demo-start' ) );
                exit;
            }
        }
    }
}

function demo_activate() {
    add_option( 'demo_activate', true );
}
register_activation_hook( __FILE__, 'demo_activate' );

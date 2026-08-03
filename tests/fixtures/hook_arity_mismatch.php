<?php
/**
 * NEGATIVE — must not be reported.
 *
 * From ml-slider 3.111.1 (ml-slider.php:327). A programmatic helper is ALSO
 * registered on admin_post_. do_action("admin_post_{$action}") passes no
 * arguments, so the two required parameters are never supplied: reaching the
 * hook raises ArgumentCountError, it does not delete anything. The callback
 * reads no superglobal, so no attacker-controlled object id exists.
 *
 * Rule to add: a callback whose required arity exceeds the arity the hook
 * supplies, AND which reads no request superglobal, is not attacker-driven.
 */

class Demo_Arity {

    public function __construct() {
        add_action( 'admin_post_demo_delete_item', array( $this, 'delete_item' ) );
    }

    public function delete_item( $item_id, $parent_id ) {
        wp_update_post( array( 'ID' => $parent_id ) );
        return wp_update_post( array( 'ID' => $item_id, 'post_status' => 'trash' ) );
    }
}

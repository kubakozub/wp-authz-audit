<?php
/**
 * NEGATIVE — the shape that collapsed precision.
 *
 * Measured across 60 popular plugins: 251 of 435 high-severity findings were
 * handlers exactly like these. Every plugin registers something on init and
 * plugins_loaded; saying "runs before any authentication branch" about a
 * plugin loading itself is true and useless.
 *
 * Only admin_init is a dispatch point, because admin-ajax.php and
 * admin-post.php fire it before their is_user_logged_in() branch.
 */

class Demo_Bootstrap {

    public function __construct() {
        add_action( 'init', array( $this, 'init_hooks' ) );
        add_action( 'plugins_loaded', array( $this, 'load_textdomain' ) );
        add_action( 'after_setup_theme', array( $this, 'initialize' ) );
    }

    public function init_hooks() {
        update_option( 'demo_last_boot', time() );
        register_post_type( 'demo_item', array( 'public' => true ) );
    }

    public function load_textdomain() {
        load_plugin_textdomain( 'demo', false, 'demo/languages' );
        update_option( 'demo_version', '1.2.3' );
    }

    public function initialize() {
        add_image_size( 'demo-thumb', 150, 150 );
    }
}

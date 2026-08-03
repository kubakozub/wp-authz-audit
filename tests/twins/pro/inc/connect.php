<?php
/** Same function, same vendor, with the capability check. */
class Demo_Connect_Pro {
    public function generate_url() {
        if ( ! current_user_can( 'install_plugins' ) ) {
            return '';
        }
        $token = get_option( 'demo_connect_token' );
        if ( empty( $token ) ) {
            return '';
        }
        return add_query_arg( 'token', $token, 'https://api.example.test/connect' );
    }
}

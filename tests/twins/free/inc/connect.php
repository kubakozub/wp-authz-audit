<?php
/** The sibling MISSING the guard the other has. */
class Demo_Connect_Free {
    public function generate_url() {
        $token = get_option( 'demo_connect_token' );
        return add_query_arg( 'token', $token, 'https://api.example.test/connect' );
    }
}

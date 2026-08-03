<?php
/** Only the larger sibling has this. Same METHOD name, unrelated class. */
class Demo_Unrelated_Importer {
    public function check_submit() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return false;
        }
        if ( ! wp_verify_nonce( $_POST['nonce'], 'demo_import' ) ) {
            return false;
        }
        return true;
    }
}

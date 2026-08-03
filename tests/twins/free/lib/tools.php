<?php
/**
 * Byte-identical in both siblings. compare must report NO divergence here.
 *
 * The guard is a vendor wrapper, and the wrapper lives in another file. When
 * functions were matched on bare name and the longest body won, the larger tree
 * contributed an unrelated same-named method and this read as divergent.
 */
class Demo_Tools {
    public function check_submit() {
        if ( ! demo_verify_nonce( 'demo_tool' ) ) {
            return false;
        }
        return true;
    }
}

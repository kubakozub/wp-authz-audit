<?php
/** Public and discloses users — the only true positive here. */
class Demo_Query_Users extends Demo_Base {
    var $action = 'demo/ajax/query_users';
    var $public = true;

    public function get_results() {
        $query = new WP_User_Query( array( 'number' => 100 ) );
        return $query->get_results();
    }
}

/** Explicitly not public. Must not appear as a nopriv entry point. */
class Demo_Check_Screen extends Demo_Base {
    var $action = 'demo/ajax/check_screen';
    var $public = false;

    public function get_results() {
        return array( 'screen' => 'demo' );
    }
}

/** Inherits public = false. Must not appear as a nopriv entry point. */
class Demo_Upgrade extends Demo_Base {
    var $action = 'demo/ajax/upgrade';

    public function get_results() {
        return array( 'done' => true );
    }
}

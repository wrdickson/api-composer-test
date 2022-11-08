<?php

namespace wrdickson\apitest;

use \PDO;

/*
class.data_connecter.php
*/
class Data_Connector {
    public static function get_connection( $db_host, $db_name, $db_user, $db_pass){
        try {
           $pdo = new PDO('mysql:host=' . $db_host .';dbname=' . $db_name, $db_user, $db_pass);
           //  see https://stackoverflow.com/questions/60174/how-can-i-prevent-sql-injection-in-php?rq=1
           $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
           $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            return $pdo;
        } catch (PDOException $e) {
            return "Error!: " . $e->getMessage() . "<br/>";
            die();
        }   
    }
}



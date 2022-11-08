<?php

namespace wrdickson\apitest;

use \PDO;
use \DateTimeImmutable;
use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;
use \Firebase\JWT\SignatureInvalidException;
use \Firebase\JWT\BeforeValidException;
use \Firebase\JWT\ExpiredException;

Class Auth {

  private $server_name;
  private $jwt_key;
  private $db_host;
  private $db_name;
  private $db_user;
  private $db_pass;

  private $id;
  private $username;
  private $email;
  private $permission; 
  private $roles;
  private $registered;
  private $last_login;
  private $last_activity;
  private $is_active;

  public function __construct (  $server_name, $jwt_key, $db_host, $db_name, $db_user, $db_pass ) {

    $this->server_name = $server_name;
    $this->jwt_key = $jwt_key;
    $this->db_host = $db_host;
    $this->db_name = $db_name;
    $this->db_user = $db_user;
    $this->db_pass = $db_pass;

  }

  public function account_to_array_secure () {
    $arr = array();
    $arr['id'] = $this->id;
    $arr['username'] = $this->username;
    $arr['permission'] = $this->permission;
    $arr['roles'] = $this->roles;
    $arr['is_active'] = $this->is_active;
    return $arr;
  }

  public function authenticate( $perm_required, $token ){
    $authenticate_status = null;
    $authenticate_decoded = null;

    //  handle jwt is null, ie 'jwt' is not set in headers
    if(!$token){
      //  status 400: Bad Request
      $authenticate_status = 400;
    } else {
      try{
        //  const JWT_KEY is defined in config
        $authenticate_decoded = JWT::decode( $token, new Key( $this->jwt_key, 'HS256') );
        //  check that the user has the permission level
        //  OR has the role 
        if( $authenticate_decoded->account->permission < $perm_required['permission'] &&
            !in_array($perm_required['role'], $authenticate_decoded->account->roles) ) {
          //  status 403: Forbidden
          $authenticate_status = 403;
        } else {
          //  test iss, nbf and exp
          $now = new DateTimeImmutable();
          if ($authenticate_decoded->iss !== $this->server_name ||
              $authenticate_decoded->nbf > $now->getTimestamp() ||
              $authenticate_decoded->exp < $now->getTimestamp()) {
            //  status 401: Unauthorized
            $authenticate_status = 401;
          } else {
            //  jwt has passed authentication
            $authenticate_status = 200;
          }
        }
      //  JWT::decode() throws errors if the decode fails
      } catch (SignatureInvalidException $e){
        //  status 401: Unauthorized
        $authenticate_status = 401;
      } catch (BeforeValidException $e) {
        // provided JWT is trying to be used before "nbf" claim OR
        // provided JWT is trying to be used before "iat" claim.
        //  status 401: Unauthorized
        $authenticate_status = 401;
      } catch (ExpiredException $e) {
        // provided JWT is trying to be used after "exp" claim.
        //  status 401: Unauthorized
        $authenticate_status = 401;
      }
    }
    $r = array(
      'status' => $authenticate_status,
      'decoded' => $authenticate_decoded
    );
    return $r;
  }

  public function check_login( $username, $password ) {
    $response = array();
    $pdo = $this->get_connection();
    $stmt = $pdo->prepare('SELECT * FROM accounts WHERE username = :u');
    $stmt->bindParam(':u', $username);
    $stmt->execute();
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    if(is_array($result)) {
      if(password_verify($password, $result['password']) == true){
        $response['pass'] = true;
        $response['account_id'] = $result['id'];
        $account = $this->load_account($result['id']);
        //  update the login
        //$response['update_login'] = $account->update_login();
        //$response['update_activity'] = $account->update_activity();
        $response['account'] = $this->account_to_array_secure();
      } else {
        $response['pass'] = false;
        $response['account_id'] = -1;
      }
    } else {
      $response['pass'] = false;
      $response['account_id'] = -1;
    }
    return $response;
  }

  public function generate_token( $account_id ) {
    $this->load_account( $account_id );
    $issuedAt = new DateTimeImmutable();
    $expire = $issuedAt->modify('+1 days')->getTimestamp();
    $payload = [
      'iat' => $issuedAt->getTimestamp(),  // Issued at: time when the token was generated,
      //  SERVER_NAME is a constant set in config.php
      'iss' => $this->server_name,
      'exp' => $expire,
      'exp_f' => date("Y-m-d H:m:s", $expire),  // Formatted expire
      'nbf'  => $issuedAt->getTimestamp(),  // Not before
      'nbf_f' => date( "Y-m-d H:m:s", $issuedAt->getTimestamp() ),  // Formatted not before
      'account' => $this->account_to_array_secure()
    ];
    $token = JWT::encode($payload, $this->jwt_key, 'HS256');
    return $token;
  }

  public function get_connection( ){
    try {
       $pdo = new PDO('mysql:host=' . $this->db_host .';dbname=' . $this->db_name, $this->db_user, $this->db_pass);
       //  see https://stackoverflow.com/questions/60174/how-can-i-prevent-sql-injection-in-php?rq=1
       $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
       $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $pdo;
    } catch (PDOException $e) {
        return "Error!: " . $e->getMessage() . "<br/>";
        die();
    }   
}

  public function load_account ( $account_id ) {
    $pdo = $this->get_connection( );
    $stmt = $pdo->prepare("SELECT * FROM accounts WHERE id = :id");
    $stmt->bindParam(":id", $account_id);
    $stmt->execute();
    while($obj = $stmt->fetch(PDO::FETCH_OBJ)){
      $this->id = $obj->id;
      $this->username = $obj->username;
      $this->email = $obj->email;
      $this->permission = $obj->permission;
      $this->roles = json_decode($obj->roles, true);
      $this->registered = $obj->registered;
      $this->last_login = $obj->last_login;
      $this->last_activity = $obj->last_activity;
      $this->is_active = (int)$obj->is_active;
    }
  }
}

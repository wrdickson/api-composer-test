<?php

namespace wrdickson\test;

Class Foo {

  public static function generate_token( ) {
    $account = array (
      'username'=>'somefrigginuser',
      'id'=>'1234',
      'permission'=>'4'
    );
    $issuedAt = new DateTimeImmutable();
    $expire = $issuedAt->modify('+1 days')->getTimestamp();
    $payload = [
      'iat' => $issuedAt->getTimestamp(),  // Issued at: time when the token was generated,
      //  SERVER_NAME is a constant set in config.php
      'iss' => SERVER_NAME,
      'exp' => $expire,
      'exp_f' => date("Y-m-d H:m:s", $expire),  // Formatted expire
      'nbf'  => $issuedAt->getTimestamp(),  // Not before
      'nbf_f' => date( "Y-m-d H:m:s", $issuedAt->getTimestamp() ),  // Formatted not before
      'account' => $account->to_array_secure()
    ];
    $token = JWT::encode($payload, JWT_KEY, 'HS256');
    return $token;
  }
}
<?php

namespace wrdickson\apitest;

require '../vendor/autoload.php';

Class Hello {

  private $name;

  function __construct( $name ){
    $this->name = $name;
  }

  public function say_hello () {
    echo $this->name;
  }
}

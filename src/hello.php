<?php

namespace wrdickson\apitest;

Class Hello {

  private $name;

  function __construct( $name ){
    $this->name = $name;
  }

  public function say_hello () {
    echo $this->name;
  }
}

<?php

use Veracode\HmacRequestSigner;

require 'RequestSigner.php';
$signed = HmacRequestSigner::getVeracodeAuthorizationHeader("abc", "abcd", "https://veracode.com/api", "GET");

var_dump($signed);

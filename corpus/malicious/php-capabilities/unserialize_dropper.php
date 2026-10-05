<?php
$raw = file_get_contents('https://example.test/obj');
$obj = unserialize(base64_decode($raw));

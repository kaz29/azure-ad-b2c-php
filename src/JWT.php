<?php
declare(strict_types=1);

namespace kaz29\AzureADB2C;

use JOSE_JWK;
use JOSE_JWT;
use phpseclib\Crypt\RSA;

class JWT
{
    public function decodeJWK($components): RSA
    {
        return JOSE_JWK::decode($components);
    }

    public function decodeJWT(string $token): JOSE_JWT
    {
        return JOSE_JWT::decode($token);
    }
}
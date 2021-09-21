<?php
declare(strict_types=1);

namespace kaz29\AzureADB2C;

use Firebase\JWT\JWT as FirebaseJWT;
use Firebase\JWT\JWK as FirebaseJWK;

class JWT
{
    public function decodeJWK(string $token, array $jwks): array
    {
        $result = FirebaseJWT::decode($token, FirebaseJWK::parseKeySet(['keys' => $jwks]), ['RS256']);
        $payload = [];
        foreach ($result as $key => $value) {
            $payload[$key] = $value;
        }

        return $payload;
    }
}
<?php
declare(strict_types=1);

namespace kaz29\AzureADB2C\Entity;

use JOSE_JWS;

/**
 * AccessToken
 *
 * @property string $accessToken
 * @property string $tokenType
 * @property int $notBefore
 * @property int $expiresIn
 * @property int $expiresOn
 * @property string $resource
 * @property string $profileInfo
 * @property string $refreshToken
 * @property int $refreshtokenExpiresIn
 * @property JOSE_JWS $jws
 */
class AccessToken extends BaseEntity {
    protected $config = [
        'map' => [
            'access_token' => 'accessToken',
            'token_type' => 'tokenType',
            'not_before' => 'notBefore',
            'expires_in' => 'expiresIn',
            'expires_on' => 'expiresOn',
            'resource' => 'resource',
            'profile_info' => 'profileInfo',
            'refresh_token' => 'refreshToken',
            'refresh_token_expires_in' => 'refreshtokenExpiresIn',
        ],
    ];

    protected $jws;

    public function setJWS(JOSE_JWS $jws): void
    {
        $this->jws = $jws;
    }

    public function getJWS(): JOSE_JWS
    {
        return $this->jws;
    }
}

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
 * @property Header $header
 * @property Claims $claims
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
    protected $header;
    protected $claims;

    public function setJWS(JOSE_JWS $jws): void
    {
        $this->jws = $jws;

        $this->header = new Header((array)$jws->header);
        $this->claims = new Claims((array)$jws->claims);
    }

    public function getJWS(): JOSE_JWS
    {
        return $this->jws;
    }

    public function getClaims(): Claims
    {
        return $this->claims;
    }

    public function getHeader(): Header
    {
        return $this->header;
    }
}

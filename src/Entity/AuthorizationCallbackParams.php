<?php
declare(strict_types=1);

namespace kaz29\AzureADB2C\Entity;

use JOSE_JWS;

/**
 * AuthorizationCallbackParams
 *
 * @property string $state
 * @property string $code
 * @property string $idToken
 */
class AuthorizationCallbackParams extends BaseEntity
{
    protected $config = [
        'map' => [
            'state' => 'state',
            'code' => 'code',
            'id_token' => 'idToken',
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

<?php
declare(strict_types=1);

namespace kaz29\AzureADB2C\Entity;

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
    protected $claims;

    public function setClaims(array $claims): void
    {
        $this->claims = new Claims($claims);
    }

    public function getClaims(): Claims
    {
        return $this->claims;
    }
}

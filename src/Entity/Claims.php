<?php
declare(strict_types=1);

namespace kaz29\AzureADB2C\Entity;

/**
 * Claims
 *
 * @property string $iss
 * @property int $exp
 * @property int $nbf
 * @property string $aud
 * @property string $tfp
 * @property string $scp
 * @property string $azp
 * @property string $ver
 * @property string $iat
 * @property string $nonce
 *
 * @property string $idp
 * @property string $sub
 * @property string $givenName
 * @property string $familyName
 * @property string $country
 * @property string $postalCode
 * @property array $emails
 */
class Claims extends BaseEntity {
    protected $config = [
        'map' => [
            'iss' => 'iss',
            'exp' => 'exp',
            'nbf' => 'nbf',
            'aud' => 'aud',
            'tfp' => 'tfp',
            'scp' => 'scp',
            'azp' => 'azp',
            'var' => 'var',
            'iat' => 'iat',
            'nonce' => 'nonce',

            'idp' => 'idp',
            'sub' => 'sub',
            'given_name' => 'givenName',
            'family_name' => 'familyName',
            'country' => 'country',
            'postalCode' => 'postalCode',
            'emails' => 'emails'
        ],
    ];
}

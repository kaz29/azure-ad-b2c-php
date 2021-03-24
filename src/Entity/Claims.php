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
 * @property string $authTime
 *
 * @property string $idp
 * @property string $idpAccessToken
 * 
 * @property string $sub
 * @property string|null $givenName
 * @property string|null $familyName
 * @property string|null $name
 * @property string|null $country
 * @property string|null $postalCode
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
            'auth_time' => 'authTime',

            'idp' => 'idp',
            'idp_access_token' => 'idpAccessToken',

            'sub' => 'sub',
            'given_name' => 'givenName',
            'family_name' => 'familyName',
            'name' => 'name',
            'country' => 'country',
            'postalCode' => 'postalCode',
            'emails' => 'emails'
        ],
    ];

    public function getFullName(string $locale): string
    {
        $fullName = '';
        switch($locale) {
            case 'ja':
            case 'ja_JP':
                $fullName = "{$this->familyName} {$this->givenName}";
                break;
            default:
                $fullName = "{$this->givenName} {$this->familyName}";
                break;
        }

        return (string)$fullName;
    }
}

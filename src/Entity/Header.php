<?php
declare(strict_types=1);

namespace kaz29\AzureADB2C\Entity;

/**
 * Header
 *
 * @property string $typ
 * @property string $alg
 * @property string $kid
 */
class Header extends BaseEntity {
    protected $config = [
        'map' => [
            'typ' => 'typ',
            'alg' => 'alg',
            'kid' => 'kid',
        ],
    ];
}

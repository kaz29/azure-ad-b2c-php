<?php
declare(strict_types=1);

namespace kaz29\AzureADB2C\Entity;

/**
 * Configuration
 *
 * @property string $isUser
 * @property string $authorizationEndpoint
 * @property string $tokenEndpoint
 * @property string $endSessionEndpoint
 * @property string $jwksUri
 * @property array $responseModesSupported
 * @property array $responseTypesSupported
 * @property array $scopesSupported
 * @property array $subjectTypesSupported
 * @property array $idTokenSigningAlgValuesSupported
 * @property array $tokenEndpointAuthMethodsSupported
 * @property array $claimsSupported
 */
class Configuration extends BaseEntity
{
    protected $config = [
        'map' => [
            'issuer' => 'isUser',
            'authorization_endpoint' => 'authorizationEndpoint',
            'token_endpoint' => 'tokenEndpoint',
            'end_session_endpoint' => 'endSessionEndpoint',
            'jwks_uri' => 'jwksUri',
            'response_modes_supported' => 'responseModesSupported',
            'response_types_supported' => 'responseTypesSupported',
            'scopes_supported' => 'scopesSupported',
            'subject_types_supported' => 'subjectTypesSupported',
            'id_token_signing_alg_values_supported' => 'idTokenSigningAlgValuesSupported',
            'token_endpoint_auth_methods_supported' => 'tokenEndpointAuthMethodsSupported',
            'claims_supported' => 'claimsSupported',
        ]
    ];
}
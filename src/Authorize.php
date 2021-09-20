<?php
declare(strict_types=1);

namespace kaz29\AzureADB2C;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Query;
use kaz29\AzureADB2C\Entity\AccessToken;
use kaz29\AzureADB2C\Entity\Configuration;
use kaz29\AzureADB2C\Exception\InternalErrorException;
use kaz29\AzureADB2C\Exception\ResponseErrorException;
use kaz29\AzureADB2C\Exception\VerificationError;

/**
 * Authorize class
 *
 * @property \GuzzleHttp\Client $client
 * @property string $tenant
 * @property string $client_id
 * @property string $client_secret
 * @property string|null $flow
 * @property \kaz29\AzureADB2C\Entity\Configuration $configuration
 * @property \kaz29\AzureADB2C\JWT $jwt
 * @property array $jwks
 */
class Authorize {
    protected static $CONFIGURATION_URI_FORMAT='https://%s.b2clogin.com/%s.onmicrosoft.com/v2.0/.well-known/openid-configuration';

    protected $client;
    protected $tenant;
    protected $client_id;
    protected $client_secret;
    protected $configuration;
    protected $jwt;
    protected $jwks;
    protected $authorizationEndpoint = null;

    public function __construct(Client $client, JWT $jwt, array $config)
    {
        $this->client = $client;
        $this->jwt = $jwt;
        $this->tenant = $config['tenant'] ?? '';
        $this->client_id = $config['client_id'] ?? '';
        $this->client_secret = $config['client_secret'] ?? '';
        $this->flow = $config['flow'] ?? null;

        if ($this->flow !== null) {
            $this->loadOpenIdConfiguration($this->flow);
        }

        if (array_key_exists('jwks', $config) && is_array($config['jwks'])) {
            $this->jwks = $config['jwks'];
        }

        if (array_key_exists('custom_authorization_endpoint', $config) && !empty($config['custom_authorization_endpoint'])) {
            $this->authorizationEndpoint = $config['custom_authorization_endpoint'];
        }
    }

    public function getConfigurationUri(string $p): string
    {
        $uri = sprintf(self::$CONFIGURATION_URI_FORMAT, $this->tenant, $this->tenant);
        $query = [
            'p' => $p,
        ];

        return $uri . '?' . Query::build($query);
    }

    public function loadOpenIdConfiguration(string $p): Configuration
    {
        $response = $this->client->get($this->getConfigurationUri($p), ['query' => ['p' => $p]]);
        if ($response->getStatusCode() !== 200) {
            throw new ResponseErrorException('Could not get configuration', $response->getStatusCode());
        }

        $json = json_decode((string)$response->getBody(), true);
        $this->configuration = new Configuration($json);
        
        return $this->configuration;
    }

    public function setOpenIdConfiguration(Configuration $config)
    {
        $this->configuration = $config;
    }

    public function getAuthorizationEndpoint(
        string $redirectUri,
        string $scope, 
        $nonce, 
        string $responseMode = 'form_post', 
        string $responseType = 'code id_token',
        string $state = null
    ): string
    {
        $authorizationEndpoint = $this->authorizationEndpoint !== null
            ? $this->authorizationEndpoint
            : $this->configuration->authorizationEndpoint;

            if (is_null($this->configuration)) {
            throw new InternalErrorException('Configuration not complete');
        }

        $query = [
            'client_id' => $this->client_id,
            'redirect_uri' => $redirectUri,
            'scope' => $scope,
            'response_type' => $responseType,
            'response_mode' => $responseMode,
            'nonce' => $nonce,
        ];

        if (!is_null($state)) {
            $query['state'] = $state;
        }

        return $authorizationEndpoint . '&' . Query::build($query);
    }

    public function getJWKs(): array
    {
        if (is_array($this->jwks)) {
            return $this->jwks;
        }

        if (is_null($this->configuration)) {
            throw new InternalErrorException('Configuration not complete');
        }
        $response = $this->client->get($this->configuration->jwksUri);
        if ($response->getStatusCode() !== 200) {
            throw new ResponseErrorException('Could not get jwks', $response->getStatusCode());
        }

        $jwks = json_decode((string)$response->getBody(), true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new InternalErrorException('Could not decode jwks');
        }

        if (!array_key_exists('keys', $jwks) || !is_array($jwks['keys'])) {
            throw new ResponseErrorException('Unknown jwks response format');
        }

        $this->jwks = $jwks['keys'];
        
        return $this->jwks;
    }

    public function getAccessToken(
        string $code, 
        string $scope,
        string $redirect_url,
        string $grant_type = 'authorization_code'): AccessToken
    {
        $response = $this->client->post(
            $this->configuration->tokenEndpoint, 
            [
                'form_params' => [
                    'grant_type' => $grant_type,
                    'client_id' => $this->client_id,
                    'scope' => $scope,
                    'code' => $code,
                    'redirect_uri' => $redirect_url,
                    'client_secret' => $this->client_secret,
                ]
            ]
        );
        if ($response->getStatusCode() !== 200) {
            throw new ResponseErrorException('Could not get accessToken', $response->getStatusCode());
        }

        $accessToken = new AccessToken(json_decode((string)$response->getBody()->getContents(), true));

        $claims = $this->verifyToken($accessToken->accessToken);
        $accessToken->setClaims($claims);

        return $accessToken;
    }

    public function tokenRefresh(
        string $refreshToken,
        string $redirect_url): AccessToken
    {
        $response = $this->client->post(
            $this->configuration->tokenEndpoint,
            [
                'form_params' => [
                    'grant_type' => 'refresh_token',
                    'client_id' => $this->client_id,
                    'redirect_uri' => $redirect_url,
                    'refresh_token' => $refreshToken,
                    'client_secret' => $this->client_secret,
                ]
            ]
        );
        if ($response->getStatusCode() !== 200) {
            throw new ResponseErrorException('Could not get accessToken', $response->getStatusCode());
        }

        $accessToken = new AccessToken(json_decode((string)$response->getBody()->getContents(), true));

        $claims = $this->verifyToken($accessToken->accessToken);
        $accessToken->setClaims($claims);

        return $accessToken;
    }

    public function verifyToken(string $token): array
    {
        try {
            return $this->jwt->decodeJWK($token, $this->getJWKs());
        } catch (\Exception $e) {
            throw new VerificationError($e->getMessage());
        }
    }
}

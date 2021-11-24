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
    protected $configurations = [];
    protected $jwt;
    protected $jwks = [];
    protected $customDomain;
    protected $claims_config = [];

    public function __construct(Client $client, JWT $jwt, array $config)
    {
        $this->client = $client;
        $this->jwt = $jwt;
        $this->tenant = $config['tenant'] ?? '';
        $this->client_id = $config['client_id'] ?? '';
        $this->client_secret = $config['client_secret'] ?? '';
        $this->flow = $config['flow'] ?? null;
        $this->customDomain = $config['custom_domain'] ?? null;
        $this->claims_config = $config['claims_config'] ?? null;

        if (array_key_exists('jwks', $config) && is_array($config['jwks'])) {
            $this->jwks = $config['jwks'];
        }
    }

    public function getConfigurationUri(string $p): string
    {
        $uri = $this->applyCustomDomain(sprintf(self::$CONFIGURATION_URI_FORMAT, $this->tenant, $this->tenant));
        $query = [
            'p' => $p,
        ];

        return $uri . '?' . Query::build($query);
    }

    public function loadOpenIdConfiguration(string $flow): Configuration
    {
        $response = $this->client->get($this->getConfigurationUri($flow), ['query' => ['p' => $flow]]);
        if ($response->getStatusCode() !== 200) {
            throw new ResponseErrorException('Could not get configuration', $response->getStatusCode());
        }

        $json = json_decode((string)$response->getBody(), true);
        $this->configurations[$flow] = new Configuration($json);
        
        return $this->configurations[$flow];
    }

    public function setOpenIdConfiguration(string $flow, Configuration $config)
    {
        $this->configurations[$flow] = $config;
    }

    public function getAuthorizationEndpoint(
        string $flow,
        string $redirectUri,
        string $scope, 
        $nonce, 
        string $responseMode = 'form_post', 
        string $responseType = 'code id_token',
        string $state = null
    ): string
    {
        if (array_key_exists($flow, $this->configurations) !== true) {
            throw new InternalErrorException('Configuration not complete');
        }

        $authorizationEndpoint = $this->applyCustomDomain($this->configurations[$flow]->authorizationEndpoint);
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

    public function getEndSessionEndpoint(string $flow): string
    {
        if (array_key_exists($flow, $this->configurations) !== true) {
            throw new InternalErrorException('Configuration not complete');
        }

        return $this->applyCustomDomain($this->configurations[$flow]->endSessionEndpoint);
    }

    public function getJWKs(string $flow): array
    {
        if (is_array($this->jwks) && array_key_exists($flow, $this->jwks)) {
            return $this->jwks[$flow];
        }

        if (array_key_exists($flow, $this->configurations) !== true) {
            throw new InternalErrorException('Configuration not complete');
        }
        $response = $this->client->get($this->configurations[$flow]->jwksUri);
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

        $this->jwks[$flow] = $jwks['keys'];
        
        return $this->jwks[$flow];
    }

    public function getAccessToken(
        string $flow,
        string $code, 
        string $scope,
        string $redirect_url,
        string $grant_type = 'authorization_code'): AccessToken
    {
        if (array_key_exists($flow, $this->configurations) !== true) {
            throw new InternalErrorException('Configuration not complete');
        }

        $response = $this->client->post(
            $this->configurations[$flow]->tokenEndpoint, 
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

        $claims = $this->verifyToken($accessToken->accessToken, $flow);

        $accessToken->setClaims($claims, $this->claims_config);

        return $accessToken;
    }

    public function tokenRefresh(
        string $flow,
        string $refreshToken,
        string $redirect_url): AccessToken
    {
        if (array_key_exists($flow, $this->configurations) !== true) {
            throw new InternalErrorException('Configuration not complete');
        }

        $response = $this->client->post(
            $this->configurations[$flow]->tokenEndpoint,
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

        $claims = $this->verifyToken($accessToken->accessToken, $flow);
        $accessToken->setClaims($claims);

        return $accessToken;
    }

    public function verifyToken(string $token, string $flow): array
    {
        try {
            return $this->jwt->decodeJWK($token, $this->getJWKs($flow));
        } catch (\Exception $e) {
            throw new VerificationError($e->getMessage());
        }
    }

    public function applyCustomDomain(string $url): string
    {
        if ($this->customDomain === null) {
            return $url;
        }

        $host = parse_url($url, PHP_URL_HOST);
        return str_replace($host, $this->customDomain, $url);
    }
}

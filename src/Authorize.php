<?php
declare(strict_types=1);

namespace kaz29\AzureADB2C;

use GuzzleHttp\Client;
use kaz29\AzureADB2C\Entity\Configuration;
use kaz29\AzureADB2C\Exception\ResponseErrorException;
use function GuzzleHttp\Psr7\build_query;

/**
 * Authorize class
 *
 * @property \GuzzleHttp\Client $client
 * @property string $tenant
 * @property string $client_id
 * @property string $client_secret
 * @property \kaz29\AzureADB2C\Entity\Configuration $configuration
 */
class Authorize {
    protected static $CONFIGRATION_URI_FORMAT='https://%s.b2clogin.com/%s.onmicrosoft.com/v2.0/.well-known/openid-configuration';

    protected $client;
    protected $tenant;
    protected $client_id;
    protected $client_secret;
    protected $configuration;

    public function __construct(Client $client, string $tenant, string $client_id, string $client_secret)
    {
        $this->client = $client;
        $this->tenant = $tenant;
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
    }

    public function getConfigurationUri(string $p): string
    {
        $uri = sprintf(self::$CONFIGRATION_URI_FORMAT, $this->tenant, $this->tenant);
        $query = [
            'p' => $p,
        ];

        return $uri . '?' . build_query($query);
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
}

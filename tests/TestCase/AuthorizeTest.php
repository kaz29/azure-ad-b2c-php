<?php
declare(strict_types=1);

namespace kaz29\AzureADB2C\Test;

use GuzzleHttp\Client;
use kaz29\AzureADB2C\Authorize;
use kaz29\AzureADB2C\Entity\Configuration;
use PHPUnit\Framework\TestCase;

use function GuzzleHttp\Psr7\build_query;

class AuthorizeTest extends TestCase
{

    public function testLoadConfiguration()
    {
        /**
         * @var Client $client
         */
        $client = $this->getMockBuilder(Client::class)
            ->setMethods(['get'])
            ->getMock();
        $response = new class() {
            public function getStatusCode()
            {
                return 200;
            }

            public function getBody()
            {
                return file_get_contents(TEST_DATA . DIRECTORY_SEPARATOR . 'configuration_response.json');
            }
        };
        $client->expects($this->once())
            ->method('get')
            ->with(
                $this->equalTo('https://azadb2cresr.b2clogin.com/azadb2cresr.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=B2C_1_normalsignupsignin'),
                $this->equalTo(['query' => ['p' => 'B2C_1_normalsignupsignin']])
            )
            ->willReturn($response);

        $authotize = new Authorize($client, 'azadb2cresr', '', '');
        $config = $authotize->loadOpenIdConfiguration('B2C_1_normalsignupsignin');
        $this->assertEquals(
            'https://azadb2cresr.b2clogin.com/azadb2cresr.onmicrosoft.com/discovery/v2.0/keys?p=b2c_1_normalsignupsignin', 
            $config->jwksUri
        );
        $this->assertEquals(
            'https://azadb2cresr.b2clogin.com/azadb2cresr.onmicrosoft.com/oauth2/v2.0/token?p=b2c_1_normalsignupsignin', 
            $config->tokenEndpoint
        );
    }

    public function testAuthorizationEndpoint()
    {
        $client = new Client();
        $authotize = new Authorize($client, 'azadb2cresr', 'dummy_client_id', 'dummy_client_secret');
        $authotize->setOpenIdConfiguration(new Configuration([
            'authorization_endpoint' => 'https://example.com/authorization',
        ]));
        $result = $authotize->getAuthorizationEndpoint(
            'B2C_1_normalsignupsignin',
            'https://example.com/oauth/callback',
            'https://azadb2cresr.onmicrosoft.com/api openid offline_access',
            12345
        );

        $expected = 'https://example.com/authorization?' .
            build_query([
                'p' => 'B2C_1_normalsignupsignin',
                'client_id' => 'dummy_client_id',
                'redirect_uri' => 'https://example.com/oauth/callback',
                'scope' => 'https://azadb2cresr.onmicrosoft.com/api openid offline_access',
                'response_type' => 'code id_token',
                'response_mode' => 'form_post',
                'nonce' => 12345,
            ]
        );
        $this->assertEquals($expected, $result);
    }
}
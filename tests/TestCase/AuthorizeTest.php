<?php
declare(strict_types=1);

namespace kaz29\AzureADB2C\Test;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Query;
use kaz29\AzureADB2C\Authorize;
use kaz29\AzureADB2C\Entity\Configuration;
use kaz29\AzureADB2C\JWT;
use PHPUnit\Framework\TestCase;

class AuthorizeTest extends TestCase
{

    public function testLoadConfiguration()
    {
        /**
         * @var Client $client
         */
        $client = $this->getMockBuilder(Client::class)
            ->addMethods(['get'])
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

        $authotize = new Authorize($client, new JWT(), ['tenant' => 'azadb2cresr']);
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
        $authorize = new Authorize($client, new JWT(), [
            'tenant' => 'azadb2cresr', 
            'client_id' => 'dummy_client_id', 
            'client_secret' => 'dummy_client_secret',
        ]);
        $authorize->setOpenIdConfiguration(new Configuration([
            'authorization_endpoint' => 'https://example.com/authorization?p=b2c_1_normalsignupsignin',
        ]));
        $result = $authorize->getAuthorizationEndpoint(
            'https://example.com/oauth/callback',
            'https://azadb2cresr.onmicrosoft.com/api openid offline_access',
            12345
        );

        $expected = 'https://example.com/authorization?p=b2c_1_normalsignupsignin&' .
            Query::build([
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

    public function testGetJwks()
    {
        $client = $this->getMockBuilder(Client::class)
            ->addMethods(['get'])
            ->getMock();
        $response = new class() {
            public function getStatusCode()
            {
                return 200;
            }

            public function getBody()
            {
                return file_get_contents(TEST_DATA . DIRECTORY_SEPARATOR . 'jwks_response.json');
            }
        };
        $client->expects($this->once())
            ->method('get')
            ->with(
                $this->equalTo('https://example.com/jwks')
            )
            ->willReturn($response);
        /**
         * @var Client $client
         */
        $authorize = new Authorize($client, new JWT(), [
            'tenant' => 'azadb2cresr', 
            'client_id' => 'dummy_client_id',
            'client_secret' => 'dummy_client_secret',
        ]);
        $authorize->setOpenIdConfiguration(new Configuration([
            'jwks_uri' => 'https://example.com/jwks',
        ]));

        $result = $authorize->getJWKs();
        $expected = [
            [
                "kid" => "dummy_kid",
                "nbf" => 1493763266,
                "use" => "sig",
                "kty" => "RSA",
                "e" => "AQAB",
                "n" => "dummy_n",
            ]
        ];
        $this->assertEquals($expected, $result);
    }

    public function testAccessToken()
    {
        /**
         * @var Client $client
         */
        $client = $this->getMockBuilder(Client::class)
            ->addMethods(['post', 'get'])
            ->getMock();
        $response = new class() {
            public function getStatusCode()
            {
                return 200;
            }

            public function getBody()
            {
                $body = new class() {
                    public function getContents() 
                    {
                        return file_get_contents(TEST_DATA . DIRECTORY_SEPARATOR . 'access_token_response.json');
                    }
                };

                return $body;
            }
        };
        $client->expects($this->once())
            ->method('post')
            ->with(
                $this->equalTo('https://example.com/token'),
                $this->equalTo([
                    'form_params' => [
                        'grant_type' => 'authorization_code',
                        'client_id' => 'dummy_client_id',
                        'scope' => 'https://example.com/api/ offline_access',
                        'code' => 'dummy_code',
                        'redirect_uri' => 'https://localhost/',
                        'client_secret' => 'dummy_client_secret',
                    ]
                ])
            )
            ->willReturn($response);
        $client->expects($this->once())
            ->method('get')
            ->with(
                $this->equalTo('https://example.com/jwks')
            )
            ->willReturn(new class() {
                public function getStatusCode()
                {
                    return 200;
                }
    
                public function getBody()
                {
                    return file_get_contents(TEST_DATA . DIRECTORY_SEPARATOR . 'jwks_response.json');
                }
            });

        $jwt = $this->getMockBuilder(JWT::class)
            ->onlyMethods(['decodeJWK'])
            ->getMock();

        $jwt->expects($this->once())
            ->method('decodeJWK')
            ->with(
                $this->equalTo('dummy_access_token'),
            )
            ->willReturn([]);

        /**
         * @var JWT $jwt
         */
        $authorize = new Authorize($client, $jwt, [
            'tenant' => 'azadb2cresr', 
            'client_id' => 'dummy_client_id', 
            'client_secret' => 'dummy_client_secret',
        ]);    
        $authorize->setOpenIdConfiguration(new Configuration([
            'token_endpoint' => 'https://example.com/token',
            'jwks_uri' => 'https://example.com/jwks',
        ]));
        $result = $authorize->getAccessToken(
            'dummy_code',
            'https://example.com/api/ offline_access',
            'https://localhost/'
        );
        $this->assertEquals('dummy_access_token', $result->accessToken);
        $this->assertEquals('Bearer', $result->tokenType);
        $this->assertEquals('dummy_refresh_access_token', $result->refreshToken);
    }
}
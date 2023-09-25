<?php
declare(strict_types=1);

namespace kaz29\AzureADB2C\Test;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\BufferStream;
use GuzzleHttp\Psr7\Query;
use kaz29\AzureADB2C\Authorize;
use kaz29\AzureADB2C\Entity\Configuration;
use kaz29\AzureADB2C\JWT;
use PHPUnit\Framework\TestCase;
use kaz29\AzureADB2C\Test\Utils\ResponseMock;

class AuthorizeTest extends TestCase
{

    public function testLoadConfiguration()
    {
        /**
         * @var Client $client
         */
        $client = $this->getMockBuilder(Client::class)
            ->onlyMethods(['get'])
            ->getMock();

        $stream = new BufferStream();
        $stream->write(file_get_contents(TEST_DATA . DIRECTORY_SEPARATOR . 'configuration_response.json'));  
        $response = new ResponseMock();
        $response
            ->withStatus(200)
            ->withBody($stream);
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
        $authorize->setOpenIdConfiguration(
            'b2c_1_normalsignupsignin',
            new Configuration([
                'authorization_endpoint' => 'https://example.com/authorization?p=b2c_1_normalsignupsignin',
            ]),
        );
        $result = $authorize->getAuthorizationEndpoint(
            'b2c_1_normalsignupsignin',
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
            ->onlyMethods(['get'])
            ->getMock();
        $stream = new BufferStream();
        $stream->write(file_get_contents(TEST_DATA . DIRECTORY_SEPARATOR . 'jwks_response.json'));  
        $response = new ResponseMock();
        $response
            ->withStatus(200)
            ->withBody($stream);
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
        $authorize->setOpenIdConfiguration(
            'b2c_1_normalsignupsignin',
            new Configuration([
                'jwks_uri' => 'https://example.com/jwks',
                'id_token_signing_alg_values_supported' => ['RS256'],
            ]),
        );

        $result = $authorize->getJWKs('b2c_1_normalsignupsignin');
        $expected = [
            [
                "kid" => "dummy_kid",
                "nbf" => 1493763266,
                "use" => "sig",
                "kty" => "RSA",
                "e" => "AQAB",
                "n" => "dummy_n",
                'alg' => 'RS256',
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
            ->onlyMethods(['post', 'get'])
            ->getMock();
        $stream = new BufferStream();
        $stream->write(file_get_contents(TEST_DATA . DIRECTORY_SEPARATOR . 'access_token_response.json'));  
        $response = new ResponseMock();
        $response
            ->withStatus(200)
            ->withBody($stream);
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

        $stream = new BufferStream();
        $stream->write(file_get_contents(TEST_DATA . DIRECTORY_SEPARATOR . 'jwks_response.json'));  
        $response = new ResponseMock();
        $response
            ->withStatus(200)
            ->withBody($stream);
        $client->expects($this->once())
            ->method('get')
            ->with(
                $this->equalTo('https://example.com/jwks')
            )
            ->willReturn($response);

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
        $authorize->setOpenIdConfiguration(
            'b2c_1_normalsignupsignin',
            new Configuration([
                'token_endpoint' => 'https://example.com/token',
                'jwks_uri' => 'https://example.com/jwks',
                'id_token_signing_alg_values_supported' => ['RS256'],
            ]),
        );
        $result = $authorize->getAccessToken(
            'b2c_1_normalsignupsignin',
            'dummy_code',
            'https://example.com/api/ offline_access',
            'https://localhost/'
        );
        $this->assertEquals('dummy_access_token', $result->accessToken);
        $this->assertEquals('Bearer', $result->tokenType);
        $this->assertEquals('dummy_refresh_access_token', $result->refreshToken);
    }

    public function testApplyCustomDomain()
    {
        /**
         * @var Client $client
         */
        $client = $this->getMockBuilder(Client::class)
            ->onlyMethods(['post', 'get'])
            ->getMock();
        /**
         * @var JWT $jwt
         */
        $jwt = $this->getMockBuilder(JWT::class)
            ->onlyMethods(['decodeJWK'])
            ->getMock();

        $authorize = new Authorize($client, $jwt, [
            'tenant' => 'azadb2cresr', 
            'client_id' => 'dummy_client_id', 
            'client_secret' => 'dummy_client_secret',
            'custom_domain' => 'example.jp',
        ]);    
        $authorize->setOpenIdConfiguration(
            'b2c_1_normalsignupsignin',
            new Configuration([
                'token_endpoint' => 'https://example.com/token',
                'jwks_uri' => 'https://example.com/jwks',
                'id_token_signing_alg_values_supported' => ['RS256'],
            ]),
        );

        $result = $authorize->applyCustomDomain('https://example.com/hoge?p=1');
        $this->assertEquals('https://example.jp/hoge?p=1', $result);
    }

    private function createMockClient(): Client
    {
         /**
         * @var Client $client
         */
        $client = $this->getMockBuilder(Client::class)
            ->onlyMethods(['post', 'get'])
            ->getMock();
        $stream = new BufferStream();
        $stream->write(file_get_contents(TEST_DATA . DIRECTORY_SEPARATOR . 'access_token_response.json'));  
        $response = new ResponseMock();
        $response
            ->withStatus(200)
            ->withBody($stream);
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

        $stream = new BufferStream();
        $stream->write(file_get_contents(TEST_DATA . DIRECTORY_SEPARATOR . 'jwks_response.json'));  
        $response = new ResponseMock();
        $response
            ->withStatus(200)
            ->withBody($stream);
        $client->expects($this->once())
            ->method('get')
            ->with(
                $this->equalTo('https://example.com/jwks')
            )
            ->willReturn($response);

        return $client;
    }

    private function getDefaultClaimsConfig(): array
    {
        return [
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
                'emails' => 'emails',
            ],
        ];
    }

    private function createMockJwt(array $payload = []): JWT
    {
        $jwt = $this->getMockBuilder(JWT::class)
            ->onlyMethods(['decodeJWK'])
            ->getMock();

        $jwt->expects($this->once())
            ->method('decodeJWK')
            ->with(
                $this->equalTo('dummy_access_token'),
            )
            ->willReturn($payload);

        /**
         * @var JWT $jwt
         */
        return $jwt;
    }

    public function GetAccessTokenTestDataProvider()
    {
        $default_payload = [
            'sub' => 'dd0b2128-7760-4495-6b2e-31eceb078ce7',
            'exp' => time() + 60 * 60 * 24,
            'nbf' => time(),
            'ver' => '1.0',
            'iss' => 'https://example.b2clogin.com/7ae4835a-3413-4498-9725-84e3fd52b1ea/v2.0/',
            'aud' => 'c84d8c55-847a-4a75-861e-ae8dae48a411',
            'nonce' => 'defaultNonce',
            'iat' => time(),
            'auth_time' => time(),
            'idp_access_token' => 'token',
            'given_name' => 'Foo',
            'family_name' => 'Bar',
            'name' => 'BarFoo',
            'idp' => 'google.com',
            'emails' => [
                'foo@example.com',
            ],
            'tfp' => 'b2c_1_normalsignupsignin',
        ];
        $default_claims_config = $this->getDefaultClaimsConfig();

        return [
            [$default_payload, null],
            [$default_payload, $default_claims_config],
            [['payload_key' => 'payload_value'], ['map' => ['payload_key' => 'claimsProperty']]],
        ];
    }

    /**
     * @dataProvider GetAccessTokenTestDataProvider
     */
    public function testGetAccessToken(array $jwt_payload, ?array $claims_config)
    {
        $mockClient = $this->createMockClient();
        $mockJwt = $this->createMockJwt($jwt_payload);

        $authorize = new Authorize($mockClient, $mockJwt, [
            'tenant' => 'azadb2cresr',
            'client_id' => 'dummy_client_id',
            'client_secret' => 'dummy_client_secret',
            'claims_config' => $claims_config
        ]);
        $authorize->setOpenIdConfiguration(
            'b2c_1_normalsignupsignin',
            new Configuration([
                'token_endpoint' => 'https://example.com/token',
                'jwks_uri' => 'https://example.com/jwks',
                'id_token_signing_alg_values_supported' => ['RS256'],
            ]),
        );

        $access_token = $authorize->getAccessToken(
            'b2c_1_normalsignupsignin',
            'dummy_code',
            'https://example.com/api/ offline_access',
            'https://localhost/'
        );
        $claims = $access_token->getClaims();
        $map = $claims_config ? $claims_config['map'] : $this->getDefaultClaimsConfig()['map'];

        foreach ($map as $payload_key => $claims_property)
        {
            $payload = array_key_exists($payload_key, $jwt_payload) ? $jwt_payload[$payload_key] : null;
            $this->assertEquals($payload, $claims->$claims_property);
        }
    }

    public function testGetConfigurationUri()
    {
        $authorize = new Authorize(new Client(), new JWT(), [
            'tenant' => 'azadb2cresr',
        ]);
        $result = $authorize->getConfigurationUri('signin');
        $this->assertEquals('https://azadb2cresr.b2clogin.com/azadb2cresr.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=signin', $result);

        $authorize = new Authorize(new Client(), new JWT(), [
            'tenant' => 'azadb2cresr',
            'custom_domain' => 'custom.example.com'
        ]);
        $result = $authorize->getConfigurationUri('signin');
        $this->assertEquals('https://custom.example.com/azadb2cresr.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=signin', $result);
    }
}

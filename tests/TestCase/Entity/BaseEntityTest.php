<?php
declare(strict_types=1);

namespace kaz29\AzureADB2C\Test\Entity;

use kaz29\AzureADB2C\Entity\BaseEntity;
use PHPUnit\Framework\TestCase;

class ValueObjectTest extends TestCase
{
    public function testSimple()
    {
        $data = [
            'string_key' => 'string data 1',
        ];
        $obj = new class($data) extends BaseEntity{};

        $this->assertEquals('string data 1', $obj->string_key);
    }

    public function testMap()
    {
        $data = [
            'string_key' => 'string data 1',
        ];
        $obj = new class($data) extends BaseEntity {
            protected $config = [
                'map' => [
                    'string_key' => 'stringKey',
                    'empty_key' => 'emptyKey',
                ],
            ];
        };

        $this->assertEquals('string data 1', $obj->stringKey);
        $this->assertNull($this->emptyKey);
    }

    public function testCouldNotUpdate()
    {
        $data = [
            'string_key' => 'string data 1',
        ];
        $obj = new class($data) extends BaseEntity{};

        $this->assertEquals('string data 1', $obj->string_key);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage("Could not update 'string_key'");
        $obj->string_key = 'foo';
    }
}

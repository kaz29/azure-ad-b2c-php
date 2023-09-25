<?php
declare(strict_types=1);

namespace kaz29\AzureADB2C\Test\Utils;

use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

class ResponseMock implements ResponseInterface
{
    protected StreamInterface $body;
    protected int $code;
    protected string $reasonPhrase;

    public function getStatusCode(): int
    {
        return $this->code;
    }

    public function getReasonPhrase(): string
    {
        return $this->reasonPhrase;
    }

    public function getBody(): StreamInterface
    {
        return $this->body;
    }

    public function getHeaders(): array
    {
        return [];
    }

    public function getHeader($name): array
    {
        return [];
    }

    public function hasHeader(string $name): bool
    {
        return true;
    }

    public function getProtocolVersion(): string
    {
        return '1.1';
    }

    public function withProtocolVersion(string $version): MessageInterface
    {
        return $this;
    }

    public function getHeaderLine(string $name): string
    {
        return '';
    }

    public function withHeader(string $name, $value): MessageInterface
    {
        return $this;
    }

    public function withAddedHeader(string $name, $value): MessageInterface
    {
        return $this;
    }

    public function withoutHeader(string $name): MessageInterface
    {
        return $this;
    }

    public function withBody(StreamInterface $body): MessageInterface
    {
        $this->body = $body;

        return $this;
    }

    public function withStatus(int $code, string $reasonPhrase = ''): ResponseInterface
    {
        $this->code = $code;
        $this->reasonPhrase = $reasonPhrase;

        return $this;
    }
}
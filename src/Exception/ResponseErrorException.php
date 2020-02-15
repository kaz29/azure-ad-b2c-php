<?php
declare(strict_types=1);

namespace kaz29\AzureADB2C\Exception;

class ResponseErrorException extends BaseException
{
    public function __construct(string $message = '', $code = 500)
    {
        parent::__construct($message, $code);
    }
}
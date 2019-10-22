<?php
declare(strict_types=1);

namespace LoyaltyCorp\EasyEntityChange\Exceptions;

use EoneoPay\Utils\Exceptions\RuntimeException;
use LoyaltyCorp\EasyEntityChange\Interfaces\EasyEntityChangeExceptionInterface;

final class InvalidDispatcherException extends RuntimeException implements EasyEntityChangeExceptionInterface
{
    /**
     * {@inheritdoc}
     */
    public function getErrorCode(): int
    {
        return self::DEFAULT_ERROR_CODE_RUNTIME + 110;
    }

    /**
     * {@inheritdoc}
     */
    public function getErrorSubCode(): int
    {
        return 1;
    }
}
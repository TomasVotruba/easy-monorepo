<?php
declare(strict_types=1);

namespace StepTheFkUp\ApiToken\Encoders;

use StepTheFkUp\ApiToken\Exceptions\InvalidArgumentException;
use StepTheFkUp\ApiToken\Exceptions\UnableToEncodeApiTokenException;
use StepTheFkUp\ApiToken\External\Interfaces\JwtDriverInterface;
use StepTheFkUp\ApiToken\Interfaces\ApiTokenEncoderInterface;
use StepTheFkUp\ApiToken\Interfaces\ApiTokenInterface;
use StepTheFkUp\ApiToken\Interfaces\Tokens\JwtApiTokenInterface;

final class JwtTokenEncoder implements ApiTokenEncoderInterface
{
    /**
     * @var \StepTheFkUp\ApiToken\External\Interfaces\JwtDriverInterface
     */
    private $jwtDriver;

    /**
     * JwtTokenEncoder constructor.
     *
     * @param \StepTheFkUp\ApiToken\External\Interfaces\JwtDriverInterface $jwtDriver
     */
    public function __construct(JwtDriverInterface $jwtDriver)
    {
        $this->jwtDriver = $jwtDriver;
    }

    /**
     * Return encoded string representation of given API token.
     *
     * @param \StepTheFkUp\ApiToken\Interfaces\ApiTokenInterface $apiToken
     *
     * @return string
     *
     * @throws \StepTheFkUp\ApiToken\Exceptions\InvalidArgumentException If encoder doesn't support given apiToken
     * @throws \StepTheFkUp\ApiToken\Exceptions\UnableToEncodeApiTokenException If encoder fails to encode apiToken
     */
    public function encode(ApiTokenInterface $apiToken): string
    {
        if (($apiToken instanceof JwtApiTokenInterface) === false) {
            throw new InvalidArgumentException(\sprintf(
                'In "%s", API token expected to be instance of "%s", "%s" given.',
                \get_class($this),
                JwtApiTokenInterface::class,
                \get_class($apiToken)
            ));
        }

        try {
            return $this->jwtDriver->encode($apiToken->getPayload());
        } catch (\Throwable $exception) {
            throw new UnableToEncodeApiTokenException(
                \sprintf(
                    'In "%s", unable to encode token. Reason: %s',
                    \get_class($this),
                    $exception->getMessage()
                ),
                $exception->getCode(),
                $exception
            );
        }
    }
}

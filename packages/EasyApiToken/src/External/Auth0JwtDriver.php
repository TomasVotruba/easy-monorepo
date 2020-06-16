<?php

declare(strict_types=1);

namespace EonX\EasyApiToken\External;

use Auth0\SDK\Helpers\JWKFetcher;
use Auth0\SDK\Helpers\Tokens\AsymmetricVerifier;
use Auth0\SDK\Helpers\Tokens\SignatureVerifier;
use Auth0\SDK\Helpers\Tokens\SymmetricVerifier;
use EonX\EasyApiToken\External\Auth0\TokenGenerator;
use EonX\EasyApiToken\External\Auth0\TokenVerifier;
use EonX\EasyApiToken\External\Interfaces\JwtDriverInterface;
use Psr\SimpleCache\CacheInterface;

final class Auth0JwtDriver implements JwtDriverInterface
{
    /**
     * @var string
     */
    private $allowedAlgo;

    /**
     * @var string
     */
    private $audienceForEncode;

    /**
     * @var string[]
     */
    private $authorizedIss;

    /**
     * @var null|\Psr\SimpleCache\CacheInterface
     */
    private $cache;

    /**
     * @var null|int
     */
    private $leeway;

    /**
     * @var null|string|resource
     */
    private $privateKey;

    /**
     * @var string[]
     */
    private $validAudiences;

    /**
     * Auth0JwtDriver constructor.
     *
     * @param string[] $validAudiences
     * @param string[] $authorizedIss
     * @param null|string|resource $privateKey
     * @param null|string[] $allowedAlgos
     */
    public function __construct(
        array $validAudiences,
        array $authorizedIss,
        $privateKey = null,
        ?string $audienceForEncode = null,
        $allowedAlgo = null,
        ?CacheInterface $cache = null,
        ?int $leeway = null
    ) {
        $this->validAudiences = $validAudiences;
        $this->authorizedIss = $authorizedIss;
        $this->privateKey = $privateKey;
        $this->audienceForEncode = $audienceForEncode ?? (string)\reset($validAudiences);
        $this->cache = $cache;
        $this->leeway = $leeway;

        $this->setAllowedAlgo($allowedAlgo ?? 'HS256');
    }

    public function decode(string $token)
    {
        $tokenVerifier = new TokenVerifier($this->validAudiences, $this->authorizedIss, $this->getSignatureVerifier());

        if ($this->leeway !== null) {
            $tokenVerifier->setLeeway($this->leeway);
        }

        return $tokenVerifier->verify($token);
    }

    /**
     * @param mixed[] $input
     */
    public function encode($input): string
    {
        /** @var string $privateKey */
        $privateKey = $this->privateKey;

        $generator = new TokenGenerator($this->audienceForEncode, $privateKey);

        return $generator->generate(
            $input['scopes'] ?? [],
            $input['roles'] ?? [],
            $input['sub'] ?? null,
            $input['lifetime'] ?? null
        );
    }

    private function getSignatureVerifier(): SignatureVerifier
    {
        if ($this->allowedAlgo === 'HS256') {
            return new SymmetricVerifier($this->privateKey);
        }

        return new AsymmetricVerifier(new JWKFetcher($this->cache));
    }

    /**
     * @param string|string[] $allowedAlgo
     */
    private function setAllowedAlgo($allowedAlgo): void
    {
        if (\is_array($allowedAlgo) === false) {
            $this->allowedAlgo = (string)$allowedAlgo;

            return;
        }

        @\trigger_error(\sprintf(
            'Passing $allowedAlgo to %s as an array is deprecated since 2.5 and will be removed in 3.0. 
                   Pass string instead.',
            self::class
        ));

        $this->allowedAlgo = \reset($allowedAlgo);
    }
}

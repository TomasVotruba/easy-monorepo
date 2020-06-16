<?php
declare(strict_types=1);

namespace EonX\EasyApiToken\External\Auth0;

use Auth0\SDK\Exception\InvalidTokenException;
use Auth0\SDK\Helpers\Tokens\SignatureVerifier;
use Auth0\SDK\Helpers\Tokens\TokenVerifier as BaseTokenVerifier;

/**
 * Overrides Auth0 TokenVerifier as for now they don't support multiple audiences.
 */
final class TokenVerifier extends BaseTokenVerifier
{
    /**
     * @var string[]
     */
    private $audiences;

    /**
     * @var string[]
     */
    private $issuers;

    /**
     * @var \Auth0\SDK\Helpers\Tokens\SignatureVerifier
     */
    private $verifier;

    /**
     * @param string[] $audiences
     * @param string[] $issuers
     */
    public function __construct(array $audiences, array $issuers, SignatureVerifier $verifier)
    {
        $this->audiences = $audiences;
        $this->issuers = $issuers;
        $this->verifier = $verifier;

        parent::__construct('', '', $verifier);
    }

    public function verify(string $token, ?array $options = null): array
    {
        if (empty($token)) {
            throw new InvalidTokenException('ID token is required but missing');
        }

        $verifiedToken = $this->verifier->verifyAndDecode($token);

        /*
         * Issuer checks
         */

        $tokenIss = $verifiedToken->getClaim('iss', false);
        if (!$tokenIss || !is_string($tokenIss)) {
            throw new InvalidTokenException('Issuer (iss) claim must be a string present in the ID token');
        }

        if ($tokenIss !== $this->issuer) {
            throw new InvalidTokenException(sprintf(
                'Issuer (iss) claim mismatch in the ID token; expected "%s", found "%s"', $this->issuer, $tokenIss
            ));
        }

        /*
         * Audience checks
         */

        $tokenAud = $verifiedToken->getClaim('aud', false);
        if (!$tokenAud || (!is_string($tokenAud) && !is_array($tokenAud))) {
            throw new InvalidTokenException(
                'Audience (aud) claim must be a string or array of strings present in the ID token'
            );
        }

        if (is_array($tokenAud) && !in_array($this->audience, $tokenAud)) {
            throw new InvalidTokenException(sprintf(
                'Audience (aud) claim mismatch in the ID token; expected "%s" was not one of "%s"',
                $this->audience,
                implode(', ', $tokenAud)
            ));
        } else {
            if (is_string($tokenAud) && $tokenAud !== $this->audience) {
                throw new InvalidTokenException(sprintf(
                    'Audience (aud) claim mismatch in the ID token; expected "%s", found "%s"', $this->audience,
                    $tokenAud
                ));
            }
        }

        /*
         * Clock checks
         */

        $options = $options ?? [];
        $now = $options['time'] ?? time();
        $leeway = $options['leeway'] ?? $this->leeway;

        $tokenExp = $verifiedToken->getClaim('exp', false);
        if (!$tokenExp || !is_int($tokenExp)) {
            throw new InvalidTokenException('Expiration Time (exp) claim must be a number present in the ID token');
        }

        $expireTime = $tokenExp + $leeway;
        if ($now > $expireTime) {
            throw new InvalidTokenException(sprintf(
                'Expiration Time (exp) claim error in the ID token; current time (%d) is after expiration time (%d)',
                $now,
                $expireTime
            ));
        }

        $profile = [];
        foreach ($verifiedToken->getClaims() as $claim => $value) {
            $profile[$claim] = $value->getValue();
        }

        return $profile;
    }
}

<?php

declare(strict_types=1);

namespace EonX\EasyApiToken\External\Auth0;

use Auth0\SDK\Helpers\Tokens\SymmetricVerifier;
use EonX\EasyApiToken\External\Auth0\Interfaces\TokenGeneratorInterface;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key;

final class TokenGenerator implements TokenGeneratorInterface
{
    /**
     * Audience for the ID token.
     *
     * @var string|null
     */
    private $audience;

    /**
     * Secret used to encode the token.
     *
     * @var string|null
     */
    private $secret;

    public function __construct(?string $audience = null, ?string $secret = null)
    {
        $this->audience = $audience;
        $this->secret = $secret;
    }

    /**
     * @param mixed[] $scopes
     * @param null|mixed[] $roles
     */
    public function generate(
        array $scopes,
        ?array $roles = null,
        ?string $subject = null,
        ?int $lifetime = null,
        ?bool $secretEncoded = null
    ): string {
        $secretEncoded = $secretEncoded ?? true;
        $lifetime = $lifetime ?? 3600;
        $time = \time();

        $payload = [
            'iat' => $time,
            'scopes' => $scopes,
            'exp' => $time + $lifetime,
            'aud' => $this->audience,
        ];

        $builder = (new Builder())
            ->permittedFor($this->audience)
            ->expiresAt($time + $lifetime)
            ->issuedAt($time)
            ->withClaim('scopes', $scopes);

        if ($subject !== null) {
            $builder->relatedTo($subject);
        }

        if ($roles !== null) {
            foreach ($roles as $key => $value) {
                $builder->withClaim($key, $value);
            }
        }

        $key = new Key($this->getSecret($secretEncoded));
        $signer = new Sha256();
        $token = $builder->getToken($signer, $key);

//        $builder->identifiedBy(\md5((string)\json_encode($payload)));

        \var_dump($token->verify($signer, $this->getSecret($secretEncoded)));
        \var_dump((string)$token);

        return (string)$token;
    }

    private function getSecret(bool $secretEncoded): string
    {
        if ($secretEncoded === false) {
            return $this->secret;
        }

        return \base64_decode(\strtr((string)$this->secret, '-_', '+/'), true);
    }
}

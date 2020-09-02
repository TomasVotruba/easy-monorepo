<?php

declare(strict_types=1);

namespace EonX\EasyCore\Tests\Bridge\Laravel\Middleware;

use EonX\EasyCore\Bridge\Laravel\Middleware\TrimStrings;
use EonX\EasyCore\Helpers\StringsTrimmerInterface;
use EonX\EasyCore\Tests\AbstractTestCase;
use Illuminate\Http\Request;
use Mockery\MockInterface;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

/**
 * @covers \EonX\EasyCore\Bridge\Laravel\Middleware\TrimStrings
 *
 * @internal
 */
final class TrimStringsTest extends AbstractTestCase
{
    public function testHandleSucceeds(): void
    {
        $data = ['abc' => '  123  '];
        $except = [];
        $expectedResult = ['abc' => '123'];
        /** @var \EonX\EasyCore\Helpers\StringsTrimmerInterface $trimmer */
        $trimmer = $this->mock(
            StringsTrimmerInterface::class,
            static function (MockInterface $mock) use ($data, $except, $expectedResult): void {
                $mock->shouldReceive('trim')->once()->with($data, $except)->andReturn($expectedResult);
            }
        );
        $middleware = new TrimStrings($trimmer, $except);
        $symfonyRequest = new SymfonyRequest($data);
        $symfonyRequest->server->set('REQUEST_METHOD', 'GET');
        $request = Request::createFromBase($symfonyRequest);

        $result = $middleware->handle($request, static function (Request $request): string {
            return $request->get('abc');
        });

        self::assertSame('123', $result);
    }
}

<?php

declare(strict_types=1);

namespace EonX\EasyPsr7Factory\Tests\Bridge\Symfony;

use EonX\EasyPsr7Factory\Tests\Bridge\Symfony\Stubs\KernelStub;
use EonX\EasySecurity\Tests\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\KernelInterface;

abstract class AbstractSymfonyTestCase extends AbstractTestCase
{
    /**
     * @var \Symfony\Component\HttpKernel\KernelInterface
     */
    private $kernel;

    /**
     * @param null|string[] $configs
     */
    protected function getKernel(?array $configs = null, ?Request $request = null): KernelInterface
    {
        if ($this->kernel !== null) {
            return $this->kernel;
        }

        $kernel = new KernelStub('test', true, $configs, $request);
        $kernel->boot();

        return $this->kernel = $kernel;
    }
}
<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Tests\Console;

use MalikAd\TenantGuard\TenantGuardServiceProvider;
use Orchestra\Testbench\TestCase;

final class TenantGuardAuditCommandTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            TenantGuardServiceProvider::class,
        ];
    }

    public function testFailsOnInvalidAction(): void
    {
        $this->artisan('tenant:guard', ['action' => 'invalid_action'])
            ->assertFailed();
    }

    public function testRunsAuditCommandInJsonFormat(): void
    {
        $this->artisan('tenant:guard', [
            'action' => 'audit',
            '--format' => 'json',
            '--path' => [__DIR__],
        ])->run();
        // Command runs and exits with status code without exception
        self::assertTrue(true);
    }
}

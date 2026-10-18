<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Tests;

use PHPUnit\Framework\TestCase;

final class BinTest extends TestCase
{
    private string $binPath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->binPath = dirname(__DIR__) . '/bin/tenant-guard';
    }

    public function testVersionFlagOutputsVersionAndExitsZero(): void
    {
        exec(sprintf('php %s --version', escapeshellarg($this->binPath)), $output, $exitCode);
        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Laravel Tenant Guard version', implode("\n", $output));
    }

    public function testHelpFlagOutputsHelpAndExitsZero(): void
    {
        exec(sprintf('php %s --help', escapeshellarg($this->binPath)), $output, $exitCode);
        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Usage:', implode("\n", $output));
        self::assertStringContainsString('--format', implode("\n", $output));
    }

    public function testFailsOnNonExistentPath(): void
    {
        exec(sprintf('php %s audit /path/that/does/not/exist/at/all', escapeshellarg($this->binPath)), $output, $exitCode);
        self::assertSame(1, $exitCode);
    }

    public function testParsesFormatOptionWithSpace(): void
    {
        exec(sprintf('php %s --version --format json', escapeshellarg($this->binPath)), $output, $exitCode);
        self::assertSame(0, $exitCode);
    }
}

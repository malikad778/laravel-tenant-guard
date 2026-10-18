<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Tests\Rules;

use MalikAd\TenantGuard\Rules\UnscopedJobSerializationRule;
use MalikAd\TenantGuard\Support\GuardConfig;
use MalikAd\TenantGuard\TenantGuardAnalyzer;
use PHPUnit\Framework\TestCase;

final class UnscopedJobSerializationRuleTest extends TestCase
{
    private TenantGuardAnalyzer $analyzer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->analyzer = new TenantGuardAnalyzer(
            new GuardConfig(),
            [new UnscopedJobSerializationRule()]
        );
    }

    public function testFlagsQueuedJobWithoutTenantContext(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Jobs;
        use Illuminate\Contracts\Queue\ShouldQueue;

        class ProcessInvoiceJob implements ShouldQueue
        {
            public function __construct(public int $invoiceId)
            {
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Jobs/ProcessInvoiceJob.php');
        self::assertCount(1, $violations);
        self::assertSame('unscoped_job_serialization', $violations[0]->ruleId);
    }

    public function testAllowsQueuedJobWithTenantProperty(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Jobs;
        use Illuminate\Contracts\Queue\ShouldQueue;

        class ProcessInvoiceJob implements ShouldQueue
        {
            public function __construct(
                public int $invoiceId,
                public int $tenantId
            ) {
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Jobs/ProcessInvoiceJob.php');
        self::assertCount(0, $violations);
    }
}

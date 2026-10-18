<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Tests\Support;

use MalikAd\TenantGuard\Support\GuardConfig;
use MalikAd\TenantGuard\TenantGuardAnalyzer;
use PHPUnit\Framework\TestCase;

final class DocblockInspectorTest extends TestCase
{
    private TenantGuardAnalyzer $analyzer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->analyzer = new TenantGuardAnalyzer(new GuardConfig());
    }

    public function testCommentSilencesOnlyAnnotatedStatement(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\DB;

        class TestService
        {
            public function run()
            {
                /** @tenant-safe */
                DB::table('invoices')->get();

                // Unannotated statement on the next line must be flagged!
                DB::table('invoices')->get();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/TestService.php');
        self::assertCount(1, $violations);
        self::assertSame(13, $violations[0]->line);
    }

    public function testStringLiteralContainingAnnotationDoesNotSilenceNextStatement(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\DB;

        class TestService
        {
            public function run()
            {
                $doc = 'see @tenant-safe docs';
                DB::table('invoices')->get();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/TestService.php');
        self::assertCount(1, $violations);
        self::assertSame(10, $violations[0]->line);
    }

    public function testClassDocblockDoesNotSilenceMethodsInside(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\DB;

        /**
         * @tenant-safe
         */
        class GlobalService
        {
            public function run()
            {
                DB::table('invoices')->get();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/GlobalService.php');
        self::assertCount(1, $violations);
        self::assertSame(12, $violations[0]->line);
    }

    public function testSupportsTenantGuardIgnoreAlias(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\DB;

        class TestService
        {
            public function run()
            {
                /** @tenant-guard-ignore */
                DB::table('invoices')->get();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/TestService.php');
        self::assertCount(0, $violations);
    }
}

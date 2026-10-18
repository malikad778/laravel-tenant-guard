<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Tests\Rules;

use MalikAd\TenantGuard\Rules\UnscopedDatabaseQueryRule;
use MalikAd\TenantGuard\Support\GuardConfig;
use MalikAd\TenantGuard\TenantGuardAnalyzer;
use PHPUnit\Framework\TestCase;

final class UnscopedDatabaseQueryRuleTest extends TestCase
{
    private TenantGuardAnalyzer $analyzer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->analyzer = new TenantGuardAnalyzer(
            new GuardConfig(),
            [new UnscopedDatabaseQueryRule()]
        );
    }

    public function testFlagsRawDbInsertUpdateDelete(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\DB;

        class OrderService
        {
            public function process()
            {
                DB::insert("INSERT INTO orders (title) VALUES ('Order 1')");
                DB::update("UPDATE invoices SET status = 'paid'");
                DB::delete("DELETE FROM invoices WHERE status = 'draft'");
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/OrderService.php');
        self::assertCount(3, $violations);
        self::assertSame(9, $violations[0]->line);
        self::assertSame(10, $violations[1]->line);
        self::assertSame(11, $violations[2]->line);
    }

    public function testFlagsChainedDbConnectionTable(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\DB;

        class InvoiceService
        {
            public function run()
            {
                return DB::connection('mysql')->table('invoices')->get();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/InvoiceService.php');
        self::assertCount(1, $violations);
        self::assertSame(9, $violations[0]->line);
    }

    public function testDoesNotAcceptSqlCommentsAsTenantColumns(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\DB;

        class ReportService
        {
            public function run()
            {
                // company_id is inside a SQL comment, not a real WHERE clause!
                return DB::select("SELECT * FROM invoices WHERE status = 'active' -- filter by company_id later");
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/ReportService.php');
        self::assertCount(1, $violations);
    }

    public function testRejectsNegativeComparisonOperators(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\DB;

        class InvoiceService
        {
            public function run(int $companyId)
            {
                // != is not positive isolation!
                return DB::table('invoices')->where('company_id', '!=', $companyId)->get();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/InvoiceService.php');
        self::assertCount(1, $violations);
    }

    public function testRejectsUnrelatedModelInWhereBelongsTo(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\DB;

        class InvoiceService
        {
            public function run($category)
            {
                return DB::table('invoices')->whereBelongsTo($category)->get();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/InvoiceService.php');
        self::assertCount(1, $violations);
    }

    public function testAllowsTenantModelInWhereBelongsTo(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\DB;

        class InvoiceService
        {
            public function run($tenant)
            {
                return DB::table('invoices')->whereBelongsTo($tenant)->get();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/InvoiceService.php');
        self::assertCount(0, $violations);
    }

    public function testAllowsSoftDeletesScopeRemoval(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use App\Models\Invoice;
        use Illuminate\Database\Eloquent\SoftDeletingScope;

        class InvoiceService
        {
            public function run()
            {
                return Invoice::withoutGlobalScopes([SoftDeletingScope::class])->get();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/InvoiceService.php');
        self::assertCount(0, $violations);
    }

    public function testRecognizesQueryScopedInLocalVariable(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\DB;

        class InvoiceService
        {
            public function run(int $companyId)
            {
                $query = DB::table('invoices');
                $query->where('company_id', $companyId);
                return $query->get();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/InvoiceService.php');
        self::assertCount(0, $violations);
    }
}

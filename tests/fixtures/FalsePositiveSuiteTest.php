<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Tests\Fixtures;

use MalikAd\TenantGuard\Support\GuardConfig;
use MalikAd\TenantGuard\TenantGuardAnalyzer;
use PHPUnit\Framework\TestCase;

final class FalsePositiveSuiteTest extends TestCase
{
    private TenantGuardAnalyzer $analyzer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->analyzer = new TenantGuardAnalyzer(new GuardConfig());
    }

    public function testTenantDiskDoesNotTriggerViolation(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\Storage;

        class ExportService
        {
            public function export()
            {
                Storage::disk('tenant')->put('reports/monthly.pdf', 'data');
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/ExportService.php');
        self::assertCount(0, $violations);
    }

    public function testTenantCacheStoreDoesNotTriggerViolation(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\Cache;

        class MetricsService
        {
            public function metrics()
            {
                return Cache::store('tenant')->remember('summary', 3600, fn () => [1, 2, 3]);
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/MetricsService.php');
        self::assertCount(0, $violations);
    }

    public function testStandaloneStorageDiskDoesNotTriggerViolation(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\Storage;

        class DiskService
        {
            public function getDisk()
            {
                $d = Storage::disk('s3');
                return $d;
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/DiskService.php');
        self::assertCount(0, $violations);
    }

    public function testPublicStorageUrlDoesNotTriggerViolation(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\Storage;

        class AssetService
        {
            public function logo()
            {
                return Storage::url('branding/logo.png');
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/AssetService.php');
        self::assertCount(0, $violations);
    }

    public function testFilamentSoftDeletesDocumentationSnippet(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Filament\Resources;
        use App\Models\Invoice;
        use Filament\Resources\Resource;
        use Illuminate\Database\Eloquent\Builder;
        use Illuminate\Database\Eloquent\SoftDeletingScope;

        class InvoiceResource extends Resource
        {
            protected static ?string $model = Invoice::class;
            protected static ?string $tenantOwnershipRelationshipName = 'company';

            public static function getEloquentQuery(): Builder
            {
                return parent::getEloquentQuery()->withoutGlobalScopes([
                    SoftDeletingScope::class,
                ]);
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Filament/Resources/InvoiceResource.php');
        self::assertCount(0, $violations);
    }

    public function testEloquentModelWithGlobalTenantScope(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use App\Models\Invoice;

        class QueryService
        {
            public function list()
            {
                return Invoice::where('status', 'paid')->get();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/QueryService.php');
        self::assertCount(0, $violations);
    }

    public function testQueryAssignedToVariableAndSubsequentlyScoped(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\DB;

        class InvoiceService
        {
            public function list(int $companyId)
            {
                $q = DB::table('invoices');
                $q->where('company_id', $companyId);
                return $q->get();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/InvoiceService.php');
        self::assertCount(0, $violations);
    }

    public function testCacheKeyAssignedToVariable(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\Cache;

        class CacheService
        {
            public function fetch(int $tenantId)
            {
                $key = 'tenant:' . $tenantId . ':metrics';
                return Cache::get($key);
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/CacheService.php');
        self::assertCount(0, $violations);
    }
}

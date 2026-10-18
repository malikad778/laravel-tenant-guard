<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Tests;

use MalikAd\TenantGuard\Support\GuardConfig;
use MalikAd\TenantGuard\TenantGuardAnalyzer;
use PHPUnit\Framework\TestCase;

final class TenantGuardAnalyzerTest extends TestCase
{
    private TenantGuardAnalyzer $analyzer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->analyzer = new TenantGuardAnalyzer(new GuardConfig());
    }

    public function testFlagsUnscopedDbTableCall(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Http\Controllers;
        use Illuminate\Support\Facades\DB;

        class InvoiceController
        {
            public function index()
            {
                return DB::table('invoices')->where('status', 'paid')->get();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Http/Controllers/InvoiceController.php');

        self::assertCount(1, $violations);
        self::assertSame('unscoped_database_query', $violations[0]->ruleId);
        self::assertSame(9, $violations[0]->line);
    }

    public function testAllowsScopedDbTableCallWithCompanyId(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Http\Controllers;
        use Illuminate\Support\Facades\DB;

        class InvoiceController
        {
            public function index(int $companyId)
            {
                return DB::table('invoices')
                    ->where('status', 'paid')
                    ->where('company_id', $companyId)
                    ->get();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Http/Controllers/InvoiceController.php');

        self::assertCount(0, $violations);
    }

    public function testFlagsWithoutGlobalScopesWithoutExplicitTenantWhere(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use App\Models\Invoice;

        class BillingService
        {
            public function exportAll()
            {
                return Invoice::withoutGlobalScopes()->where('status', 'paid')->get();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/BillingService.php');

        self::assertCount(1, $violations);
        self::assertSame('unscoped_database_query', $violations[0]->ruleId);
    }

    public function testRespectsTenantSafeDocblockAnnotation(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\DB;

        class SystemReportService
        {
            public function countAllInvoices(): int
            {
                /** @tenant-safe */
                return DB::table('invoices')->count();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/SystemReportService.php');

        self::assertCount(0, $violations);
    }

    public function testFlagsUnscopedRuleUniqueCall(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Http\Requests;
        use Illuminate\Validation\Rule;

        class StoreUserRequest
        {
            public function rules(): array
            {
                return [
                    'email' => ['required', 'email', Rule::unique('users', 'email')],
                ];
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Http/Requests/StoreUserRequest.php');

        self::assertCount(1, $violations);
        self::assertSame('unscoped_validation', $violations[0]->ruleId);
        self::assertSame(10, $violations[0]->line);
    }

    public function testAllowsScopedRuleUniqueCallWithDirectWhereAndClosureWhere(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Http\Requests;
        use Illuminate\Validation\Rule;

        class StoreUserRequest
        {
            public function rules(int $companyId): array
            {
                return [
                    'email' => [
                        'required',
                        Rule::unique('users', 'email')->where('company_id', $companyId),
                    ],
                    'code' => [
                        'required',
                        Rule::unique('invoices', 'code')->where(fn ($query) => $query->where('company_id', $companyId)),
                    ],
                ];
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Http/Requests/StoreUserRequest.php');

        self::assertCount(0, $violations);
    }

    public function testFlagsStringUniqueValidationWithoutTenantColumn(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Http\Requests;

        class RegisterMemberRequest
        {
            public function rules(): array
            {
                return [
                    'email' => 'required|email|unique:users,email',
                ];
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Http/Requests/RegisterMemberRequest.php');

        self::assertCount(1, $violations);
        self::assertSame('unscoped_validation', $violations[0]->ruleId);
    }

    public function testFlagsHardcodedCacheKeyCollision(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Http\Controllers;
        use Illuminate\Support\Facades\Cache;

        class DashboardController
        {
            public function stats()
            {
                return Cache::remember('dashboard_metrics', 60, fn () => []);
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Http/Controllers/DashboardController.php');

        self::assertCount(1, $violations);
        self::assertSame('tenant_cache_collision', $violations[0]->ruleId);
        self::assertSame(9, $violations[0]->line);
    }

    public function testAllowsTenantPrefixedCacheKeyAndStoragePath(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Http\Controllers;
        use Illuminate\Support\Facades\Cache;
        use Illuminate\Support\Facades\Storage;

        class DashboardController
        {
            public function stats(int $tenantId)
            {
                Storage::disk('s3')->put("tenants/{$tenantId}/exports/metrics.json", '{}');
                return Cache::remember('tenant:' . tenant('id') . ':dashboard_metrics', 60, fn () => []);
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Http/Controllers/DashboardController.php');

        self::assertCount(0, $violations);
    }

    public function testFlagsFilamentResourceMissingOwnershipRelationshipAndUnsafeQuery(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Filament\Resources;
        use App\Models\Invoice;
        use Filament\Resources\Resource;
        use Illuminate\Database\Eloquent\Builder;

        class InvoiceResource extends Resource
        {
            protected static ?string $model = Invoice::class;

            public static function getEloquentQuery(): Builder
            {
                return parent::getEloquentQuery()->withoutGlobalScopes();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Filament/Resources/InvoiceResource.php');

        self::assertCount(2, $violations);
        self::assertSame('filament_resource_tenant', $violations[0]->ruleId);
        self::assertSame('filament_resource_tenant', $violations[1]->ruleId);
    }

    public function testAllowsProperlyConfiguredFilamentResource(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Filament\Resources;
        use App\Models\Invoice;
        use Filament\Resources\Resource;
        use Illuminate\Database\Eloquent\Builder;

        class InvoiceResource extends Resource
        {
            protected static ?string $model = Invoice::class;

            protected static ?string $tenantOwnershipRelationshipName = 'company';

            public static function getEloquentQuery(): Builder
            {
                return parent::getEloquentQuery()->where('status', 'active');
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Filament/Resources/InvoiceResource.php');

        self::assertCount(0, $violations);
    }
}

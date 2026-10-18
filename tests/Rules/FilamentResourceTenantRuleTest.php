<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Tests\Rules;

use MalikAd\TenantGuard\Rules\FilamentResourceTenantRule;
use MalikAd\TenantGuard\Support\GuardConfig;
use MalikAd\TenantGuard\TenantGuardAnalyzer;
use PHPUnit\Framework\TestCase;

final class FilamentResourceTenantRuleTest extends TestCase
{
    private TenantGuardAnalyzer $analyzer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->analyzer = new TenantGuardAnalyzer(
            new GuardConfig(),
            [new FilamentResourceTenantRule()]
        );
    }

    public function testIgnoresLaravelNovaResources(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Nova;
        use Laravel\Nova\Resource;

        class UserNovaResource extends Resource
        {
            public static function getEloquentQuery()
            {
                return parent::getEloquentQuery();
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Nova/UserNovaResource.php');
        self::assertCount(0, $violations);
    }

    public function testIgnoresLaravelApiJsonResources(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Http\Resources;
        use Illuminate\Http\Resources\Json\JsonResource;

        class UserResource extends JsonResource
        {
            public function toArray($request)
            {
                return parent::toArray($request);
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Http/Resources/UserResource.php');
        self::assertCount(0, $violations);
    }

    public function testAllowsFilamentSoftDeletesPattern(): void
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

    public function testFlagsFilamentPageDisablingTenantScoping(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Filament\Pages;
        use Filament\Pages\Page;

        class GlobalDashboard extends Page
        {
            protected static bool $isScopedToTenant = false;
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Filament/Pages/GlobalDashboard.php');
        self::assertCount(1, $violations);
        self::assertSame('filament_resource_tenant', $violations[0]->ruleId);
    }
}

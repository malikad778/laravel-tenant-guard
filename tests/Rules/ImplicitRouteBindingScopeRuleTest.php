<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Tests\Rules;

use MalikAd\TenantGuard\Rules\ImplicitRouteBindingScopeRule;
use MalikAd\TenantGuard\Support\GuardConfig;
use MalikAd\TenantGuard\TenantGuardAnalyzer;
use PHPUnit\Framework\TestCase;

final class ImplicitRouteBindingScopeRuleTest extends TestCase
{
    private TenantGuardAnalyzer $analyzer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->analyzer = new TenantGuardAnalyzer(
            new GuardConfig(),
            [new ImplicitRouteBindingScopeRule()]
        );
    }

    public function testFlagsNestedRouteWithoutScopeBindings(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Routes;
        use Illuminate\Support\Facades\Route;

        Route::get('/companies/{company}/invoices/{invoice}', 'InvoiceController@show');
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'routes/web.php');
        self::assertCount(1, $violations);
        self::assertSame('implicit_route_binding_scope', $violations[0]->ruleId);
    }

    public function testAllowsNestedRouteWithScopeBindings(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Routes;
        use Illuminate\Support\Facades\Route;

        Route::get('/companies/{company}/invoices/{invoice}', 'InvoiceController@show')->scopeBindings();
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'routes/web.php');
        self::assertCount(0, $violations);
    }
}

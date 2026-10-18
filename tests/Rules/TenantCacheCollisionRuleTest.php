<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Tests\Rules;

use MalikAd\TenantGuard\Rules\TenantCacheCollisionRule;
use MalikAd\TenantGuard\Support\GuardConfig;
use MalikAd\TenantGuard\TenantGuardAnalyzer;
use PHPUnit\Framework\TestCase;

final class TenantCacheCollisionRuleTest extends TestCase
{
    private TenantGuardAnalyzer $analyzer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->analyzer = new TenantGuardAnalyzer(
            new GuardConfig(),
            [new TenantCacheCollisionRule()]
        );
    }

    public function testFlagsUnrelatedVariablesContainingSubstring(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\Cache;

        class StatsService
        {
            public function run($companyStats, $tenantless)
            {
                Cache::put($companyStats, 'val');
                Cache::get($tenantless);
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/StatsService.php');
        self::assertCount(2, $violations);
    }

    public function testFlagsSafePrefixMatchingSubstringInUnrelatedLiteral(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\Cache;

        class OrgService
        {
            public function run($x)
            {
                // 'org_chart_global' should NOT be treated as a safe tenant prefix!
                return Cache::get('org_chart_global' . $x);
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/OrgService.php');
        self::assertCount(1, $violations);
    }

    public function testFlagsCacheHelperCall(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;

        class HelperService
        {
            public function run()
            {
                return cache('global_unscoped_key');
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/HelperService.php');
        self::assertCount(1, $violations);
        self::assertSame('tenant_cache_collision', $violations[0]->ruleId);
    }

    public function testFlagsCacheLock(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\Cache;

        class LockService
        {
            public function run()
            {
                return Cache::lock('cron_run');
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/LockService.php');
        self::assertCount(1, $violations);
        self::assertSame('tenant_cache_collision', $violations[0]->ruleId);
    }

    public function testAllowsTenantIsolatedDiskAndStore(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\Cache;
        use Illuminate\Support\Facades\Storage;

        class TenantService
        {
            public function run()
            {
                Storage::disk('tenant')->put('invoice.pdf', 'data');
                return Cache::store('tenant')->get('dashboard_stats');
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/TenantService.php');
        self::assertCount(0, $violations);
    }

    public function testAllowsSafeGlobalCacheKeys(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\Cache;

        class SystemService
        {
            public function run()
            {
                return Cache::get('app_version');
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/SystemService.php');
        self::assertCount(0, $violations);
    }

    public function testRecognizesKeyAssignedInLocalVariable(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Services;
        use Illuminate\Support\Facades\Cache;

        class KeyService
        {
            public function run(int $id)
            {
                $key = 'tenant:' . $id . ':dashboard';
                return Cache::get($key);
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Services/KeyService.php');
        self::assertCount(0, $violations);
    }
}

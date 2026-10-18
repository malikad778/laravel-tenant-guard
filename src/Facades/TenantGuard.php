<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Facades;

use Illuminate\Support\Facades\Facade;
use MalikAd\TenantGuard\Support\AuditResult;
use MalikAd\TenantGuard\Support\Violation;
use MalikAd\TenantGuard\TenantGuardAnalyzer;

/**
 * @method static AuditResult analyzePaths(list<string> $paths, ?string $baselineFile = null)
 * @method static list<Violation> analyzeCode(string $code, string $filePath = 'inline.php')
 *
 * @see \MalikAd\TenantGuard\TenantGuardAnalyzer
 */
final class TenantGuard extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return TenantGuardAnalyzer::class;
    }
}

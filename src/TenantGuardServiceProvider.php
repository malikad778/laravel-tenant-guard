<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard;

use Illuminate\Support\ServiceProvider;
use MalikAd\TenantGuard\Console\TenantGuardAuditCommand;
use MalikAd\TenantGuard\Support\GuardConfig;

final class TenantGuardServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/tenant-guard.php',
            'tenant-guard'
        );

        $this->app->singleton(GuardConfig::class, function ($app): GuardConfig {
            /** @var array<string, mixed> $options */
            $options = (array) $app['config']->get('tenant-guard', []);
            return new GuardConfig($options);
        });

        $this->app->singleton(TenantGuardAnalyzer::class, function ($app): TenantGuardAnalyzer {
            return new TenantGuardAnalyzer($app->make(GuardConfig::class));
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/tenant-guard.php' => $this->app->configPath('tenant-guard.php'),
            ], 'tenant-guard-config');

            $this->commands([
                TenantGuardAuditCommand::class,
            ]);
        }
    }
}

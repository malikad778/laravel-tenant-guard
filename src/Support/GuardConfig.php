<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Support;

final class GuardConfig
{
    /** @var list<string> */
    public readonly array $paths;

    /** @var list<string> */
    public readonly array $exclude;

    /** @var list<string> */
    public readonly array $tenantColumns;

    public readonly bool $strictAllTables;

    /** @var list<string> */
    public readonly array $tenantTables;

    /** @var list<string> */
    public readonly array $globalTables;

    /** @var list<string> */
    public readonly array $globalModels;

    /** @var list<string> */
    public readonly array $safeScopeMethods;

    /** @var list<string> */
    public readonly array $safeCachePrefixes;

    /** @var list<string> */
    public readonly array $tenantDisks;

    /** @var list<string> */
    public readonly array $tenantCacheStores;

    /** @var list<string> */
    public readonly array $safeCacheKeys;

    /** @var list<string> */
    public readonly array $tenantContextIdentifiers;

    public readonly bool $requireFilamentOwnershipRelationship;

    public readonly bool $checkFilamentEloquentQueryOverride;

    /** @var array<string, bool> */
    public readonly array $enabledRules;

    public readonly string $ignoreAnnotation;

    public readonly bool $ignoreParseErrors;

    /**
     * @param array<string, mixed> $options
     */
    public function __construct(array $options = [])
    {
        $defaults = self::defaultOptions();
        $merged = array_replace_recursive($defaults, $options);

        $this->paths = array_values((array) ($options['paths'] ?? $defaults['paths']));
        $this->exclude = array_values((array) ($options['exclude'] ?? $defaults['exclude']));
        $this->tenantColumns = array_values((array) ($options['tenant_columns'] ?? $defaults['tenant_columns']));
        $this->strictAllTables = (bool) ($merged['strict_all_tables'] ?? false);
        $this->tenantTables = array_values((array) ($options['tenant_tables'] ?? $defaults['tenant_tables']));
        $this->globalTables = array_values((array) ($options['global_tables'] ?? $defaults['global_tables']));
        $this->globalModels = array_values((array) ($options['global_models'] ?? $defaults['global_models']));
        $this->safeScopeMethods = array_values((array) ($options['safe_scope_methods'] ?? $defaults['safe_scope_methods']));
        $this->safeCachePrefixes = array_values((array) ($options['safe_cache_prefixes'] ?? $defaults['safe_cache_prefixes']));
        $this->tenantDisks = array_values((array) ($options['tenant_disks'] ?? $defaults['tenant_disks'] ?? []));
        $this->tenantCacheStores = array_values((array) ($options['tenant_cache_stores'] ?? $defaults['tenant_cache_stores'] ?? []));
        $this->safeCacheKeys = array_values((array) ($options['safe_cache_keys'] ?? $defaults['safe_cache_keys'] ?? []));
        $this->tenantContextIdentifiers = array_values((array) ($options['tenant_context_identifiers'] ?? $defaults['tenant_context_identifiers']));

        $filament = (array) ($merged['filament'] ?? []);
        $this->requireFilamentOwnershipRelationship = (bool) ($filament['require_ownership_relationship'] ?? true);
        $this->checkFilamentEloquentQueryOverride = (bool) ($filament['check_eloquent_query_override'] ?? true);

        $this->enabledRules = (array) ($merged['rules'] ?? $defaults['rules']);
        $this->ignoreAnnotation = (string) ($merged['ignore_annotation'] ?? '@tenant-safe');
        $this->ignoreParseErrors = (bool) ($merged['ignore_parse_errors'] ?? false);
    }

    /**
     * @return array<string, mixed>
     */
    public static function defaultOptions(): array
    {
        $configFile = dirname(__DIR__, 2) . '/config/tenant-guard.php';
        if (is_file($configFile)) {
            /** @var array<string, mixed> $loaded */
            $loaded = require $configFile;
            return $loaded;
        }

        return [
            'paths' => ['app', 'routes'],
            'exclude' => ['vendor', 'storage', 'bootstrap', 'node_modules'],
            'tenant_columns' => ['company_id', 'tenant_id', 'organization_id', 'team_id', 'workspace_id', 'account_id'],
            'strict_all_tables' => false,
            'tenant_tables' => ['users', 'invoices', 'orders', 'projects', 'customers', 'subscriptions', 'payments', 'documents', 'tasks', 'teams', 'members', 'settings'],
            'global_tables' => ['migrations', 'failed_jobs', 'jobs', 'job_batches', 'password_reset_tokens', 'personal_access_tokens', 'sessions', 'cache', 'cache_locks', 'tenants', 'domains', 'plans', 'system_settings', 'global_settings'],
            'global_models' => ['Tenant', 'Domain', 'Plan', 'SystemSetting', 'GlobalSetting'],
            'safe_scope_methods' => ['forTenant', 'forCompany', 'whereTenant', 'whereBelongsTo', 'scopedToTenant'],
            'safe_cache_prefixes' => ['tenant:', 'tenant_', 'company:', 'company_', 'org:', 'org_', 'team:', 'workspace:'],
            'tenant_disks' => ['tenant', 'tenants', 'tenant_s3'],
            'tenant_cache_stores' => ['tenant', 'redis_tenant'],
            'safe_cache_keys' => ['app_version', 'system_health', 'global_features'],
            'tenant_context_identifiers' => ['tenant', 'tenantId', 'tenant_id', 'company', 'companyId', 'company_id', 'organization', 'organizationId', 'organization_id', 'teamId', 'team_id', 'workspaceId', 'workspace_id', 'getTenant', 'currentTenant'],
            'filament' => [
                'require_ownership_relationship' => true,
                'check_eloquent_query_override' => true,
            ],
            'rules' => [
                'unscoped_database_query' => true,
                'unscoped_validation' => true,
                'tenant_cache_collision' => true,
                'filament_resource_tenant' => true,
                'unscoped_job_serialization' => true,
                'implicit_route_binding_scope' => true,
            ],
            'ignore_annotation' => '@tenant-safe',
            'ignore_parse_errors' => false,
        ];
    }

    public function isTenantTable(string $table): bool
    {
        $normalized = strtolower(trim($table));
        if ($normalized === '') {
            return false;
        }

        // Strip schema or alias prefix if present
        if (str_contains($normalized, '.')) {
            $parts = explode('.', $normalized);
            $normalized = (string) end($parts);
        }
        if (str_contains($normalized, ' as ')) {
            $parts = explode(' as ', $normalized);
            $normalized = trim($parts[0]);
        }

        $globalLower = array_map('strtolower', $this->globalTables);
        if (in_array($normalized, $globalLower, true)) {
            return false;
        }

        $tenantLower = array_map('strtolower', $this->tenantTables);
        if (in_array($normalized, $tenantLower, true)) {
            return true;
        }

        return $this->strictAllTables;
    }

    public function isTenantModel(string $modelClass): bool
    {
        $shortName = $this->extractShortClassName($modelClass);
        if ($shortName === '') {
            return false;
        }

        foreach ($this->globalModels as $globalModel) {
            if (strcasecmp($shortName, $this->extractShortClassName($globalModel)) === 0) {
                return false;
            }
        }

        return true;
    }

    public function isTenantColumn(string $column): bool
    {
        $normalized = strtolower(trim($column));
        if (str_contains($normalized, '.')) {
            $parts = explode('.', $normalized);
            $normalized = (string) end($parts);
        }

        foreach ($this->tenantColumns as $tenantColumn) {
            if ($normalized === strtolower($tenantColumn)) {
                return true;
            }
        }

        return false;
    }

    public function isTenantDisk(string $disk): bool
    {
        $normalized = strtolower(trim($disk));
        foreach ($this->tenantDisks as $tenantDisk) {
            if ($normalized === strtolower($tenantDisk)) {
                return true;
            }
        }

        return false;
    }

    public function isTenantCacheStore(string $store): bool
    {
        $normalized = strtolower(trim($store));
        foreach ($this->tenantCacheStores as $tenantStore) {
            if ($normalized === strtolower($tenantStore)) {
                return true;
            }
        }

        return false;
    }

    public function isSafeCacheKey(string $key): bool
    {
        $normalized = strtolower(trim($key));
        foreach ($this->safeCacheKeys as $safeKey) {
            if ($normalized === strtolower($safeKey)) {
                return true;
            }
        }

        return false;
    }

    public function isRuleEnabled(string $ruleKey): bool
    {
        return (bool) ($this->enabledRules[$ruleKey] ?? true);
    }

    private function extractShortClassName(string $className): string
    {
        $trimmed = trim($className, '\\');
        if (!str_contains($trimmed, '\\')) {
            return $trimmed;
        }

        $parts = explode('\\', $trimmed);
        return (string) end($parts);
    }
}

<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | Default Scan Paths
    |--------------------------------------------------------------------------
    | Directories relative to the base directory that the AST analyzer will
    | inspect when running audits without explicit paths.
    */
    'paths' => [
        'app',
        'routes',
    ],

    /*
    |--------------------------------------------------------------------------
    | Excluded Paths
    |--------------------------------------------------------------------------
    | Glob patterns or directory names relative to the scan paths that should
    | be skipped during AST traversal.
    */
    'exclude' => [
        'vendor',
        'storage',
        'bootstrap',
        'node_modules',
    ],

    /*
    |--------------------------------------------------------------------------
    | Tenant Identifier Columns
    |--------------------------------------------------------------------------
    | Foreign key columns recognized as valid tenant scoping boundaries in
    | queries, query builder chains, and unique/exists validation rules.
    */
    'tenant_columns' => [
        'company_id',
        'tenant_id',
        'organization_id',
        'team_id',
        'workspace_id',
        'account_id',
    ],

    /*
    |--------------------------------------------------------------------------
    | Strict Table Auditing Mode
    |--------------------------------------------------------------------------
    | When true, every table not explicitly listed in `global_tables` is treated
    | as tenant-owned. When false, only tables listed in `tenant_tables` are
    | audited for missing tenant constraints.
    */
    'strict_all_tables' => false,

    /*
    |--------------------------------------------------------------------------
    | Tenant-Owned Database Tables
    |--------------------------------------------------------------------------
    | Tables storing tenant-isolated records.
    */
    'tenant_tables' => [
        'users',
        'invoices',
        'orders',
        'projects',
        'customers',
        'subscriptions',
        'payments',
        'documents',
        'tasks',
        'teams',
        'members',
        'settings',
        'webhooks',
        'api_keys',
    ],

    /*
    |--------------------------------------------------------------------------
    | Global Database Tables
    |--------------------------------------------------------------------------
    | Central/landlord tables that are intentionally shared across tenants.
    */
    'global_tables' => [
        'migrations',
        'failed_jobs',
        'jobs',
        'job_batches',
        'password_reset_tokens',
        'personal_access_tokens',
        'sessions',
        'cache',
        'cache_locks',
        'tenants',
        'domains',
        'plans',
        'system_settings',
        'global_settings',
    ],

    /*
    |--------------------------------------------------------------------------
    | Global Eloquent Models
    |--------------------------------------------------------------------------
    | Eloquent model short names or FQCNs representing central/landlord data.
    */
    'global_models' => [
        'Tenant',
        'Domain',
        'Plan',
        'SystemSetting',
        'GlobalSetting',
    ],

    /*
    |--------------------------------------------------------------------------
    | Recognized Tenant Scope Methods
    |--------------------------------------------------------------------------
    | Eloquent or Query Builder methods that apply tenant filtering cleanly.
    */
    'safe_scope_methods' => [
        'forTenant',
        'forCompany',
        'whereTenant',
        'whereBelongsTo',
        'scopedToTenant',
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache and Storage Isolation Configuration
    |--------------------------------------------------------------------------
    | Prefixes, tenant-aware storage disks, and tenant cache stores that
    | guarantee tenant isolation without manual key prefixing.
    */
    'safe_cache_prefixes' => [
        'tenant:',
        'tenant_',
        'company:',
        'company_',
        'org:',
        'org_',
        'team:',
        'workspace:',
    ],

    'tenant_disks' => [
        'tenant',
        'tenants',
        'tenant_s3',
    ],

    'tenant_cache_stores' => [
        'tenant',
        'redis_tenant',
    ],

    'safe_cache_keys' => [
        'app_version',
        'system_health',
        'global_features',
    ],

    'tenant_context_identifiers' => [
        'tenant',
        'tenantId',
        'tenant_id',
        'company',
        'companyId',
        'company_id',
        'organization',
        'organizationId',
        'organization_id',
        'teamId',
        'team_id',
        'workspaceId',
        'workspace_id',
        'getTenant',
        'currentTenant',
    ],

    /*
    |--------------------------------------------------------------------------
    | Filament Resource Audit Settings
    |--------------------------------------------------------------------------
    | In Filament 3+, tenant ownership is inferred from the tenant model when
    | tenancy is enabled on the panel. Set `require_ownership_relationship` to
    | true if your codebase strictly requires explicit property declarations.
    */
    'filament' => [
        'require_ownership_relationship' => true,
        'check_eloquent_query_override' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Active Rules
    |--------------------------------------------------------------------------
    | Enable or disable individual AST audit rules.
    */
    'rules' => [
        'unscoped_database_query' => true,
        'unscoped_validation' => true,
        'tenant_cache_collision' => true,
        'filament_resource_tenant' => true,
        'unscoped_job_serialization' => true,
        'implicit_route_binding_scope' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Safety Annotation Tag & Error Handling
    |--------------------------------------------------------------------------
    */
    'ignore_annotation' => '@tenant-safe',
    'ignore_parse_errors' => false,
];

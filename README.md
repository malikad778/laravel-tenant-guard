# Laravel Tenant Guard

<p align="center">
  <img src="https://raw.githubusercontent.com/malikad778/laravel-tenant-guard/main/art/banner.png" alt="Laravel Tenant Guard Banner" width="100%" onerror="this.style.display='none'"/>
</p>

<p align="center">
  <a href="https://packagist.org/packages/malikad/laravel-tenant-guard"><img src="https://img.shields.io/packagist/v/malikad/laravel-tenant-guard.svg?style=flat-square&color=blue" alt="Latest Version on Packagist"></a>
  <a href="https://packagist.org/packages/malikad/laravel-tenant-guard"><img src="https://img.shields.io/packagist/dt/malikad/laravel-tenant-guard.svg?style=flat-square&color=green" alt="Total Downloads"></a>
  <a href="https://github.com/malikad778/laravel-tenant-guard/actions"><img src="https://img.shields.io/github/actions/workflow/status/malikad778/laravel-tenant-guard/ci.yml?branch=main&style=flat-square&label=CI" alt="GitHub CI Status"></a>
  <a href="https://packagist.org/packages/malikad/laravel-tenant-guard"><img src="https://img.shields.io/packagist/php-v/malikad/laravel-tenant-guard.svg?style=flat-square&color=purple" alt="Supported PHP Versions"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-informational?style=flat-square" alt="License: MIT"></a>
</p>

---

## Overview

**Laravel Tenant Guard** is a specialized security static analysis tool for multi-tenant Laravel SaaS applications. Powered by Abstract Syntax Tree (AST) analysis via `nikic/php-parser` v5, Tenant Guard scans your codebase in CI to catch cross-tenant data leaks, cache collisions, unisolated queued jobs, and tenant validation flaws before they reach production.

Unlike runtime tenancy packages that rely on request execution, Tenant Guard operates at build time. It validates code paths across database queries, Eloquent builder chains, cache stores, storage disks, route bindings, and Filament admin panels.

---

## Key Features

- **Zero-Bootstrap CLI**: Inspects code in milliseconds without booting Laravel, configuring environments, or connecting to databases.
- **AST Security Rules**:
  - `unscoped_database_query`: Detects raw SQL, query builders, and global scope stripping lacking tenant filters.
  - `unscoped_validation`: Validates that unique and exists rules enforce tenant column boundaries.
  - `tenant_cache_collision`: Prevents shared cache keys and storage paths from colliding across tenants.
  - `filament_resource_tenant`: Ensures Filament admin resources, pages, and relation managers enforce tenant ownership.
  - `unscoped_job_serialization`: Flags async queued jobs that lack serialized tenant identifiers or tenancy traits.
  - `implicit_route_binding_scope`: Detects nested route parameters lacking `scopeBindings()`.
- **Intra-Procedural Variable Resolution**: Resolves local query and cache key assignments within methods to eliminate false positives.
- **Baseline Support**: Grandfather existing issues in legacy codebases using `--baseline` and `--generate-baseline`.
- **CI Ready**: Native support for GitHub Actions error annotations, SARIF v2.1.0 output, JSON, and standard console tables.
- **PHPStan Extension**: Ships with an adapter for seamless integration into PHPStan 2.x workflows.

---

## Comparison: Static Analysis vs Runtime Tenancy

| Security Concern | Runtime Tenancy Packages (Stancl / Spatie) | Laravel Tenant Guard |
| :--- | :--- | :--- |
| **Bypassing Global Scopes** (`withoutGlobalScopes()`) | Silent cross-tenant leak at runtime | Fails build in CI with exact file and line |
| **Raw DB Queries** (`DB::table('invoices')`) | Global scope never applies | Fails build in CI |
| **Global Cache Collision** (`Cache::remember('stats')`) | Tenant A data served to Tenant B | Fails build in CI |
| **Async Queued Jobs** (`implements ShouldQueue`) | Context dropped if job constructor forgets tenant | Fails build in CI |
| **Nested Route Model Binding** (`/tenants/{t}/orders/{o}`) | Possible cross-tenant ID enumeration | Fails build in CI |
| **Performance Overhead** | Executes on every HTTP request | Zero runtime overhead (runs only in CI/build) |

---

## Requirements

- PHP: 8.3 or 8.4
- Laravel Framework: 10.x, 11.x, or 12.x
- Composer: 2.x

---

## Installation

Install Laravel Tenant Guard as a development dependency via Composer:

```bash
composer require malikad/laravel-tenant-guard --dev
```

Publish the package configuration file:

```bash
php artisan vendor:publish --tag="tenant-guard-config"
```

The published configuration file is located at `config/tenant-guard.php`.

---

## Usage Guide

### 1. Standalone Binary (Zero-Bootstrap in CI)

Run the audit directly without booting Laravel. This is the fastest approach for pull request checks:

```bash
# Audit default paths (app, routes)
./vendor/bin/tenant-guard

# Audit custom directories or specific files
./vendor/bin/tenant-guard audit app/Http app/Services app/Jobs

# Output as GitHub Actions workflow annotations
./vendor/bin/tenant-guard --format=github

# Output SARIF format for GitHub Code Scanning
./vendor/bin/tenant-guard --format=sarif > tenant-guard.sarif

# Output machine-readable JSON
./vendor/bin/tenant-guard --format=json

# Filter audit by a single rule
./vendor/bin/tenant-guard --rule=unscoped_database_query

# Enforce strict table checks on all unlisted tables
./vendor/bin/tenant-guard --strict
```

### 2. Artisan CLI Command

If you prefer running audits through Laravel Artisan:

```bash
php artisan tenant:guard audit
php artisan tenant:guard audit --path=app/Services --format=json
php artisan tenant:guard audit --strict
```

### 3. GitHub Actions Integration

Add this job to your `.github/workflows/ci.yml` file:

```yaml
name: Security Audit

on:
  push:
    branches: [main, master]
  pull_request:

jobs:
  tenant-guard:
    name: Tenant Isolation Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.3'
          coverage: none

      - name: Install Composer Dependencies
        run: composer install --prefer-dist --no-progress

      - name: Run Tenant Guard
        run: ./vendor/bin/tenant-guard --format=github
```

---

## Rule Details and Code Examples

### 1. Unscoped Database Queries (`unscoped_database_query`)

Detects raw queries, query builder calls, and scope stripping methods that access tenant tables without positive tenant isolation filters.

#### Bad (Fails Audit)

```php
// Query builder bypassing Eloquent scopes
$invoices = DB::table('invoices')->where('status', 'paid')->get();

// Stripping global scopes without explicit tenant constraint
$invoices = Invoice::withoutGlobalScopes()->get();

// Raw SQL query missing tenant column
DB::select("SELECT * FROM invoices WHERE status = 'paid'");

// Negative comparison operator (does not isolate to current tenant)
DB::table('invoices')->where('company_id', '!=', $tenantId)->get();
```

#### Good (Passes Audit)

```php
// Eloquent model with global tenant scope active
$invoices = Invoice::where('status', 'paid')->get();

// Explicit tenant scoping on query builder
$invoices = DB::table('invoices')
    ->where('company_id', $tenantId)
    ->where('status', 'paid')
    ->get();

// Variable assignment with intra-procedural scoping
$query = DB::table('invoices');
$query->where('company_id', $tenantId);
return $query->get();

// Stripping only non-tenant scopes
$invoices = Invoice::withoutGlobalScopes([SoftDeletingScope::class])->get();
```

---

### 2. Unscoped Validation Rules (`unscoped_validation`)

Detects `unique` and `exists` validation rules that check records across all tenants instead of scoping to the active tenant foreign key.

#### Bad (Fails Audit)

```php
// Global uniqueness check
'email' => ['required', Rule::unique('users', 'email')];

// String rule without tenant column parameter
'email' => 'required|email|unique:users,email';

// Concatenated rule string missing tenant scoping
'code' => 'required|' . 'unique:invoices,code';
```

#### Good (Passes Audit)

```php
// Scoped with fluent Rule method
'email' => [
    'required',
    Rule::unique('users', 'email')->where('company_id', $tenantId),
];

// String rule containing tenant column parameter
'email' => "required|email|unique:users,email,NULL,id,company_id,{$tenantId}";
```

---

### 3. Tenant Cache Collision (`tenant_cache_collision`)

Ensures cached keys and file storage operations maintain distinct tenant boundaries.

#### Bad (Fails Audit)

```php
// Shared global cache key
Cache::remember('monthly_stats', 3600, fn () => $this->calculate());

// Global cache helper invocation
cache('dashboard_summary');

// Shared storage path without tenant prefix
Storage::disk('s3')->put('exports/report.csv', $data);
```

#### Good (Passes Audit)

```php
// Tenant-prefixed cache key
Cache::remember('tenant:' . tenant('id') . ':monthly_stats', 3600, fn () => $this->calculate());

// Tenant-isolated cache store
Cache::store('tenant')->remember('monthly_stats', 3600, fn () => $this->calculate());

// Tenant-isolated storage disk
Storage::disk('tenant')->put('exports/report.csv', $data);

// Dynamic storage path with tenant identifier
Storage::disk('s3')->put("tenants/{$tenantId}/exports/report.csv", $data);

// Safe global cache key (listed in safe_cache_keys config)
Cache::get('app_version');
```

---

### 4. Filament Resource Tenant Rule (`filament_resource_tenant`)

Validates that Filament v3 and v4 Resources, Pages, and RelationManagers maintain tenant scoping.

#### Bad (Fails Audit)

```php
class InvoiceResource extends Resource
{
    protected static ?string $model = Invoice::class;

    // Disabling tenant scoping explicitly
    protected static bool $isScopedToTenant = false;

    // Overriding getEloquentQuery without calling parent or re-scoping
    public static function getEloquentQuery(): Builder
    {
        return parent::getEloquentQuery()->withoutGlobalScopes();
    }
}
```

#### Good (Passes Audit)

```php
class InvoiceResource extends Resource
{
    protected static ?string $model = Invoice::class;
    protected static ?string $tenantOwnershipRelationshipName = 'company';

    public static function getEloquentQuery(): Builder
    {
        // Safe: strips only SoftDeletingScope
        return parent::getEloquentQuery()->withoutGlobalScopes([
            SoftDeletingScope::class,
        ]);
    }
}
```

---

### 5. Queued Job Tenant Serialization (`unscoped_job_serialization`)

Asynchronous background jobs running via queue workers do not inherit the HTTP request context. This rule ensures queued jobs serialize tenant identifiers.

#### Bad (Fails Audit)

```php
class GenerateInvoicePdfJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(public int $invoiceId)
    {
        // Missing tenant identifier property
    }
}
```

#### Good (Passes Audit)

```php
class GenerateInvoicePdfJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(
        public int $invoiceId,
        public int $tenantId
    ) {
    }
}
```

---

### 6. Implicit Route Binding Scoping (`implicit_route_binding_scope`)

Flags nested route model bindings that omit `->scopeBindings()`, preventing tenant ID enumeration attacks.

#### Bad (Fails Audit)

```php
Route::get('/companies/{company}/invoices/{invoice}', [InvoiceController::class, 'show']);
```

#### Good (Passes Audit)

```php
Route::get('/companies/{company}/invoices/{invoice}', [InvoiceController::class, 'show'])
    ->scopeBindings();
```

---

## Suppressing Safe Lines

When an operation is intentionally global (such as system maintenance tasks, landlord migrations, or central administrative queries), annotate the statement or method with `/** @tenant-safe */`:

```php
/** @tenant-safe */
$totalPlatformRevenue = DB::table('invoices')->sum('total');
```

The alias `/** @tenant-guard-ignore */` is also supported.

---

## Baseline Support for Legacy Codebases

When introducing Tenant Guard to an established project, generate a baseline to ignore existing violations while preventing new ones:

```bash
# Generate baseline file
./vendor/bin/tenant-guard --generate-baseline

# Run audits using baseline file
./vendor/bin/tenant-guard --baseline=tenant-guard-baseline.json
```

---

## Configuration Reference

The `config/tenant-guard.php` file provides granular control over analysis behavior:

```php
return [
    // Paths inspected during default audits
    'paths' => ['app', 'routes'],

    // Directories or patterns skipped during analysis
    'exclude' => ['vendor', 'storage', 'bootstrap', 'node_modules'],

    // Columns recognized as valid tenant scoping boundaries
    'tenant_columns' => [
        'company_id',
        'tenant_id',
        'organization_id',
        'team_id',
        'workspace_id',
        'account_id',
    ],

    // If true, all non-global tables are treated as tenant-owned
    'strict_all_tables' => false,

    // Tables owned by tenants
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

    // Landlord or platform tables exempt from tenant constraints
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

    // Central models allowed to run without tenant scopes
    'global_models' => [
        'Tenant',
        'Domain',
        'Plan',
        'SystemSetting',
        'GlobalSetting',
    ],

    // Tenant-isolated storage disks
    'tenant_disks' => [
        'tenant',
        'tenants',
        'tenant_s3',
    ],

    // Tenant-isolated cache stores
    'tenant_cache_stores' => [
        'tenant',
        'redis_tenant',
    ],

    // Allowlist of safe global cache keys
    'safe_cache_keys' => [
        'app_version',
        'system_health',
        'global_features',
    ],

    // Filament configuration
    'filament' => [
        'require_ownership_relationship' => true,
        'check_eloquent_query_override' => true,
    ],

    // Active rules toggle
    'rules' => [
        'unscoped_database_query' => true,
        'unscoped_validation' => true,
        'tenant_cache_collision' => true,
        'filament_resource_tenant' => true,
        'unscoped_job_serialization' => true,
        'implicit_route_binding_scope' => true,
    ],

    // Safety docblock tag
    'ignore_annotation' => '@tenant-safe',

    // Skip parse error failures if desired
    'ignore_parse_errors' => false,
];
```

---

## PHPStan Integration

If your application uses PHPStan, Tenant Guard integrates natively as a rule extension.

### 1. Install Extension Installer

```bash
composer require --dev phpstan/extension-installer
```

### 2. Configure PHPStan

Tenant Guard is discovered automatically. You can customize options inside `phpstan.neon`:

```neon
parameters:
    tenantGuard:
        strict_all_tables: false
        tenant_columns:
            - company_id
            - tenant_id
        safe_cache_keys:
            - app_version
```

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and testing guidelines.

```bash
# Run PHPUnit test suite
vendor/bin/phpunit

# Run PHPStan static analysis
vendor/bin/phpstan analyse --memory-limit=512M
```

---

## Security

If you discover a security vulnerability, please review [SECURITY.md](SECURITY.md) for reporting procedures.

---

## License

Laravel Tenant Guard is open-sourced software licensed under the [MIT License](LICENSE).

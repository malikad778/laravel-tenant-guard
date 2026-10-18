# Changelog

All notable changes to `laravel-tenant-guard` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-18

### Added
- Comprehensive AST analysis across raw database queries, query builder, Eloquent models, validation rules, cache and storage accesses, queued jobs, and Filament resources.
- `UnscopedJobSerializationRule` to detect unisolated async queued jobs.
- `ImplicitRouteBindingScopeRule` to prevent cross-tenant parameter ID enumeration.
- Multi-format output support: Console table, JSON, SARIF v2.1.0, and GitHub Actions workflow commands (`--format=github`).
- Baseline support (`--baseline` and `--generate-baseline`) to grandfather in legacy codebases.
- Intra-procedural query and cache key assignment resolution within local method blocks.
- Tenant-aware storage disk (`tenant_disks`) and cache store (`tenant_cache_stores`) configurations.
- Soft-deleting scope support in Filament and Eloquent queries without false violations.
- Comprehensive PHPUnit test suite with 60 unit, integration, and false-positive fixture tests.

### Fixed
- Fixed exclude logic to compute paths relative to scan root, preventing false passes on absolute paths containing excluded segment names.
- Fixed bad path handling to exit non-zero when paths do not exist or zero files are found.
- Fixed violation deduplication across multiple visitor rule passes.
- Fixed docblock inspection to prevent cross-statement and class-wide silencing leaks.
- Fixed validation rule inspection for string concatenations and array assignments.
- Fixed cache key inspection to prevent substring false negatives on variables like `$companyStats`.
- Fixed Filament rule to strictly match `Filament\Resources\Resource` instead of matching Nova or JsonResource classes.

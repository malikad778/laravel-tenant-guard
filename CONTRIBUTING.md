# Contributing to Laravel Tenant Guard

Thank you for considering contributing to Laravel Tenant Guard!

## Development Setup

1. Fork and clone the repository.
2. Install dependencies:
   ```bash
   composer install
   ```
3. Run the test suite:
   ```bash
   vendor/bin/phpunit
   ```
4. Run static analysis:
   ```bash
   vendor/bin/phpstan analyse
   ```

## Pull Request Guidelines

- Ensure all PHPUnit tests pass.
- Add test coverage for new rules or bug fixes in `tests/Rules/` or `tests/fixtures/`.
- Maintain docblock integrity and strict types (`declare(strict_types=1);`).
- Keep code style aligned with Laravel standards.

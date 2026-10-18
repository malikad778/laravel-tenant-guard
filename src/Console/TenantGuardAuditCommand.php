<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Console;

use Illuminate\Console\Command;
use MalikAd\TenantGuard\Support\GuardConfig;
use MalikAd\TenantGuard\TenantGuardAnalyzer;

final class TenantGuardAuditCommand extends Command
{
    /**
     * @var string
     */
    protected $signature = 'tenant:guard
        {action=audit : The action to execute (audit)}
        {--path=* : Custom file or directory paths to scan}
        {--format=table : Output format (table, json, sarif, github)}
        {--strict : Treat all non-global tables as tenant-owned}
        {--no-strict : Treat only tenant_tables as tenant-owned}
        {--rule= : Filter audit by a specific rule ID}
        {--baseline= : Path to baseline JSON file}
        {--generate-baseline : Export current violations to baseline JSON file}
        {--ignore-parse-errors : Do not fail the audit on PHP parse errors}';

    /**
     * @var string
     */
    protected $description = 'Run AST static analysis to detect cross-tenant database, validation, cache, job, and Filament scope leaks.';

    public function handle(): int
    {
        $rawAction = $this->argument('action');
        $action = is_string($rawAction) ? strtolower($rawAction) : 'audit';
        if ($action !== 'audit') {
            $this->components->error(sprintf('Unknown action "%s". Only "audit" is supported.', $action));
            return self::FAILURE;
        }

        /** @var array<string, mixed> $rawConfig */
        $rawConfig = function_exists('config') ? (array) config('tenant-guard', []) : [];

        if ((bool) $this->option('strict')) {
            $rawConfig['strict_all_tables'] = true;
        } elseif ((bool) $this->option('no-strict')) {
            $rawConfig['strict_all_tables'] = false;
        }

        $ruleOption = $this->option('rule');
        if (is_string($ruleOption) && $ruleOption !== '') {
            $rawConfig['rules'] = [
                $ruleOption => true,
            ];
        }

        if ((bool) $this->option('ignore-parse-errors')) {
            $rawConfig['ignore_parse_errors'] = true;
        }

        $guardConfig = new GuardConfig($rawConfig);
        $analyzer = new TenantGuardAnalyzer($guardConfig);

        /** @var list<string> $customPaths */
        $customPaths = (array) $this->option('path');
        $targetPaths = $customPaths !== [] ? $customPaths : $this->resolveDefaultPaths($guardConfig);

        $baselineOption = $this->option('baseline');
        $baselineFile = is_string($baselineOption) && $baselineOption !== '' ? $baselineOption : null;

        $result = $analyzer->analyzePaths($targetPaths, $baselineFile);
        $basePath = function_exists('base_path') ? base_path() : (getcwd() ?: '.');

        // Handle baseline generation
        if ((bool) $this->option('generate-baseline')) {
            $targetBaseline = $baselineFile ?? ($basePath . DIRECTORY_SEPARATOR . 'tenant-guard-baseline.json');
            $data = $result->generateBaseline($basePath);
            file_put_contents($targetBaseline, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            $this->components->info(sprintf('Baseline generated at %s with %d violation(s).', $targetBaseline, $result->totalViolations()));
            return self::SUCCESS;
        }

        $rawFormat = $this->option('format');
        $format = is_string($rawFormat) ? strtolower($rawFormat) : 'table';

        if ($format === 'json') {
            $this->line((string) json_encode(
                $result->toArray(),
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
            ));
            return $result->passed() ? self::SUCCESS : self::FAILURE;
        }

        if ($format === 'sarif') {
            $this->line((string) json_encode(
                $result->toSarif($basePath),
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
            ));
            return $result->passed() ? self::SUCCESS : self::FAILURE;
        }

        if ($format === 'github') {
            foreach ($result->toGitHubAnnotations($basePath) as $annotation) {
                $this->line($annotation);
            }
            return $result->passed() ? self::SUCCESS : self::FAILURE;
        }

        $this->newLine();
        $this->components->info(sprintf(
            'Laravel Tenant Guard scanned %d file(s) in %.2f ms.',
            $result->filesScanned,
            $result->elapsedMilliseconds
        ));

        if ($result->parseErrors !== []) {
            foreach ($result->parseErrors as $file => $errorMessage) {
                $this->components->error(sprintf('Parse error in %s: %s', $file, $errorMessage));
            }
        }

        if ($result->filesScanned === 0) {
            $this->components->error('No PHP files were found in the scanned paths.');
            return self::FAILURE;
        }

        if ($result->passed()) {
            $msg = 'Zero tenant isolation violations detected.';
            if ($result->baselineIgnoredCount > 0) {
                $msg .= sprintf(' (%d baseline violation(s) ignored)', $result->baselineIgnoredCount);
            }
            $this->components->info($msg);
            return self::SUCCESS;
        }

        $normalizedBase = rtrim(str_replace('\\', '/', $basePath), '/') . '/';
        $rows = [];
        foreach ($result->violations as $violation) {
            $displayFile = str_replace('\\', '/', $violation->file);
            if (str_starts_with($displayFile, $normalizedBase)) {
                $displayFile = substr($displayFile, strlen($normalizedBase));
            }

            $rows[] = [
                $violation->ruleId,
                sprintf('%s:%d', $displayFile, $violation->line),
                $violation->message,
                $violation->suggestion,
            ];
        }

        $this->table(
            ['Rule', 'Location', 'Violation', 'Suggested Fix'],
            $rows
        );

        $this->components->error(sprintf(
            'Audit failed with %d tenant isolation violation(s).',
            $result->totalViolations()
        ));

        return self::FAILURE;
    }

    /**
     * @return list<string>
     */
    private function resolveDefaultPaths(GuardConfig $config): array
    {
        $basePath = function_exists('base_path') ? base_path() : (getcwd() ?: '.');
        $resolved = [];

        foreach ($config->paths as $relativePath) {
            $candidate = rtrim($basePath, '/\\') . DIRECTORY_SEPARATOR . ltrim($relativePath, '/\\');
            if (file_exists($candidate)) {
                $resolved[] = $candidate;
            }
        }

        return $resolved !== [] ? $resolved : [$basePath];
    }
}

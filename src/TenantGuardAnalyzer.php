<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard;

use MalikAd\TenantGuard\Contracts\TenantRuleInterface;
use MalikAd\TenantGuard\Rules\FilamentResourceTenantRule;
use MalikAd\TenantGuard\Rules\ImplicitRouteBindingScopeRule;
use MalikAd\TenantGuard\Rules\TenantCacheCollisionRule;
use MalikAd\TenantGuard\Rules\UnscopedDatabaseQueryRule;
use MalikAd\TenantGuard\Rules\UnscopedJobSerializationRule;
use MalikAd\TenantGuard\Rules\UnscopedValidationRule;
use MalikAd\TenantGuard\Support\AuditResult;
use MalikAd\TenantGuard\Support\GuardConfig;
use MalikAd\TenantGuard\Support\Violation;
use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\NodeVisitor\ParentConnectingVisitor;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Parser;
use PhpParser\ParserFactory;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class TenantGuardAnalyzer
{
    private readonly GuardConfig $config;

    private readonly Parser $parser;

    /** @var list<TenantRuleInterface> */
    private array $rules;

    /**
     * @param list<TenantRuleInterface>|null $rules
     */
    public function __construct(?GuardConfig $config = null, ?array $rules = null)
    {
        $this->config = $config ?? new GuardConfig();
        $this->parser = (new ParserFactory())->createForNewestSupportedVersion();
        $this->rules = $rules ?? self::defaultRules();
    }

    /**
     * @return list<TenantRuleInterface>
     */
    public static function defaultRules(): array
    {
        return [
            new UnscopedDatabaseQueryRule(),
            new UnscopedValidationRule(),
            new TenantCacheCollisionRule(),
            new FilamentResourceTenantRule(),
            new UnscopedJobSerializationRule(),
            new ImplicitRouteBindingScopeRule(),
        ];
    }

    public function getConfig(): GuardConfig
    {
        return $this->config;
    }

    /**
     * Audits an array of file or directory paths and returns a consolidated AuditResult.
     *
     * @param list<string> $paths
     */
    public function analyzePaths(array $paths, ?string $baselineFile = null): AuditResult
    {
        $startTime = hrtime(true);
        $parseErrors = [];

        foreach ($paths as $path) {
            if (!file_exists($path)) {
                $parseErrors[$path] = sprintf('Specified path does not exist: %s', $path);
            }
        }

        $files = $this->collectPhpFiles($paths);
        $allViolations = [];
        $seenKeys = [];

        foreach ($files as $filePath) {
            $code = @file_get_contents($filePath);
            if ($code === false) {
                $parseErrors[$filePath] = 'Unable to read file contents.';
                continue;
            }

            try {
                $violations = $this->analyzeCode($code, $filePath);
                foreach ($violations as $violation) {
                    $key = $violation->getUniqueKey();
                    if (!isset($seenKeys[$key])) {
                        $seenKeys[$key] = true;
                        $allViolations[] = $violation;
                    }
                }
            } catch (Error $error) {
                $parseErrors[$filePath] = $error->getMessage();
            }
        }

        $baselineIgnored = 0;
        if ($baselineFile !== null && is_file($baselineFile)) {
            $baselineContent = (string) @file_get_contents($baselineFile);
            /** @var array<string, list<string>> $baselineData */
            $baselineData = (array) json_decode($baselineContent, true);

            $filtered = [];
            foreach ($allViolations as $violation) {
                $file = $violation->file;
                $hash = sha1(sprintf('%s:%s:%s', $file, $violation->ruleId, $violation->message));
                if (isset($baselineData[$file]) && in_array($hash, $baselineData[$file], true)) {
                    $baselineIgnored++;
                    continue;
                }
                $filtered[] = $violation;
            }
            $allViolations = $filtered;
        }

        $elapsedMs = (hrtime(true) - $startTime) / 1_000_000;

        return new AuditResult(
            filesScanned: count($files),
            violations: $allViolations,
            parseErrors: $this->config->ignoreParseErrors ? [] : $parseErrors,
            elapsedMilliseconds: $elapsedMs,
            baselineIgnoredCount: $baselineIgnored,
        );
    }

    /**
     * Parses and audits a single PHP source string.
     *
     * @return list<Violation>
     */
    public function analyzeCode(string $code, string $filePath = 'inline.php'): array
    {
        $stmts = $this->parser->parse($code);
        if ($stmts === null) {
            return [];
        }

        /** @var list<string> $sourceLines */
        $sourceLines = preg_split("/\r\n|\n|\r/", $code) ?: [];

        $activeRules = array_values(array_filter(
            $this->rules,
            fn (TenantRuleInterface $rule): bool => $this->config->isRuleEnabled($rule->ruleId())
        ));

        $collector = new class($activeRules, $filePath, $this->config, $sourceLines) extends NodeVisitorAbstract {
            /** @var list<Violation> */
            public array $violations = [];

            /** @var array<string, bool> */
            private array $seenKeys = [];

            /**
             * @param list<TenantRuleInterface> $rules
             * @param list<string> $sourceLines
             */
            public function __construct(
                private readonly array $rules,
                private readonly string $filePath,
                private readonly GuardConfig $config,
                private readonly array $sourceLines,
            ) {
            }

            public function enterNode(Node $node): ?int
            {
                foreach ($this->rules as $rule) {
                    $found = $rule->inspect($node, $this->filePath, $this->config, $this->sourceLines);
                    foreach ($found as $violation) {
                        $key = $violation->getUniqueKey();
                        if (!isset($this->seenKeys[$key])) {
                            $this->seenKeys[$key] = true;
                            $this->violations[] = $violation;
                        }
                    }
                }

                return null;
            }
        };

        $traverser = new NodeTraverser();
        $traverser->addVisitor(new NameResolver());
        $traverser->addVisitor(new ParentConnectingVisitor());
        $traverser->addVisitor($collector);
        $traverser->traverse($stmts);

        return $collector->violations;
    }

    /**
     * @param list<string> $paths
     * @return list<string>
     */
    private function collectPhpFiles(array $paths): array
    {
        $collected = [];

        foreach ($paths as $path) {
            if (!file_exists($path)) {
                continue;
            }

            if (is_file($path)) {
                $base = dirname($path);
                if (str_ends_with(strtolower($path), '.php') && !$this->isExcluded($path, $base)) {
                    $collected[] = realpath($path) ?: $path;
                }
                continue;
            }

            if (is_dir($path)) {
                $base = realpath($path) ?: $path;
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($base, RecursiveDirectoryIterator::SKIP_DOTS)
                );

                /** @var SplFileInfo $fileInfo */
                foreach ($iterator as $fileInfo) {
                    if (!$fileInfo->isFile()) {
                        continue;
                    }

                    $pathname = $fileInfo->getPathname();
                    if (!str_ends_with(strtolower($pathname), '.php')) {
                        continue;
                    }

                    if ($this->isExcluded($pathname, $base)) {
                        continue;
                    }

                    $collected[] = realpath($pathname) ?: $pathname;
                }
            }
        }

        $collected = array_values(array_unique($collected));
        sort($collected);

        return $collected;
    }

    /**
     * Checks if a file path is excluded relative to the base scan directory.
     */
    private function isExcluded(string $filePath, string $basePath): bool
    {
        $normalizedFile = str_replace('\\', '/', $filePath);
        $normalizedBase = rtrim(str_replace('\\', '/', $basePath), '/');

        if (str_starts_with($normalizedFile, $normalizedBase . '/')) {
            $relative = substr($normalizedFile, strlen($normalizedBase) + 1);
        } else {
            $relative = ltrim($normalizedFile, '/');
        }

        $segments = explode('/', $relative);

        foreach ($this->config->exclude as $excludedPattern) {
            $pattern = trim(str_replace('\\', '/', $excludedPattern), '/');
            if ($pattern === '') {
                continue;
            }

            if (
                $relative === $pattern
                || str_starts_with($relative, $pattern . '/')
                || in_array($pattern, $segments, true)
                || fnmatch($pattern, $relative)
                || fnmatch($pattern . '/*', $relative)
                || fnmatch('*/' . $pattern . '/*', $relative)
            ) {
                return true;
            }
        }

        return false;
    }
}

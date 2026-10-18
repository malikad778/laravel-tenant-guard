<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Support;

final class AuditResult
{
    /**
     * @param list<Violation> $violations
     * @param array<string, string> $parseErrors
     */
    public function __construct(
        public readonly int $filesScanned,
        public readonly array $violations = [],
        public readonly array $parseErrors = [],
        public readonly float $elapsedMilliseconds = 0.0,
        public readonly int $baselineIgnoredCount = 0,
    ) {
    }

    public function passed(): bool
    {
        return $this->filesScanned > 0
            && count($this->violations) === 0
            && count($this->parseErrors) === 0;
    }

    public function failed(): bool
    {
        return !$this->passed();
    }

    public function totalViolations(): int
    {
        return count($this->violations);
    }

    /**
     * @return array<string, list<Violation>>
     */
    public function violationsByFile(): array
    {
        $grouped = [];
        foreach ($this->violations as $violation) {
            $grouped[$violation->file][] = $violation;
        }

        ksort($grouped);
        return $grouped;
    }

    /**
     * @return array<string, list<Violation>>
     */
    public function violationsByRule(): array
    {
        $grouped = [];
        foreach ($this->violations as $violation) {
            $grouped[$violation->ruleId][] = $violation;
        }

        ksort($grouped);
        return $grouped;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'passed' => $this->passed(),
            'files_scanned' => $this->filesScanned,
            'total_violations' => $this->totalViolations(),
            'baseline_ignored' => $this->baselineIgnoredCount,
            'elapsed_ms' => round($this->elapsedMilliseconds, 2),
            'violations' => array_map(
                static fn (Violation $v): array => $v->toArray(),
                $this->violations
            ),
            'parse_errors' => $this->parseErrors,
        ];
    }

    /**
     * @return list<string>
     */
    public function toGitHubAnnotations(string $basePath = ''): array
    {
        return array_map(
            static fn (Violation $v): string => $v->toGitHubAnnotation($basePath),
            $this->violations
        );
    }

    /**
     * Generates a SARIF v2.1.0 log representation.
     *
     * @return array<string, mixed>
     */
    public function toSarif(string $basePath = ''): array
    {
        $rules = [];
        $results = [];

        foreach ($this->violations as $violation) {
            if (!isset($rules[$violation->ruleId])) {
                $rules[$violation->ruleId] = [
                    'id' => $violation->ruleId,
                    'shortDescription' => [
                        'text' => sprintf('TenantGuard rule %s', $violation->ruleId),
                    ],
                ];
            }

            $displayPath = $violation->file;
            if ($basePath !== '') {
                $normalizedBase = rtrim(str_replace('\\', '/', $basePath), '/') . '/';
                $normalizedFile = str_replace('\\', '/', $violation->file);
                if (str_starts_with($normalizedFile, $normalizedBase)) {
                    $displayPath = substr($normalizedFile, strlen($normalizedBase));
                }
            }

            $results[] = [
                'ruleId' => $violation->ruleId,
                'level' => $violation->severity === Violation::SEVERITY_WARNING ? 'warning' : 'error',
                'message' => [
                    'text' => $violation->message . ($violation->suggestion !== '' ? ' ' . $violation->suggestion : ''),
                ],
                'locations' => [
                    [
                        'physicalLocation' => [
                            'artifactLocation' => [
                                'uri' => str_replace('\\', '/', $displayPath),
                                'uriBaseId' => '%SRCROOT%',
                            ],
                            'region' => [
                                'startLine' => $violation->line,
                            ],
                        ],
                    ],
                ],
            ];
        }

        return [
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'Laravel Tenant Guard',
                            'informationUri' => 'https://github.com/malikad778/laravel-tenant-guard',
                            'rules' => array_values($rules),
                        ],
                    ],
                    'results' => $results,
                ],
            ],
        ];
    }

    /**
     * @return array<string, list<string>>
     */
    public function generateBaseline(string $basePath = ''): array
    {
        $baseline = [];
        foreach ($this->violations as $violation) {
            $displayPath = $violation->file;
            if ($basePath !== '') {
                $normalizedBase = rtrim(str_replace('\\', '/', $basePath), '/') . '/';
                $normalizedFile = str_replace('\\', '/', $violation->file);
                if (str_starts_with($normalizedFile, $normalizedBase)) {
                    $displayPath = substr($normalizedFile, strlen($normalizedBase));
                }
            }
            $hash = sha1(sprintf('%s:%s:%s', $displayPath, $violation->ruleId, $violation->message));
            $baseline[$displayPath][] = $hash;
        }

        foreach ($baseline as $file => $hashes) {
            $baseline[$file] = array_values(array_unique($hashes));
            sort($baseline[$file]);
        }
        ksort($baseline);

        return $baseline;
    }
}

<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Support;

final class Violation
{
    public const SEVERITY_ERROR = 'error';
    public const SEVERITY_WARNING = 'warning';

    public function __construct(
        public readonly string $ruleId,
        public readonly string $file,
        public readonly int $line,
        public readonly string $message,
        public readonly string $suggestion = '',
        public readonly string $snippet = '',
        public readonly string $severity = self::SEVERITY_ERROR,
    ) {
    }

    /**
     * @return array{rule_id: string, file: string, line: int, message: string, suggestion: string, snippet: string, severity: string}
     */
    public function toArray(): array
    {
        return [
            'rule_id' => $this->ruleId,
            'file' => $this->file,
            'line' => $this->line,
            'message' => $this->message,
            'suggestion' => $this->suggestion,
            'snippet' => $this->snippet,
            'severity' => $this->severity,
        ];
    }

    public function formatLocation(): string
    {
        return sprintf('%s:%d', $this->file, $this->line);
    }

    public function getUniqueKey(): string
    {
        return sprintf('%s:%d:%s:%s', $this->file, $this->line, $this->ruleId, $this->message);
    }

    public function toGitHubAnnotation(string $basePath = ''): string
    {
        $displayPath = $this->file;
        if ($basePath !== '') {
            $normalizedBase = rtrim(str_replace('\\', '/', $basePath), '/') . '/';
            $normalizedFile = str_replace('\\', '/', $this->file);
            if (str_starts_with($normalizedFile, $normalizedBase)) {
                $displayPath = substr($normalizedFile, strlen($normalizedBase));
            }
        }

        $command = $this->severity === self::SEVERITY_WARNING ? 'warning' : 'error';
        $title = sprintf('TenantGuard: %s', $this->ruleId);
        $fullMessage = $this->message;
        if ($this->suggestion !== '') {
            $fullMessage .= sprintf(' Fix: %s', $this->suggestion);
        }

        return sprintf(
            '::%s file=%s,line=%d,title=%s::%s',
            $command,
            $displayPath,
            $this->line,
            $title,
            str_replace(["\r", "\n"], ' ', $fullMessage)
        );
    }
}

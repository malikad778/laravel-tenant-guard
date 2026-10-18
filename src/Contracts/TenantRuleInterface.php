<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Contracts;

use MalikAd\TenantGuard\Support\GuardConfig;
use MalikAd\TenantGuard\Support\Violation;
use PhpParser\Node;

interface TenantRuleInterface
{
    public function ruleId(): string;

    /**
     * Inspects an AST node and returns zero or more tenant safety violations.
     *
     * @param list<string> $sourceLines
     * @return list<Violation>
     */
    public function inspect(
        Node $node,
        string $filePath,
        GuardConfig $config,
        array $sourceLines = []
    ): array;
}

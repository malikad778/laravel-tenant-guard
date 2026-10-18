<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\PHPStan;

use MalikAd\TenantGuard\Support\GuardConfig;
use MalikAd\TenantGuard\TenantGuardAnalyzer;
use PhpParser\Error;
use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\FileNode;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

/**
 * PHPStan rule adapter that runs the full TenantGuard AST rule suite once per
 * analyzed file and reports violations as native PHPStan errors with identifiers.
 *
 * @implements Rule<FileNode>
 */
final class TenantGuardPHPStanRule implements Rule
{
    private readonly TenantGuardAnalyzer $analyzer;

    /**
     * @param array<string, mixed> $options
     */
    public function __construct(array $options = [])
    {
        // Filter out empty arrays from unconfigured parameters so GuardConfig defaults take effect
        $cleanOptions = array_filter($options, static fn ($v): bool => $v !== [] && $v !== null);
        $this->analyzer = new TenantGuardAnalyzer(new GuardConfig($cleanOptions));
    }

    public function getNodeType(): string
    {
        return FileNode::class;
    }

    /**
     * @param FileNode $node
     */
    public function processNode(Node $node, Scope $scope): array
    {
        $filePath = $scope->getFile();
        $code = @file_get_contents($filePath);
        if ($code === false) {
            return [];
        }

        try {
            $violations = $this->analyzer->analyzeCode($code, $filePath);
        } catch (Error $e) {
            // Do not crash PHPStan on parse errors in target files
            return [];
        }

        $errors = [];

        foreach ($violations as $violation) {
            $message = $violation->message;
            if ($violation->suggestion !== '') {
                $message .= ' Tip: ' . $violation->suggestion;
            }

            $errors[] = RuleErrorBuilder::message($message)
                ->line($violation->line)
                ->identifier('tenantGuard.' . $violation->ruleId)
                ->build();
        }

        return $errors;
    }
}

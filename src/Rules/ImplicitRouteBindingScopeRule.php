<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Rules;

use MalikAd\TenantGuard\Contracts\TenantRuleInterface;
use MalikAd\TenantGuard\Support\DocblockInspector;
use MalikAd\TenantGuard\Support\GuardConfig;
use MalikAd\TenantGuard\Support\Violation;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;

final class ImplicitRouteBindingScopeRule implements TenantRuleInterface
{
    private const ROUTE_METHODS = [
        'get',
        'post',
        'put',
        'patch',
        'delete',
        'options',
        'any',
        'match',
        'resource',
        'apiResource',
    ];

    public function ruleId(): string
    {
        return 'implicit_route_binding_scope';
    }

    public function inspect(
        Node $node,
        string $filePath,
        GuardConfig $config,
        array $sourceLines = []
    ): array {
        if (!$config->isRuleEnabled($this->ruleId())) {
            return [];
        }

        if (!$node instanceof StaticCall && !$node instanceof MethodCall) {
            return [];
        }

        if (DocblockInspector::isMarkedTenantSafe($node, $config->ignoreAnnotation, $sourceLines)) {
            return [];
        }

        $uri = $this->extractRouteUri($node);
        if ($uri === null) {
            return [];
        }

        if (!$this->hasNestedTenantParameters($uri, $config)) {
            return [];
        }

        if ($this->chainContainsScopeBindings($node)) {
            return [];
        }

        $line = $node->getStartLine();
        return [
            new Violation(
                ruleId: $this->ruleId(),
                file: $filePath,
                line: $line,
                message: sprintf(
                    "Nested route '%s' uses implicit route model binding without ->scopeBindings(), risking cross-tenant resource access.",
                    $uri
                ),
                suggestion: sprintf(
                    "Chain ->scopeBindings() after the route definition or annotate with /** %s */.",
                    $config->ignoreAnnotation
                ),
                snippet: trim($sourceLines[$line - 1] ?? '')
            ),
        ];
    }

    private function extractRouteUri(StaticCall|MethodCall $call): ?string
    {
        if ($call instanceof StaticCall) {
            if (!$call->class instanceof Name || !$call->name instanceof Identifier) {
                return null;
            }
            $shortClass = $this->shortName($call->class->toString());
            if ($shortClass !== 'Route' && !str_ends_with($call->class->toString(), 'Facades\Route')) {
                return null;
            }
            if (!in_array($call->name->toString(), self::ROUTE_METHODS, true)) {
                return null;
            }
            return $this->getFirstStringArg($call->args);
        }

        if ($call->name instanceof Identifier && in_array($call->name->toString(), self::ROUTE_METHODS, true)) {
            if ($this->isRouteReceiver($call->var)) {
                return $this->getFirstStringArg($call->args);
            }
        }

        return null;
    }

    private function isRouteReceiver(Expr $expr): bool
    {
        $cursor = $expr;
        while ($cursor instanceof MethodCall) {
            $cursor = $cursor->var;
        }

        if ($cursor instanceof StaticCall && $cursor->class instanceof Name) {
            return $this->shortName($cursor->class->toString()) === 'Route';
        }

        return false;
    }

    /**
     * @param array<mixed> $args
     */
    private function getFirstStringArg(array $args): ?string
    {
        if ($args === [] || !$args[0] instanceof Arg) {
            return null;
        }

        return $args[0]->value instanceof String_ ? $args[0]->value->value : null;
    }

    private function hasNestedTenantParameters(string $uri, GuardConfig $config): bool
    {
        preg_match_all('/\{([a-zA-Z0-9_]+)\}/', $uri, $matches);
        $params = $matches[1];
        if (count($params) < 2) {
            return false;
        }

        $tenantParamFound = false;
        foreach ($params as $index => $param) {
            $lower = strtolower($param);
            foreach ($config->tenantContextIdentifiers as $identifier) {
                if ($lower === strtolower($identifier) || str_contains($lower, strtolower($identifier))) {
                    $tenantParamFound = true;
                    // If tenant param is not the last param, there is a nested child parameter
                    if ($index < count($params) - 1) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private function chainContainsScopeBindings(Expr $node): bool
    {
        $cursor = $node;
        while (true) {
            $parent = $cursor->getAttribute('parent');
            if (!$parent instanceof MethodCall || $parent->var !== $cursor) {
                break;
            }

            if ($parent->name instanceof Identifier && $parent->name->toString() === 'scopeBindings') {
                return true;
            }

            $cursor = $parent;
        }

        return false;
    }

    private function shortName(string $className): string
    {
        $trimmed = trim($className, '\\');
        if (!str_contains($trimmed, '\\')) {
            return $trimmed;
        }

        $parts = explode('\\', $trimmed);
        return (string) end($parts);
    }
}

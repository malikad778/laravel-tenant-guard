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
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\InterpolatedString;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Function_;

final class TenantCacheCollisionRule implements TenantRuleInterface
{
    /** @var list<string> */
    private const CACHE_KEY_METHODS = [
        'remember',
        'rememberForever',
        'sear',
        'put',
        'add',
        'forever',
        'get',
        'pull',
        'forget',
        'has',
        'missing',
        'increment',
        'decrement',
        'flexible',
        'lock',
        'restoreLock',
    ];

    /** @var list<string> */
    private const STORAGE_PATH_METHODS = [
        'put',
        'putFile',
        'putFileAs',
        'get',
        'exists',
        'missing',
        'download',
        'delete',
        'deleteDirectory',
        'makeDirectory',
        'path',
    ];

    public function ruleId(): string
    {
        return 'tenant_cache_collision';
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

        if ($node instanceof StaticCall) {
            return $this->inspectStaticCall($node, $filePath, $config, $sourceLines);
        }

        if ($node instanceof MethodCall) {
            return $this->inspectMethodCall($node, $filePath, $config, $sourceLines);
        }

        if ($node instanceof FuncCall) {
            return $this->inspectFuncCall($node, $filePath, $config, $sourceLines);
        }

        return [];
    }

    /**
     * @param list<string> $sourceLines
     * @return list<Violation>
     */
    private function inspectStaticCall(
        StaticCall $call,
        string $filePath,
        GuardConfig $config,
        array $sourceLines
    ): array {
        if (!$call->class instanceof Name || !$call->name instanceof Identifier) {
            return [];
        }

        if (DocblockInspector::isMarkedTenantSafe($call, $config->ignoreAnnotation, $sourceLines)) {
            return [];
        }

        $shortClass = $this->shortName($call->class->toString());
        $method = $call->name->toString();

        // Direct Cache::remember('dashboard_stats', ...) calls
        if ($shortClass === 'Cache' && in_array($method, self::CACHE_KEY_METHODS, true)) {
            if ($call->args === [] || !$call->args[0] instanceof Arg) {
                return [];
            }

            $keyExpr = $call->args[0]->value;
            if ($this->isSafeCacheKeyOrExpression($keyExpr, $config, $call)) {
                return [];
            }

            $line = $call->getStartLine();
            return [
                new Violation(
                    ruleId: $this->ruleId(),
                    file: $filePath,
                    line: $line,
                    message: sprintf(
                        "Unscoped cache call Cache::%s() uses a key without a tenant identifier prefix, risking cross-tenant cache bleed.",
                        $method
                    ),
                    suggestion: sprintf(
                        "Prefix the cache key with the active tenant ID (for example: 'tenant:' . tenant('id') . ':key') or annotate with /** %s */.",
                        $config->ignoreAnnotation
                    ),
                    snippet: trim($sourceLines[$line - 1] ?? '')
                ),
            ];
        }

        // Direct Storage::put('invoices/report.pdf', ...)
        if ($shortClass === 'Storage') {
            if (in_array($method, self::STORAGE_PATH_METHODS, true)) {
                if ($call->args === [] || !$call->args[0] instanceof Arg) {
                    return [];
                }

                if ($this->expressionHasTenantContext($call->args[0]->value, $config, $call)) {
                    return [];
                }

                $line = $call->getStartLine();
                return [
                    new Violation(
                        ruleId: $this->ruleId(),
                        file: $filePath,
                        line: $line,
                        message: sprintf(
                            "Unscoped storage call Storage::%s() uses a path without tenant isolation.",
                            $method
                        ),
                        suggestion: sprintf(
                            "Prefix the storage path with the tenant identifier (e.g. 'tenants/' . tenant('id') . '/file') or annotate with /** %s */.",
                            $config->ignoreAnnotation
                        ),
                        snippet: trim($sourceLines[$line - 1] ?? '')
                    ),
                ];
            }
        }

        return [];
    }

    /**
     * Inspects chained calls like:
     * - Cache::store('redis')->remember('stats', ...)
     * - Storage::disk('s3')->put('exports/report.csv', ...)
     *
     * @param list<string> $sourceLines
     * @return list<Violation>
     */
    private function inspectMethodCall(
        MethodCall $call,
        string $filePath,
        GuardConfig $config,
        array $sourceLines
    ): array {
        if (!$call->name instanceof Identifier) {
            return [];
        }

        if (DocblockInspector::isMarkedTenantSafe($call, $config->ignoreAnnotation, $sourceLines)) {
            return [];
        }

        $method = $call->name->toString();

        // Chained Cache calls
        if (in_array($method, self::CACHE_KEY_METHODS, true) && $this->isCacheReceiver($call->var)) {
            if ($this->receiverHasTenantTags($call->var, $config)) {
                return [];
            }

            if ($this->receiverIsTenantIsolatedStore($call->var, $config)) {
                return [];
            }

            if ($call->args === [] || !$call->args[0] instanceof Arg) {
                return [];
            }

            if ($this->isSafeCacheKeyOrExpression($call->args[0]->value, $config, $call)) {
                return [];
            }

            $line = $call->getStartLine();
            return [
                new Violation(
                    ruleId: $this->ruleId(),
                    file: $filePath,
                    line: $line,
                    message: sprintf(
                        "Unscoped cache call ->%s() uses a key without a tenant identifier prefix.",
                        $method
                    ),
                    suggestion: sprintf(
                        "Include the active tenant ID in the cache key or cache tags, or annotate with /** %s */.",
                        $config->ignoreAnnotation
                    ),
                    snippet: trim($sourceLines[$line - 1] ?? '')
                ),
            ];
        }

        // Chained Storage::disk('s3')->put($path, ...)
        if (in_array($method, self::STORAGE_PATH_METHODS, true) && $this->isStorageReceiver($call->var)) {
            if ($this->storageDiskReceiverIsTenantIsolated($call->var, $config)) {
                return [];
            }

            if ($call->args === [] || !$call->args[0] instanceof Arg) {
                return [];
            }

            if ($this->expressionHasTenantContext($call->args[0]->value, $config, $call)) {
                return [];
            }

            $line = $call->getStartLine();
            return [
                new Violation(
                    ruleId: $this->ruleId(),
                    file: $filePath,
                    line: $line,
                    message: sprintf(
                        "Unscoped storage operation ->%s() writes or reads a shared path without a tenant prefix.",
                        $method
                    ),
                    suggestion: sprintf(
                        "Prefix the storage path with the tenant ID (e.g. 'tenants/' . tenant('id') . '/...') or mark with /** %s */.",
                        $config->ignoreAnnotation
                    ),
                    snippet: trim($sourceLines[$line - 1] ?? '')
                ),
            ];
        }

        return [];
    }

    /**
     * Inspects helper calls like cache('key') or cache(['key' => $val]).
     *
     * @param list<string> $sourceLines
     * @return list<Violation>
     */
    private function inspectFuncCall(
        FuncCall $call,
        string $filePath,
        GuardConfig $config,
        array $sourceLines
    ): array {
        if (!$call->name instanceof Name) {
            return [];
        }

        if (strtolower($call->name->toString()) !== 'cache') {
            return [];
        }

        // cache() with no args returns cache manager
        if ($call->args === []) {
            return [];
        }

        if (DocblockInspector::isMarkedTenantSafe($call, $config->ignoreAnnotation, $sourceLines)) {
            return [];
        }

        $firstArg = $call->args[0];
        if (!$firstArg instanceof Arg) {
            return [];
        }

        // cache('my_key')
        if ($this->isSafeCacheKeyOrExpression($firstArg->value, $config, $call)) {
            return [];
        }

        $line = $call->getStartLine();
        return [
            new Violation(
                ruleId: $this->ruleId(),
                file: $filePath,
                line: $line,
                message: "Unscoped cache() helper call uses a key without a tenant prefix.",
                suggestion: sprintf(
                    "Prefix the cache key with the tenant ID or mark with /** %s */.",
                    $config->ignoreAnnotation
                ),
                snippet: trim($sourceLines[$line - 1] ?? '')
            ),
        ];
    }

    private function isSafeCacheKeyOrExpression(Expr $expr, GuardConfig $config, Node $contextNode): bool
    {
        if ($expr instanceof String_) {
            return $config->isSafeCacheKey($expr->value);
        }

        return $this->expressionHasTenantContext($expr, $config, $contextNode);
    }

    private function expressionHasTenantContext(Expr $expr, GuardConfig $config, ?Node $contextNode = null): bool
    {
        if ($expr instanceof String_) {
            return false;
        }

        // Concatenation: 'tenant:' . $tenantId . ':stats'
        if ($expr instanceof Concat) {
            return $this->expressionHasTenantContext($expr->left, $config, $contextNode)
                || $this->expressionHasTenantContext($expr->right, $config, $contextNode)
                || $this->concatContainsSafePrefix($expr, $config);
        }

        // Double-quoted interpolated string: "tenant_{$tenantId}_stats"
        if ($expr instanceof InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Expr && $this->expressionHasTenantContext($part, $config, $contextNode)) {
                    return true;
                }
                if ($part instanceof Node\InterpolatedStringPart) {
                    foreach ($config->safeCachePrefixes as $prefix) {
                        if (str_starts_with(strtolower($part->value), strtolower($prefix))) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        // sprintf('tenant:%s:stats', $tenantId) or tenant('id')
        if ($expr instanceof FuncCall && $expr->name instanceof Name) {
            $fnName = strtolower($expr->name->toString());
            if ($this->isTenantFunctionCall($fnName, $config)) {
                return true;
            }
            if ($fnName === 'sprintf' && count($expr->args) >= 2) {
                foreach (array_slice($expr->args, 1) as $arg) {
                    if ($arg instanceof Arg && $this->expressionHasTenantContext($arg->value, $config, $contextNode)) {
                        return true;
                    }
                }
            }
        }

        // Variable like $tenantId, $companyId
        if ($expr instanceof Variable && is_string($expr->name)) {
            if ($this->matchesTenantIdentifier($expr->name, $config)) {
                return true;
            }

            // Resolve assigned expression in enclosing method
            if ($contextNode !== null && $this->variableResolvesToTenantContext($expr->name, $contextNode, $config)) {
                return true;
            }
        }

        // Property fetch like $tenant->id or $user->company_id
        if ($expr instanceof PropertyFetch) {
            if ($expr->name instanceof Identifier && $this->matchesTenantIdentifier($expr->name->toString(), $config)) {
                return true;
            }
            return $this->expressionHasTenantContext($expr->var, $config, $contextNode);
        }

        // Method call like $request->user()->companyId() or Filament::getTenant()->id
        if ($expr instanceof MethodCall) {
            if ($expr->name instanceof Identifier && $this->matchesTenantIdentifier($expr->name->toString(), $config)) {
                return true;
            }
            return $this->expressionHasTenantContext($expr->var, $config, $contextNode);
        }

        // Static call like Filament::getTenant() or Tenant::current()
        if ($expr instanceof StaticCall) {
            if ($expr->class instanceof Name) {
                $cls = $this->shortName($expr->class->toString());
                if ($this->matchesTenantIdentifier($cls, $config)) {
                    return true;
                }
            }
            if ($expr->name instanceof Identifier && $this->matchesTenantIdentifier($expr->name->toString(), $config)) {
                return true;
            }
        }

        return false;
    }

    private function concatContainsSafePrefix(Concat $concat, GuardConfig $config): bool
    {
        if ($concat->left instanceof String_) {
            $val = strtolower(trim($concat->left->value));
            foreach ($config->safeCachePrefixes as $prefix) {
                $lowerPrefix = strtolower(trim($prefix));
                if ($val === $lowerPrefix) {
                    return !$concat->right instanceof String_;
                }
            }
        }

        return false;
    }

    /**
     * Exact or boundary-based tenant identifier matching (avoids false matches on $companyStats).
     */
    private function matchesTenantIdentifier(string $name, GuardConfig $config): bool
    {
        $normalized = strtolower(trim($name, '$'));

        // Direct exact match
        foreach ($config->tenantContextIdentifiers as $identifier) {
            if ($normalized === strtolower($identifier)) {
                return true;
            }
        }

        // Ending with tenant identifier, e.g. current_tenant, activeTenantId
        foreach ($config->tenantColumns as $col) {
            if ($normalized === strtolower($col)) {
                return true;
            }
        }

        return in_array($normalized, ['tenantid', 'tenant_id', 'companyid', 'company_id', 'teamid', 'team_id'], true);
    }

    private function isTenantFunctionCall(string $fnName, GuardConfig $config): bool
    {
        $lower = strtolower($fnName);
        return in_array($lower, ['tenant', 'currenttenant', 'company'], true);
    }

    private function variableResolvesToTenantContext(string $varName, Node $contextNode, GuardConfig $config): bool
    {
        $enclosing = $this->findEnclosingBlock($contextNode);
        if ($enclosing === null) {
            return false;
        }

        $targetLine = $contextNode->getStartLine();
        foreach ($enclosing as $stmt) {
            if ($stmt->getStartLine() >= $targetLine) {
                break;
            }

            if ($stmt instanceof Node\Stmt\Expression && $stmt->expr instanceof Assign) {
                if ($stmt->expr->var instanceof Variable && is_string($stmt->expr->var->name)) {
                    if ($stmt->expr->var->name === $varName) {
                        if ($this->expressionHasTenantContext($stmt->expr->expr, $config, $stmt)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    /**
     * @return list<Node\Stmt>|null
     */
    private function findEnclosingBlock(Node $node): ?array
    {
        $current = $node->getAttribute('parent');
        while ($current instanceof Node) {
            if ($current instanceof ClassMethod || $current instanceof Function_ || $current instanceof Expr\Closure) {
                return $current->stmts !== null ? array_values($current->stmts) : null;
            }
            $current = $current->getAttribute('parent');
        }

        return null;
    }

    private function isCacheReceiver(Expr $expr): bool
    {
        $cursor = $expr;
        while ($cursor instanceof MethodCall) {
            $cursor = $cursor->var;
        }

        if ($cursor instanceof StaticCall && $cursor->class instanceof Name) {
            return $this->shortName($cursor->class->toString()) === 'Cache';
        }

        if ($cursor instanceof FuncCall && $cursor->name instanceof Name) {
            return strtolower($cursor->name->toString()) === 'cache';
        }

        return false;
    }

    private function receiverHasTenantTags(Expr $expr, GuardConfig $config): bool
    {
        $cursor = $expr;
        while ($cursor instanceof MethodCall || $cursor instanceof StaticCall) {
            if (
                $cursor->name instanceof Identifier
                && $cursor->name->toString() === 'tags'
                && isset($cursor->args[0])
                && $cursor->args[0] instanceof Arg
            ) {
                $tagArg = $cursor->args[0]->value;
                if ($this->expressionHasTenantContext($tagArg, $config, $cursor)) {
                    return true;
                }
                if ($tagArg instanceof Expr\Array_) {
                    foreach ($tagArg->items as $item) {
                        if ($item !== null && $this->expressionHasTenantContext($item->value, $config, $cursor)) {
                            return true;
                        }
                    }
                }
            }

            $cursor = $cursor instanceof MethodCall ? $cursor->var : null;
        }

        return false;
    }

    private function receiverIsTenantIsolatedStore(Expr $expr, GuardConfig $config): bool
    {
        $cursor = $expr;
        while ($cursor instanceof MethodCall || $cursor instanceof StaticCall) {
            if (
                $cursor->name instanceof Identifier
                && in_array($cursor->name->toString(), ['store', 'driver'], true)
                && isset($cursor->args[0])
                && $cursor->args[0] instanceof Arg
                && $cursor->args[0]->value instanceof String_
            ) {
                if ($config->isTenantCacheStore($cursor->args[0]->value->value)) {
                    return true;
                }
            }

            $cursor = $cursor instanceof MethodCall ? $cursor->var : null;
        }

        return false;
    }

    private function isStorageReceiver(Expr $expr): bool
    {
        $cursor = $expr;
        while ($cursor instanceof MethodCall) {
            $cursor = $cursor->var;
        }

        if ($cursor instanceof StaticCall && $cursor->class instanceof Name) {
            return $this->shortName($cursor->class->toString()) === 'Storage';
        }

        return false;
    }

    private function storageDiskReceiverIsTenantIsolated(Expr $expr, GuardConfig $config): bool
    {
        $cursor = $expr;
        while ($cursor instanceof MethodCall || $cursor instanceof StaticCall) {
            if (
                $cursor->name instanceof Identifier
                && $cursor->name->toString() === 'disk'
                && isset($cursor->args[0])
                && $cursor->args[0] instanceof Arg
            ) {
                $val = $cursor->args[0]->value;
                if ($val instanceof String_ && $config->isTenantDisk($val->value)) {
                    return true;
                }
                if ($this->expressionHasTenantContext($val, $config, $cursor)) {
                    return true;
                }
            }

            $cursor = $cursor instanceof MethodCall ? $cursor->var : null;
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

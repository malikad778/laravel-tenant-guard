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
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\InterpolatedString;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Function_;

final class UnscopedDatabaseQueryRule implements TenantRuleInterface
{
    /** @var list<string> */
    private const RAW_DB_METHODS = [
        'select',
        'selectOne',
        'statement',
        'unprepared',
        'cursor',
        'affectingStatement',
        'insert',
        'update',
        'delete',
    ];

    /** @var list<string> */
    private const SCOPE_STRIPPING_METHODS = [
        'withoutGlobalScopes',
        'withoutGlobalScope',
        'newQueryWithoutScopes',
        'toBase',
    ];

    private const NON_TENANT_SCOPES = [
        'softdeletingscope',
        'softdeletes',
        'trashed',
    ];

    public function ruleId(): string
    {
        return 'unscoped_database_query';
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

        $className = $call->class->toString();
        $shortClass = $this->shortName($className);
        $methodName = $call->name->toString();

        // Case 1: DB::table('invoices') or DB::query()->from('invoices')
        if ($this->isDbFacade($className, $shortClass) && in_array($methodName, ['table', 'from'], true)) {
            $tableName = $this->extractTableName($call->args);
            if ($tableName !== null && !$config->isTenantTable($tableName)) {
                return [];
            }

            if ($this->chainContainsTenantConstraint($call, $config)) {
                return [];
            }

            if ($this->isAssignedAndSubsequentlyScoped($call, $config)) {
                return [];
            }

            $line = $call->getStartLine();
            $targetLabel = $tableName ?? 'dynamic table';

            return [
                new Violation(
                    ruleId: $this->ruleId(),
                    file: $filePath,
                    line: $line,
                    message: sprintf(
                        "Unscoped query builder call DB::%s('%s') bypasses Eloquent global tenant scopes.",
                        $methodName,
                        $targetLabel
                    ),
                    suggestion: sprintf(
                        "Use the Eloquent model with a global tenant scope, chain ->where('%s', \$tenantId), or annotate with /** %s */.",
                        $config->tenantColumns[0] ?? 'company_id',
                        $config->ignoreAnnotation
                    ),
                    snippet: trim($sourceLines[$line - 1] ?? '')
                ),
            ];
        }

        // Case 2: Raw SQL execution via DB::select(...), DB::insert(...), DB::update(...), etc.
        if ($this->isDbFacade($className, $shortClass) && in_array($methodName, self::RAW_DB_METHODS, true)) {
            $sql = $this->extractSqlText($call->args);
            if ($sql === null) {
                return [];
            }

            $referencedTenantTable = $this->findTenantTableInSql($sql, $config);
            if ($referencedTenantTable === null) {
                return [];
            }

            if ($this->sqlContainsTenantColumn($sql, $config)) {
                return [];
            }

            $line = $call->getStartLine();
            return [
                new Violation(
                    ruleId: $this->ruleId(),
                    file: $filePath,
                    line: $line,
                    message: sprintf(
                        "Unscoped raw SQL call DB::%s() queries tenant table '%s' without a tenant column filter.",
                        $methodName,
                        $referencedTenantTable
                    ),
                    suggestion: sprintf(
                        "Add a '%s' WHERE clause parameter to the query or annotate with /** %s */.",
                        $config->tenantColumns[0] ?? 'company_id',
                        $config->ignoreAnnotation
                    ),
                    snippet: trim($sourceLines[$line - 1] ?? '')
                ),
            ];
        }

        // Case 3: Model::withoutGlobalScopes(), Model::withoutGlobalScope(), or Model::toBase()
        if (
            !$this->isDbFacade($className, $shortClass)
            && in_array($methodName, self::SCOPE_STRIPPING_METHODS, true)
            && $config->isTenantModel($className)
        ) {
            if ($this->isSafeScopeStrippingCall($call)) {
                return [];
            }

            if ($this->chainContainsTenantConstraint($call, $config)) {
                return [];
            }

            if ($this->isAssignedAndSubsequentlyScoped($call, $config)) {
                return [];
            }

            $line = $call->getStartLine();
            return [
                new Violation(
                    ruleId: $this->ruleId(),
                    file: $filePath,
                    line: $line,
                    message: sprintf(
                        "Call to %s::%s() strips global tenant scopes without applying an explicit tenant constraint.",
                        $shortClass,
                        $methodName
                    ),
                    suggestion: sprintf(
                        "Chain ->where('%s', \$tenantId) after %s() or mark with /** %s */.",
                        $config->tenantColumns[0] ?? 'company_id',
                        $methodName,
                        $config->ignoreAnnotation
                    ),
                    snippet: trim($sourceLines[$line - 1] ?? '')
                ),
            ];
        }

        return [];
    }

    /**
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

        $methodName = $call->name->toString();

        // Chained DB::connection(...)->table('invoices') or DB::connection()->select(...)
        if ($this->isDbReceiver($call->var)) {
            if (in_array($methodName, ['table', 'from', 'fromRaw'], true)) {
                $tableName = $this->extractTableName($call->args);
                if ($tableName !== null && !$config->isTenantTable($tableName)) {
                    return [];
                }

                if ($this->chainContainsTenantConstraint($call, $config)) {
                    return [];
                }

                if ($this->isAssignedAndSubsequentlyScoped($call, $config)) {
                    return [];
                }

                $line = $call->getStartLine();
                return [
                    new Violation(
                        ruleId: $this->ruleId(),
                        file: $filePath,
                        line: $line,
                        message: sprintf(
                            "Unscoped query builder call ->%s('%s') bypasses Eloquent global tenant scopes.",
                            $methodName,
                            $tableName ?? 'dynamic table'
                        ),
                        suggestion: sprintf(
                            "Scope the query with ->where('%s', \$tenantId) or mark with /** %s */.",
                            $config->tenantColumns[0] ?? 'company_id',
                            $config->ignoreAnnotation
                        ),
                        snippet: trim($sourceLines[$line - 1] ?? '')
                    ),
                ];
            }

            if (in_array($methodName, self::RAW_DB_METHODS, true)) {
                $sql = $this->extractSqlText($call->args);
                if ($sql !== null) {
                    $referencedTenantTable = $this->findTenantTableInSql($sql, $config);
                    if ($referencedTenantTable !== null && !$this->sqlContainsTenantColumn($sql, $config)) {
                        $line = $call->getStartLine();
                        return [
                            new Violation(
                                ruleId: $this->ruleId(),
                                file: $filePath,
                                line: $line,
                                message: sprintf(
                                    "Unscoped raw SQL call ->%s() queries tenant table '%s' without a tenant column filter.",
                                    $methodName,
                                    $referencedTenantTable
                                ),
                                suggestion: sprintf(
                                    "Add a '%s' WHERE clause parameter to the query or annotate with /** %s */.",
                                    $config->tenantColumns[0] ?? 'company_id',
                                    $config->ignoreAnnotation
                                ),
                                snippet: trim($sourceLines[$line - 1] ?? '')
                            ),
                        ];
                    }
                }
            }
        }

        // Scope stripping methods on Eloquent query chains
        if (in_array($methodName, self::SCOPE_STRIPPING_METHODS, true)) {
            // Avoid duplicate reporting if FilamentResourceTenantRule is handling this Filament class
            if ($this->isInsideFilamentResourceClass($call, $config)) {
                return [];
            }

            // Deduplicate if already chained directly from another scope-stripping call
            if ($call->var instanceof MethodCall && $call->var->name instanceof Identifier && in_array($call->var->name->toString(), self::SCOPE_STRIPPING_METHODS, true)) {
                return [];
            }

            if ($this->isSafeScopeStrippingCall($call)) {
                return [];
            }

            if ($this->chainContainsTenantConstraint($call, $config)) {
                return [];
            }

            if ($this->isAssignedAndSubsequentlyScoped($call, $config)) {
                return [];
            }

            $rootModel = $this->resolveRootClassName($call->var);
            if ($rootModel !== null && !$config->isTenantModel($rootModel)) {
                return [];
            }

            $line = $call->getStartLine();
            $targetLabel = $rootModel !== null ? $this->shortName($rootModel) : 'Query';

            return [
                new Violation(
                    ruleId: $this->ruleId(),
                    file: $filePath,
                    line: $line,
                    message: sprintf(
                        "%s chain invokes ->%s() without re-applying an explicit tenant constraint.",
                        $targetLabel,
                        $methodName
                    ),
                    suggestion: sprintf(
                        "Chain ->where('%s', \$tenantId) or annotate with /** %s */ if cross-tenant access is intentional.",
                        $config->tenantColumns[0] ?? 'company_id',
                        $config->ignoreAnnotation
                    ),
                    snippet: trim($sourceLines[$line - 1] ?? '')
                ),
            ];
        }

        return [];
    }

    /**
     * Determines whether a call to withoutGlobalScopes() or withoutGlobalScope() only strips
     * non-tenant scopes, such as SoftDeletingScope.
     */
    private function isSafeScopeStrippingCall(StaticCall|MethodCall $call): bool
    {
        if ($call->args === []) {
            // withoutGlobalScopes() without arguments strips ALL scopes, including tenant scopes!
            return false;
        }

        foreach ($call->args as $arg) {
            if (!$arg instanceof Arg) {
                continue;
            }

            $val = $arg->value;

            // withoutGlobalScope(SoftDeletingScope::class)
            if ($val instanceof Expr\ClassConstFetch && $val->class instanceof Name) {
                $scopeClass = strtolower($this->shortName($val->class->toString()));
                if (!in_array($scopeClass, self::NON_TENANT_SCOPES, true)) {
                    return false;
                }
            } elseif ($val instanceof String_) {
                $scopeName = strtolower($val->value);
                if (!in_array($scopeName, self::NON_TENANT_SCOPES, true)) {
                    return false;
                }
            } elseif ($val instanceof Array_) {
                // withoutGlobalScopes([SoftDeletingScope::class])
                foreach ($val->items as $item) {
                    if ($item === null) {
                        continue;
                    }
                    if ($item->value instanceof Expr\ClassConstFetch && $item->value->class instanceof Name) {
                        $scopeClass = strtolower($this->shortName($item->value->class->toString()));
                        if (!in_array($scopeClass, self::NON_TENANT_SCOPES, true)) {
                            return false;
                        }
                    } elseif ($item->value instanceof String_) {
                        $scopeName = strtolower($item->value->value);
                        if (!in_array($scopeName, self::NON_TENANT_SCOPES, true)) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            } else {
                return false;
            }
        }

        return true;
    }

    /**
     * Walks both up and down the fluent method chain surrounding $node to see
     * whether a tenant constraint is applied anywhere on the query expression.
     */
    private function chainContainsTenantConstraint(Expr $node, GuardConfig $config): bool
    {
        $cursor = $node;
        while ($cursor instanceof MethodCall) {
            if ($this->isTenantScopingMethodCall($cursor, $config)) {
                return true;
            }
            $cursor = $cursor->var;
        }

        $current = $node;
        while (true) {
            $parent = $current->getAttribute('parent');
            if (!$parent instanceof MethodCall || $parent->var !== $current) {
                break;
            }

            if ($this->isTenantScopingMethodCall($parent, $config)) {
                return true;
            }

            $current = $parent;
        }

        return false;
    }

    /**
     * Checks if the query expression was assigned to a local variable (e.g. $q = DB::table('invoices');)
     * and subsequently scoped via $q->where('company_id', $id) in the same function/method block.
     */
    private function isAssignedAndSubsequentlyScoped(Expr $node, GuardConfig $config): bool
    {
        $parent = $node->getAttribute('parent');
        while ($parent instanceof MethodCall && $parent->var === $node) {
            $node = $parent;
            $parent = $node->getAttribute('parent');
        }

        if (!$parent instanceof Assign || !$parent->var instanceof Variable || !is_string($parent->var->name)) {
            return false;
        }

        $varName = $parent->var->name;
        $enclosingBlock = $this->findEnclosingBlock($parent);
        if ($enclosingBlock === null) {
            return false;
        }

        return $this->blockScopesVariable($enclosingBlock, $varName, $config, $parent->getStartLine());
    }

    /**
     * @param list<Node\Stmt> $stmts
     */
    private function blockScopesVariable(array $stmts, string $varName, GuardConfig $config, int $afterLine): bool
    {
        foreach ($stmts as $stmt) {
            if ($stmt->getStartLine() < $afterLine) {
                continue;
            }

            if ($this->nodeScopesVariable($stmt, $varName, $config)) {
                return true;
            }
        }

        return false;
    }

    private function nodeScopesVariable(Node $node, string $varName, GuardConfig $config): bool
    {
        if ($node instanceof MethodCall) {
            if ($node->var instanceof Variable && is_string($node->var->name) && $node->var->name === $varName) {
                if ($this->isTenantScopingMethodCall($node, $config)) {
                    return true;
                }
            }
        }

        foreach ($node->getSubNodeNames() as $subName) {
            $sub = $node->$subName;
            if ($sub instanceof Node && $this->nodeScopesVariable($sub, $varName, $config)) {
                return true;
            }
            if (is_array($sub)) {
                foreach ($sub as $child) {
                    if ($child instanceof Node && $this->nodeScopesVariable($child, $varName, $config)) {
                        return true;
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
            if ($current instanceof ClassMethod || $current instanceof Function_ || $current instanceof Closure) {
                return $current->stmts !== null ? array_values($current->stmts) : null;
            }
            $current = $current->getAttribute('parent');
        }

        return null;
    }

    private function isTenantScopingMethodCall(MethodCall $call, GuardConfig $config): bool
    {
        if (!$call->name instanceof Identifier) {
            return false;
        }

        $method = $call->name->toString();

        if (in_array($method, $config->safeScopeMethods, true)) {
            if ($method === 'whereBelongsTo') {
                return $this->whereBelongsToIsTenant($call, $config);
            }
            return true;
        }

        if ($method === 'whereRaw' && isset($call->args[0]) && $call->args[0] instanceof Arg) {
            $sql = $this->extractSqlText([$call->args[0]]);
            if ($sql !== null && $this->sqlContainsTenantColumn($sql, $config)) {
                return true;
            }
        }

        if (!in_array($method, ['where', 'whereIn', 'whereColumn'], true)) {
            return false;
        }

        if ($call->args === [] || !$call->args[0] instanceof Arg) {
            return false;
        }

        $firstArg = $call->args[0]->value;

        // ->where('company_id', $id) or ->where('company_id', '=', $id)
        if ($firstArg instanceof String_) {
            if (!$config->isTenantColumn($firstArg->value)) {
                return false;
            }

            // Check comparison operator if 3 arguments are passed
            if (count($call->args) >= 3 && $call->args[1] instanceof Arg) {
                $opVal = $call->args[1]->value;
                if ($opVal instanceof String_) {
                    $op = strtolower(trim($opVal->value));
                    // Reject negative operators
                    if (in_array($op, ['!=', '<>', 'not in', 'not like', 'not ilike'], true)) {
                        return false;
                    }
                }
            }

            return true;
        }

        // ->where(['company_id' => $id])
        if ($firstArg instanceof Array_) {
            foreach ($firstArg->items as $item) {
                if ($item === null) {
                    continue;
                }
                if ($item->key instanceof String_ && $config->isTenantColumn($item->key->value)) {
                    return true;
                }
            }
        }

        // ->where(fn ($q) => $q->where('company_id', $id))
        if ($firstArg instanceof Closure || $firstArg instanceof ArrowFunction) {
            return $this->closureContainsTenantWhere($firstArg, $config);
        }

        return false;
    }

    private function whereBelongsToIsTenant(MethodCall $call, GuardConfig $config): bool
    {
        if ($call->args === [] || !$call->args[0] instanceof Arg) {
            return false;
        }

        $argVal = $call->args[0]->value;

        // $call->whereBelongsTo($tenant) or $call->whereBelongsTo($user->company)
        if ($argVal instanceof Variable && is_string($argVal->name)) {
            $name = strtolower($argVal->name);
            foreach ($config->tenantContextIdentifiers as $id) {
                if ($name === strtolower($id) || str_contains($name, strtolower($id))) {
                    return true;
                }
            }
        }

        if ($argVal instanceof PropertyFetch && $argVal->name instanceof Identifier) {
            $name = strtolower($argVal->name->toString());
            foreach ($config->tenantContextIdentifiers as $id) {
                if ($name === strtolower($id) || str_contains($name, strtolower($id))) {
                    return true;
                }
            }
        }

        if ($argVal instanceof MethodCall && $argVal->name instanceof Identifier) {
            $name = strtolower($argVal->name->toString());
            foreach ($config->tenantContextIdentifiers as $id) {
                if ($name === strtolower($id) || str_contains($name, strtolower($id))) {
                    return true;
                }
            }
        }

        if ($argVal instanceof StaticCall && $argVal->class instanceof Name) {
            $cls = strtolower($this->shortName($argVal->class->toString()));
            if (str_contains($cls, 'filament') || str_contains($cls, 'tenant')) {
                return true;
            }
        }

        // If second argument specifies relation name, e.g. whereBelongsTo($model, 'company')
        if (count($call->args) >= 2 && $call->args[1] instanceof Arg && $call->args[1]->value instanceof String_) {
            $relation = strtolower($call->args[1]->value->value);
            foreach ($config->tenantContextIdentifiers as $id) {
                if ($relation === strtolower($id) || str_contains($relation, strtolower($id))) {
                    return true;
                }
            }
        }

        return false;
    }

    private function closureContainsTenantWhere(Closure|ArrowFunction $fn, GuardConfig $config): bool
    {
        $nodes = $fn instanceof Closure ? $fn->stmts : [$fn->expr];
        return $this->nodesContainTenantCall($nodes, $config);
    }

    /**
     * @param array<int, Node|null> $nodes
     */
    private function nodesContainTenantCall(array $nodes, GuardConfig $config): bool
    {
        foreach ($nodes as $node) {
            if (!$node instanceof Node) {
                continue;
            }

            if ($node instanceof MethodCall && $this->isTenantScopingMethodCall($node, $config)) {
                return true;
            }

            foreach ($node->getSubNodeNames() as $subName) {
                $sub = $node->$subName;
                if ($sub instanceof Node && $this->nodesContainTenantCall([$sub], $config)) {
                    return true;
                }
                if (is_array($sub) && $this->nodesContainTenantCall($sub, $config)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param array<mixed> $args
     */
    private function extractTableName(array $args): ?string
    {
        if ($args === [] || !$args[0] instanceof Arg) {
            return null;
        }

        $val = $args[0]->value;
        if ($val instanceof String_) {
            return $val->value;
        }

        if ($val instanceof InterpolatedString) {
            $buffer = '';
            foreach ($val->parts as $part) {
                if ($part instanceof Node\InterpolatedStringPart) {
                    $buffer .= $part->value;
                }
            }
            return $buffer !== '' ? $buffer : null;
        }

        return null;
    }

    /**
     * @param array<mixed> $args
     */
    private function extractSqlText(array $args): ?string
    {
        if ($args === [] || !$args[0] instanceof Arg) {
            return null;
        }

        $val = $args[0]->value;
        if ($val instanceof String_) {
            return $val->value;
        }

        if ($val instanceof InterpolatedString) {
            $buffer = '';
            foreach ($val->parts as $part) {
                if ($part instanceof Node\InterpolatedStringPart) {
                    $buffer .= $part->value;
                } else {
                    $buffer .= ' ? ';
                }
            }
            return $buffer;
        }

        if ($val instanceof Concat) {
            $left = $this->extractSqlText([new Arg($val->left)]);
            $right = $this->extractSqlText([new Arg($val->right)]);
            if ($left !== null || $right !== null) {
                return ($left ?? '') . ' ' . ($right ?? '');
            }
        }

        return null;
    }

    private function findTenantTableInSql(string $sql, GuardConfig $config): ?string
    {
        $cleanSql = $this->stripSqlComments($sql);
        $pattern = '/\b(?:FROM|JOIN|UPDATE|INTO)\s+[`"\'\s]?([a-zA-Z0-9_\.]+)[`"\'\s]?/i';
        if (preg_match_all($pattern, $cleanSql, $matches) === false) {
            return null;
        }

        foreach ($matches[1] as $table) {
            $cleanTable = trim($table, "`'\" \t\n\r");
            if ($config->isTenantTable($cleanTable)) {
                return $cleanTable;
            }
        }

        return null;
    }

    private function sqlContainsTenantColumn(string $sql, GuardConfig $config): bool
    {
        $cleanSql = strtolower($this->stripSqlComments($sql));
        foreach ($config->tenantColumns as $column) {
            if (preg_match('/\b' . preg_quote(strtolower($column), '/') . '\b/', $cleanSql) === 1) {
                return true;
            }
        }

        return false;
    }

    private function stripSqlComments(string $sql): string
    {
        // Strip single line -- comments
        $sql = preg_replace('/--.*$/m', '', $sql) ?? $sql;
        // Strip single line # comments
        $sql = preg_replace('/#.*$/m', '', $sql) ?? $sql;
        // Strip /* ... */ multi-line comments
        $sql = preg_replace('/\/\*.*?\*\//s', '', $sql) ?? $sql;

        return $sql;
    }

    private function isDbReceiver(Expr $expr): bool
    {
        $cursor = $expr;
        while ($cursor instanceof MethodCall) {
            $cursor = $cursor->var;
        }

        if ($cursor instanceof StaticCall && $cursor->class instanceof Name) {
            $short = $this->shortName($cursor->class->toString());
            return $this->isDbFacade($cursor->class->toString(), $short);
        }

        return false;
    }

    private function resolveRootClassName(Expr $expr): ?string
    {
        $cursor = $expr;
        while ($cursor instanceof MethodCall) {
            $cursor = $cursor->var;
        }

        if ($cursor instanceof StaticCall && $cursor->class instanceof Name) {
            return $cursor->class->toString();
        }

        return null;
    }

    private function isDbFacade(string $className, string $shortClass): bool
    {
        return $shortClass === 'DB'
            || strcasecmp($className, 'Illuminate\Support\Facades\DB') === 0;
    }

    private function isInsideFilamentResourceClass(Node $call, GuardConfig $config): bool
    {
        if (!$config->isRuleEnabled('filament_resource_tenant')) {
            return false;
        }

        $current = $call->getAttribute('parent');
        while ($current instanceof Node) {
            if ($current instanceof Stmt\Class_) {
                if ($current->extends !== null) {
                    $ext = $current->extends->toString();
                    if ($ext === 'Filament\Resources\Resource' || str_contains($ext, 'Filament\Resources\Resource')) {
                        return true;
                    }
                    $short = $this->shortName($ext);
                    if ($short === 'Resource' || str_ends_with($short, 'Resource') || $short === 'BaseResource') {
                        return true;
                    }
                }
                return false;
            }
            $current = $current->getAttribute('parent');
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


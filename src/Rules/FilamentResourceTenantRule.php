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
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Property;
use PhpParser\Node\Stmt\Return_;

final class FilamentResourceTenantRule implements TenantRuleInterface
{
    private const NON_TENANT_SCOPES = [
        'softdeletingscope',
        'softdeletes',
        'trashed',
    ];

    public function ruleId(): string
    {
        return 'filament_resource_tenant';
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

        if (!$node instanceof Class_) {
            return [];
        }

        if (!$this->isFilamentClass($node)) {
            return [];
        }

        if (DocblockInspector::isMarkedTenantSafe($node, $config->ignoreAnnotation, $sourceLines)) {
            return [];
        }

        $className = $node->name instanceof Identifier ? $node->name->toString() : 'AnonymousClass';
        $violations = [];

        // Check if resource targets a global model
        $modelClass = $this->extractResourceModelClass($node);
        if ($modelClass !== null && !$config->isTenantModel($modelClass)) {
            return [];
        }

        // Check 1: Explicit $isScopedToTenant = false without @tenant-safe
        $scopedToTenantProp = $this->findProperty($node, 'isScopedToTenant');
        if ($scopedToTenantProp !== null && $this->propertyIsFalse($scopedToTenantProp)) {
            if (!DocblockInspector::isMarkedTenantSafe($scopedToTenantProp, $config->ignoreAnnotation, $sourceLines)) {
                $line = $scopedToTenantProp->getStartLine();
                $violations[] = new Violation(
                    ruleId: $this->ruleId(),
                    file: $filePath,
                    line: $line,
                    message: sprintf(
                        "Filament class '%s' disables tenant scoping via \$isScopedToTenant = false.",
                        $className
                    ),
                    suggestion: sprintf(
                        "Remove \$isScopedToTenant = false or annotate with /** %s */ if this class is intentionally global.",
                        $config->ignoreAnnotation
                    ),
                    snippet: trim($sourceLines[$line - 1] ?? '')
                );
            }
        }

        // Check 2: Missing $tenantOwnershipRelationshipName property (if strictly configured)
        if ($config->requireFilamentOwnershipRelationship && $this->isFilamentResourceClass($node)) {
            $ownershipProp = $this->findProperty($node, 'tenantOwnershipRelationshipName');
            if ($ownershipProp === null || $this->propertyIsNull($ownershipProp)) {
                $line = $node->getStartLine();
                $violations[] = new Violation(
                    ruleId: $this->ruleId(),
                    file: $filePath,
                    line: $line,
                    message: sprintf(
                        "Filament resource '%s' is missing protected static ?string \$tenantOwnershipRelationshipName.",
                        $className
                    ),
                    suggestion: sprintf(
                        "Define protected static ?string \$tenantOwnershipRelationshipName = 'company'; on %s, or annotate with /** %s */.",
                        $className,
                        $config->ignoreAnnotation
                    ),
                    snippet: trim($sourceLines[$line - 1] ?? '')
                );
            }
        }

        // Check 3: Inspect getEloquentQuery() override if present
        if ($config->checkFilamentEloquentQueryOverride) {
            $eloquentQueryMethod = $node->getMethod('getEloquentQuery');
            if (
                $eloquentQueryMethod !== null
                && !DocblockInspector::isMarkedTenantSafe($eloquentQueryMethod, $config->ignoreAnnotation, $sourceLines)
            ) {
                $methodViolation = $this->inspectGetEloquentQuery($eloquentQueryMethod, $className, $filePath, $config, $sourceLines);
                if ($methodViolation !== null) {
                    $violations[] = $methodViolation;
                }
            }
        }

        return $violations;
    }

    /**
     * @param list<string> $sourceLines
     */
    private function inspectGetEloquentQuery(
        ClassMethod $method,
        string $className,
        string $filePath,
        GuardConfig $config,
        array $sourceLines
    ): ?Violation {
        $stmts = $method->stmts ?? [];

        $stripsAllGlobalScopes = $this->hasUnsafeGlobalScopeStripping($stmts);
        $callsParentQuery = $this->nodesCallParentEloquentQuery($stmts);
        $appliesExplicitTenantScope = $this->returnStatementAppliesTenantScope($stmts, $config);

        if ($stripsAllGlobalScopes && !$appliesExplicitTenantScope) {
            $line = $method->getStartLine();
            return new Violation(
                ruleId: $this->ruleId(),
                file: $filePath,
                line: $line,
                message: sprintf(
                    "%s::getEloquentQuery() calls withoutGlobalScopes() without re-applying a tenant scope constraint.",
                    $className
                ),
                suggestion: sprintf(
                    "Scope the query via ->whereBelongsTo(Filament::getTenant()) or ->where('%s', Filament::getTenant()->id).",
                    $config->tenantColumns[0] ?? 'company_id'
                ),
                snippet: trim($sourceLines[$line - 1] ?? '')
            );
        }

        if (!$callsParentQuery && !$appliesExplicitTenantScope) {
            $line = $method->getStartLine();
            return new Violation(
                ruleId: $this->ruleId(),
                file: $filePath,
                line: $line,
                message: sprintf(
                    "%s::getEloquentQuery() overrides the base query without calling parent::getEloquentQuery() or scoping to the active tenant.",
                    $className
                ),
                suggestion: "Start from parent::getEloquentQuery() or chain ->whereBelongsTo(Filament::getTenant()).",
                snippet: trim($sourceLines[$line - 1] ?? '')
            );
        }

        return null;
    }

    private function isFilamentClass(Class_ $class): bool
    {
        return $this->isFilamentResourceClass($class)
            || $this->isFilamentPageClass($class)
            || $this->isFilamentRelationManagerClass($class);
    }

    private function isFilamentResourceClass(Class_ $class): bool
    {
        if ($class->extends === null) {
            return false;
        }

        $extended = $class->extends->toString();

        // Reject Laravel Nova resources and API JsonResources
        if (str_contains($extended, 'Nova\Resource') || str_contains($extended, 'JsonResource') || str_contains($extended, 'Http\Resources')) {
            return false;
        }

        if ($extended === 'Filament\Resources\Resource' || str_contains($extended, 'Filament\Resources\Resource')) {
            return true;
        }

        $shortExtended = $this->shortName($extended);
        $shortClass = $class->name instanceof Identifier ? $class->name->toString() : '';

        // Handle BaseResource or classes ending with Resource extending *Resource
        if (str_ends_with($shortClass, 'Resource') && (str_ends_with($shortExtended, 'Resource') || $shortExtended === 'BaseResource')) {
            return true;
        }

        return false;
    }

    private function isFilamentPageClass(Class_ $class): bool
    {
        if ($class->extends === null) {
            return false;
        }

        $extended = $class->extends->toString();
        return str_contains($extended, 'Filament\Pages')
            || str_contains($extended, 'Filament\Resources\Pages')
            || in_array($this->shortName($extended), ['ListRecords', 'ManageRecords', 'EditRecord', 'CreateRecord', 'ViewRecord'], true);
    }

    private function isFilamentRelationManagerClass(Class_ $class): bool
    {
        if ($class->extends === null) {
            return false;
        }

        $extended = $class->extends->toString();
        return str_contains($extended, 'Filament\Resources\RelationManagers\RelationManager')
            || $this->shortName($extended) === 'RelationManager';
    }

    /**
     * @param array<int, Node|null> $stmts
     */
    private function hasUnsafeGlobalScopeStripping(array $stmts): bool
    {
        foreach ($stmts as $stmt) {
            if (!$stmt instanceof Node) {
                continue;
            }

            if (($stmt instanceof MethodCall || $stmt instanceof StaticCall) && $stmt->name instanceof Identifier) {
                $method = $stmt->name->toString();
                if ($method === 'withoutGlobalScopes') {
                    // withoutGlobalScopes() with NO arguments strips all scopes
                    if ($stmt->args === []) {
                        return true;
                    }

                    // If it has arguments, check if they are only non-tenant scopes like SoftDeletingScope
                    if (!$this->isOnlySafeScopeArguments($stmt->args)) {
                        return true;
                    }
                } elseif ($method === 'withoutGlobalScope') {
                    if (!$this->isOnlySafeScopeArguments($stmt->args)) {
                        return true;
                    }
                }
            }

            foreach ($stmt->getSubNodeNames() as $subName) {
                $sub = $stmt->$subName;
                if ($sub instanceof Node && $this->hasUnsafeGlobalScopeStripping([$sub])) {
                    return true;
                }
                if (is_array($sub) && $this->hasUnsafeGlobalScopeStripping($sub)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param array<mixed> $args
     */
    private function isOnlySafeScopeArguments(array $args): bool
    {
        if ($args === []) {
            return false;
        }

        foreach ($args as $arg) {
            if (!$arg instanceof Arg) {
                continue;
            }

            $val = $arg->value;
            if ($val instanceof ClassConstFetch && $val->class instanceof Name) {
                $scope = strtolower($this->shortName($val->class->toString()));
                if (!in_array($scope, self::NON_TENANT_SCOPES, true)) {
                    return false;
                }
            } elseif ($val instanceof String_) {
                $scope = strtolower($val->value);
                if (!in_array($scope, self::NON_TENANT_SCOPES, true)) {
                    return false;
                }
            } elseif ($val instanceof Expr\Array_) {
                foreach ($val->items as $item) {
                    if ($item === null) {
                        continue;
                    }
                    if ($item->value instanceof ClassConstFetch && $item->value->class instanceof Name) {
                        $scope = strtolower($this->shortName($item->value->class->toString()));
                        if (!in_array($scope, self::NON_TENANT_SCOPES, true)) {
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
     * @param array<int, Node|null> $stmts
     */
    private function nodesCallParentEloquentQuery(array $stmts): bool
    {
        foreach ($stmts as $stmt) {
            if (!$stmt instanceof Node) {
                continue;
            }

            if (
                $stmt instanceof StaticCall
                && $stmt->class instanceof Name
                && strtolower($stmt->class->toString()) === 'parent'
                && $stmt->name instanceof Identifier
                && $stmt->name->toString() === 'getEloquentQuery'
            ) {
                return true;
            }

            foreach ($stmt->getSubNodeNames() as $subName) {
                $sub = $stmt->$subName;
                if ($sub instanceof Node && $this->nodesCallParentEloquentQuery([$sub])) {
                    return true;
                }
                if (is_array($sub) && $this->nodesCallParentEloquentQuery($sub)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Checks if the return statement of getEloquentQuery() applies a tenant constraint on the root query.
     *
     * @param array<int, Node\Stmt> $stmts
     */
    private function returnStatementAppliesTenantScope(array $stmts, GuardConfig $config): bool
    {
        foreach ($stmts as $stmt) {
            if ($stmt instanceof Return_ && $stmt->expr !== null) {
                if ($this->queryChainAppliesTenantScope($stmt->expr, $config)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function queryChainAppliesTenantScope(Expr $expr, GuardConfig $config): bool
    {
        $cursor = $expr;
        while ($cursor instanceof MethodCall) {
            if ($cursor->name instanceof Identifier) {
                $method = $cursor->name->toString();
                if (in_array($method, $config->safeScopeMethods, true)) {
                    return true;
                }

                if (
                    in_array($method, ['where', 'whereIn'], true)
                    && isset($cursor->args[0])
                    && $cursor->args[0] instanceof Arg
                    && $cursor->args[0]->value instanceof String_
                    && $config->isTenantColumn($cursor->args[0]->value->value)
                ) {
                    return true;
                }
            }

            $cursor = $cursor->var;
        }

        return false;
    }

    private function extractResourceModelClass(Class_ $class): ?string
    {
        $prop = $this->findProperty($class, 'model');
        if ($prop === null || $prop->props === []) {
            return null;
        }

        $default = $prop->props[0]->default;
        if ($default instanceof ClassConstFetch && $default->class instanceof Name) {
            return $default->class->toString();
        }

        if ($default instanceof String_) {
            return $default->value;
        }

        return null;
    }

    private function findProperty(Class_ $class, string $propertyName): ?Property
    {
        foreach ($class->stmts as $stmt) {
            if (!$stmt instanceof Property) {
                continue;
            }
            foreach ($stmt->props as $prop) {
                if ($prop->name->toString() === $propertyName) {
                    return $stmt;
                }
            }
        }

        return null;
    }

    private function propertyIsFalse(Property $property): bool
    {
        $default = $property->props[0]->default ?? null;
        return $default instanceof ConstFetch
            && strtolower($default->name->toString()) === 'false';
    }

    private function propertyIsNull(Property $property): bool
    {
        $default = $property->props[0]->default ?? null;
        if ($default === null) {
            return true;
        }

        return $default instanceof ConstFetch
            && strtolower($default->name->toString()) === 'null';
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

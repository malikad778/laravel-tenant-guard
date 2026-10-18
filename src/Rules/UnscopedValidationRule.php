<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Rules;

use MalikAd\TenantGuard\Contracts\TenantRuleInterface;
use MalikAd\TenantGuard\Support\DocblockInspector;
use MalikAd\TenantGuard\Support\GuardConfig;
use MalikAd\TenantGuard\Support\Violation;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\ArrayItem;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\InterpolatedString;
use PhpParser\Node\Scalar\String_;

final class UnscopedValidationRule implements TenantRuleInterface
{
    public function ruleId(): string
    {
        return 'unscoped_validation';
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
            return $this->inspectRuleStaticCall($node, $filePath, $config, $sourceLines);
        }

        if ($node instanceof ArrayItem) {
            return $this->inspectValidationArrayItem($node, $filePath, $config, $sourceLines);
        }

        if ($node instanceof Assign) {
            return $this->inspectValidationAssign($node, $filePath, $config, $sourceLines);
        }

        return [];
    }

    /**
     * Inspects Rule::unique('users', 'email') and Rule::exists('invoices', 'id').
     *
     * @param list<string> $sourceLines
     * @return list<Violation>
     */
    private function inspectRuleStaticCall(
        StaticCall $call,
        string $filePath,
        GuardConfig $config,
        array $sourceLines
    ): array {
        if (!$call->class instanceof Name || !$call->name instanceof Identifier) {
            return [];
        }

        $shortClass = $this->shortName($call->class->toString());
        $method = $call->name->toString();

        if ($shortClass !== 'Rule' || !in_array($method, ['unique', 'exists'], true)) {
            return [];
        }

        if (DocblockInspector::isMarkedTenantSafe($call, $config->ignoreAnnotation, $sourceLines)) {
            return [];
        }

        $targetTableOrModel = $this->extractTargetTableOrModel($call, $config);
        if ($targetTableOrModel === null) {
            return [];
        }

        if ($this->ruleChainHasTenantWhere($call, $config)) {
            return [];
        }

        $line = $call->getStartLine();
        $tenantColumn = $config->tenantColumns[0] ?? 'company_id';

        return [
            new Violation(
                ruleId: $this->ruleId(),
                file: $filePath,
                line: $line,
                message: sprintf(
                    "Unscoped validation rule Rule::%s('%s') checks records across all tenants.",
                    $method,
                    $targetTableOrModel
                ),
                suggestion: sprintf(
                    "Scope the validation rule to the active tenant using ->where('%s', \$tenantId).",
                    $tenantColumn
                ),
                snippet: trim($sourceLines[$line - 1] ?? '')
            ),
        ];
    }

    /**
     * Inspects array item validation definitions like:
     * 'email' => 'required|unique:users,email'
     *
     * @param list<string> $sourceLines
     * @return list<Violation>
     */
    private function inspectValidationArrayItem(
        ArrayItem $item,
        string $filePath,
        GuardConfig $config,
        array $sourceLines
    ): array {
        if (DocblockInspector::isMarkedTenantSafe($item, $config->ignoreAnnotation, $sourceLines)) {
            return [];
        }

        $fieldName = $this->extractFieldName($item->key);
        return $this->evaluateValidationRules($item->value, $fieldName, $filePath, $config, $sourceLines);
    }

    /**
     * Inspects variable assignments like:
     * $rules['email'] = 'required|unique:users,email';
     *
     * @param list<string> $sourceLines
     * @return list<Violation>
     */
    private function inspectValidationAssign(
        Assign $assign,
        string $filePath,
        GuardConfig $config,
        array $sourceLines
    ): array {
        if ($assign->var instanceof Node\Expr\ArrayDimFetch) {
            $dim = $assign->var->dim;
            $fieldName = $dim !== null ? $this->extractFieldName($dim) : 'field';

            if (DocblockInspector::isMarkedTenantSafe($assign, $config->ignoreAnnotation, $sourceLines)) {
                return [];
            }

            return $this->evaluateValidationRules($assign->expr, $fieldName, $filePath, $config, $sourceLines);
        }

        return [];
    }

    /**
     * @param list<string> $sourceLines
     * @return list<Violation>
     */
    private function evaluateValidationRules(
        Node\Expr $expr,
        string $fieldName,
        string $filePath,
        GuardConfig $config,
        array $sourceLines
    ): array {
        $ruleStrings = $this->collectRuleStrings($expr);
        if ($ruleStrings === []) {
            return [];
        }

        $violations = [];
        $tenantColumn = $config->tenantColumns[0] ?? 'company_id';

        foreach ($ruleStrings as [$ruleString, $line]) {
            $segments = explode('|', $ruleString);
            foreach ($segments as $segment) {
                $parsed = $this->parseStringValidationRule(trim($segment));
                if ($parsed === null) {
                    continue;
                }

                [$ruleName, $table, $extraColumns] = $parsed;
                if (!$config->isTenantTable($table)) {
                    continue;
                }

                if ($this->hasTenantColumnInParameters($extraColumns, $config)) {
                    continue;
                }

                $violations[] = new Violation(
                    ruleId: $this->ruleId(),
                    file: $filePath,
                    line: $line,
                    message: sprintf(
                        "Validation rule '%s:%s' on field '%s' is not scoped to a tenant column.",
                        $ruleName,
                        $table,
                        $fieldName
                    ),
                    suggestion: sprintf(
                        "Replace string rule with Rule::%s('%s')->where('%s', \$tenantId).",
                        $ruleName,
                        $table,
                        $tenantColumn
                    ),
                    snippet: trim($sourceLines[$line - 1] ?? '')
                );
            }
        }

        return $violations;
    }

    private function extractFieldName(?Node $keyNode): string
    {
        if ($keyNode instanceof String_) {
            return $keyNode->value;
        }

        if ($keyNode instanceof Node\Expr\Variable && is_string($keyNode->name)) {
            return '$' . $keyNode->name;
        }

        return 'field';
    }

    private function extractTargetTableOrModel(StaticCall $call, GuardConfig $config): ?string
    {
        if ($call->args === [] || !$call->args[0] instanceof Arg) {
            return null;
        }

        $firstVal = $call->args[0]->value;

        if ($firstVal instanceof String_) {
            return $config->isTenantTable($firstVal->value) ? $firstVal->value : null;
        }

        if ($firstVal instanceof ClassConstFetch && $firstVal->class instanceof Name) {
            $className = $firstVal->class->toString();
            return $config->isTenantModel($className) ? $this->shortName($className) : null;
        }

        return null;
    }

    private function ruleChainHasTenantWhere(StaticCall $call, GuardConfig $config): bool
    {
        $current = $call;

        while (true) {
            $parent = $current->getAttribute('parent');
            if (!$parent instanceof MethodCall || $parent->var !== $current) {
                break;
            }

            if ($parent->name instanceof Identifier) {
                $method = $parent->name->toString();

                if (in_array($method, $config->safeScopeMethods, true)) {
                    return true;
                }

                if ($method === 'where' && $this->whereCallHasTenantColumn($parent, $config)) {
                    return true;
                }
            }

            $current = $parent;
        }

        return false;
    }

    private function whereCallHasTenantColumn(MethodCall $whereCall, GuardConfig $config): bool
    {
        if ($whereCall->args === [] || !$whereCall->args[0] instanceof Arg) {
            return false;
        }

        $firstArg = $whereCall->args[0]->value;

        if ($firstArg instanceof String_) {
            return $config->isTenantColumn($firstArg->value);
        }

        if ($firstArg instanceof Closure || $firstArg instanceof ArrowFunction) {
            $nodes = $firstArg instanceof Closure ? $firstArg->stmts : [$firstArg->expr];
            return $this->closureNodesScopeToTenant($nodes, $config);
        }

        return false;
    }

    /**
     * @param array<int, Node|null> $nodes
     */
    private function closureNodesScopeToTenant(array $nodes, GuardConfig $config): bool
    {
        foreach ($nodes as $node) {
            if (!$node instanceof Node) {
                continue;
            }

            if (
                $node instanceof MethodCall
                && $node->name instanceof Identifier
                && in_array($node->name->toString(), ['where', 'whereIn'], true)
                && isset($node->args[0])
                && $node->args[0] instanceof Arg
                && $node->args[0]->value instanceof String_
                && $config->isTenantColumn($node->args[0]->value->value)
            ) {
                return true;
            }

            foreach ($node->getSubNodeNames() as $subName) {
                $sub = $node->$subName;
                if ($sub instanceof Node && $this->closureNodesScopeToTenant([$sub], $config)) {
                    return true;
                }
                if (is_array($sub) && $this->closureNodesScopeToTenant($sub, $config)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Collects rule strings including literal strings, concatenations, and interpolated strings.
     *
     * @return list<array{0: string, 1: int}>
     */
    private function collectRuleStrings(Node\Expr $value): array
    {
        if ($value instanceof String_) {
            return [[$value->value, $value->getStartLine()]];
        }

        if ($value instanceof InterpolatedString) {
            $buffer = '';
            foreach ($value->parts as $part) {
                if ($part instanceof Node\InterpolatedStringPart) {
                    $buffer .= $part->value;
                } else {
                    $buffer .= '{var}';
                }
            }
            return [[$buffer, $value->getStartLine()]];
        }

        if ($value instanceof Concat) {
            $left = $this->collectRuleStrings($value->left);
            $right = $this->collectRuleStrings($value->right);
            if ($left !== [] && $right !== []) {
                return [[$left[0][0] . $right[0][0], $value->getStartLine()]];
            }
            if ($left !== []) {
                return [[$left[0][0], $value->getStartLine()]];
            }
            if ($right !== []) {
                return [[$right[0][0], $value->getStartLine()]];
            }
        }

        if ($value instanceof Array_) {
            $collected = [];
            foreach ($value->items as $subItem) {
                if ($subItem !== null) {
                    $subStrings = $this->collectRuleStrings($subItem->value);
                    foreach ($subStrings as $str) {
                        $collected[] = $str;
                    }
                }
            }
            return $collected;
        }

        return [];
    }

    /**
     * Parses a rule segment like 'unique:users,email,NULL,id,company_id,1'
     * into [ruleName, table, extraParams].
     *
     * @return array{0: string, 1: string, 2: list<string>}|null
     */
    private function parseStringValidationRule(string $segment): ?array
    {
        if (!str_starts_with($segment, 'unique:') && !str_starts_with($segment, 'exists:')) {
            return null;
        }

        [$ruleName, $paramString] = explode(':', $segment, 2);
        $params = array_map('trim', explode(',', $paramString));
        $table = $params[0] ?? '';

        if ($table === '') {
            return null;
        }

        $extraParams = array_slice($params, 2);
        return [$ruleName, $table, $extraParams];
    }

    /**
     * @param list<string> $extraParams
     */
    private function hasTenantColumnInParameters(array $extraParams, GuardConfig $config): bool
    {
        foreach ($extraParams as $param) {
            if ($config->isTenantColumn($param)) {
                return true;
            }
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

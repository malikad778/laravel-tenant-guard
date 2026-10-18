<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Rules;

use MalikAd\TenantGuard\Contracts\TenantRuleInterface;
use MalikAd\TenantGuard\Support\DocblockInspector;
use MalikAd\TenantGuard\Support\GuardConfig;
use MalikAd\TenantGuard\Support\Violation;
use PhpParser\Node;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\Property;
use PhpParser\Node\Stmt\TraitUse;

final class UnscopedJobSerializationRule implements TenantRuleInterface
{
    public function ruleId(): string
    {
        return 'unscoped_job_serialization';
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

        if (!$this->implementsShouldQueue($node)) {
            return [];
        }

        if (DocblockInspector::isMarkedTenantSafe($node, $config->ignoreAnnotation, $sourceLines)) {
            return [];
        }

        if ($this->hasTenantContext($node, $config)) {
            return [];
        }

        $className = $node->name instanceof Identifier ? $node->name->toString() : 'AnonymousJob';
        $line = $node->getStartLine();

        return [
            new Violation(
                ruleId: $this->ruleId(),
                file: $filePath,
                line: $line,
                message: sprintf(
                    "Queued job '%s' implements ShouldQueue without serialized tenant context.",
                    $className
                ),
                suggestion: sprintf(
                    "Add a $%s property or Tenant model parameter to the job constructor, use a tenancy trait, or annotate with /** %s */.",
                    $config->tenantColumns[0] ?? 'tenant_id',
                    $config->ignoreAnnotation
                ),
                snippet: trim($sourceLines[$line - 1] ?? '')
            ),
        ];
    }

    private function implementsShouldQueue(Class_ $class): bool
    {
        foreach ($class->implements as $interface) {
            $name = $interface->toString();
            $short = $this->shortName($name);
            if ($short === 'ShouldQueue' || str_contains($name, 'Queue\ShouldQueue')) {
                return true;
            }
        }

        return false;
    }

    private function hasTenantContext(Class_ $class, GuardConfig $config): bool
    {
        // 1. Check properties
        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Property) {
                foreach ($stmt->props as $prop) {
                    $propName = strtolower($prop->name->toString());
                    foreach ($config->tenantContextIdentifiers as $identifier) {
                        if ($propName === strtolower($identifier) || str_contains($propName, strtolower($identifier))) {
                            return true;
                        }
                    }
                }
            }

            // 2. Check traits like TenancyAware, TenantAware
            if ($stmt instanceof TraitUse) {
                foreach ($stmt->traits as $trait) {
                    $traitName = strtolower($this->shortName($trait->toString()));
                    if (str_contains($traitName, 'tenant') || str_contains($traitName, 'tenancy')) {
                        return true;
                    }
                }
            }
        }

        // 3. Check constructor parameters if present
        $constructor = $class->getMethod('__construct');
        if ($constructor !== null) {
            foreach ($constructor->params as $param) {
                if ($param->var instanceof Node\Expr\Variable && is_string($param->var->name)) {
                    $varName = strtolower($param->var->name);
                    foreach ($config->tenantContextIdentifiers as $identifier) {
                        if ($varName === strtolower($identifier) || str_contains($varName, strtolower($identifier))) {
                            return true;
                        }
                    }
                }

                if ($param->type instanceof Name) {
                    $typeName = $this->shortName($param->type->toString());
                    if (str_contains(strtolower($typeName), 'tenant')) {
                        return true;
                    }
                }
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

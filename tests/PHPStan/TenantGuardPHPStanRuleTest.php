<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Tests\PHPStan;

use MalikAd\TenantGuard\PHPStan\TenantGuardPHPStanRule;
use PHPStan\Analyser\Scope;
use PHPStan\Node\FileNode;
use PHPUnit\Framework\TestCase;

final class TenantGuardPHPStanRuleTest extends TestCase
{
    public function testGetNodeTypeReturnsFileNode(): void
    {
        $rule = new TenantGuardPHPStanRule();
        self::assertSame(FileNode::class, $rule->getNodeType());
    }

    public function testProcessNodeReturnsEmptyOnNonExistentFile(): void
    {
        $rule = new TenantGuardPHPStanRule();

        $fileNode = new FileNode([]);
        $scope = $this->createMock(Scope::class);
        $scope->method('getFile')->willReturn('/non/existent/path/file.php');

        $errors = $rule->processNode($fileNode, $scope);
        self::assertSame([], $errors);
    }
}

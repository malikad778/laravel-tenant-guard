<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Tests\Rules;

use MalikAd\TenantGuard\Rules\UnscopedValidationRule;
use MalikAd\TenantGuard\Support\GuardConfig;
use MalikAd\TenantGuard\TenantGuardAnalyzer;
use PHPUnit\Framework\TestCase;

final class UnscopedValidationRuleTest extends TestCase
{
    private TenantGuardAnalyzer $analyzer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->analyzer = new TenantGuardAnalyzer(
            new GuardConfig(),
            [new UnscopedValidationRule()]
        );
    }

    public function testFlagsConcatenatedValidationRule(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Http\Requests;

        class UserRequest
        {
            public function rules(): array
            {
                return [
                    'email' => 'required|' . 'unique:users,email',
                ];
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Http/Requests/UserRequest.php');
        self::assertCount(1, $violations);
        self::assertSame('unscoped_validation', $violations[0]->ruleId);
    }

    public function testFlagsInterpolatedValidationRule(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Http\Requests;

        class UserRequest
        {
            public function rules(int $id): array
            {
                return [
                    'email' => "required|unique:users,email,{$id}",
                ];
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Http/Requests/UserRequest.php');
        self::assertCount(1, $violations);
        self::assertSame('unscoped_validation', $violations[0]->ruleId);
    }

    public function testFlagsArrayAssignedValidationRule(): void
    {
        $code = <<<'PHP'
        <?php
        namespace App\Http\Requests;

        class UserRequest
        {
            public function rules(): array
            {
                $rules = [];
                $rules['email'] = 'required|unique:users,email';
                return $rules;
            }
        }
        PHP;

        $violations = $this->analyzer->analyzeCode($code, 'app/Http/Requests/UserRequest.php');
        self::assertCount(1, $violations);
        self::assertSame('unscoped_validation', $violations[0]->ruleId);
    }
}

<?php

declare(strict_types=1);

namespace MalikAd\TenantGuard\Support;

use PhpParser\Node;
use PhpParser\Node\Stmt;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Function_;

final class DocblockInspector
{
    public const DEFAULT_ANNOTATION = '@tenant-safe';
    public const ALIAS_ANNOTATION = '@tenant-guard-ignore';

    /**
     * Checks whether the given AST node, its enclosing statement, or its enclosing method
     * is annotated with the safety annotation.
     *
     * Will NOT walk to the class level to avoid silencing entire classes.
     *
     * @param list<string> $sourceLines
     */
    public static function isMarkedTenantSafe(
        Node $node,
        string $annotation = self::DEFAULT_ANNOTATION,
        array $sourceLines = []
    ): bool {
        // 1. Direct comments on the node itself
        if (self::hasAnnotationInComments($node->getComments(), $annotation)) {
            return true;
        }

        // 2. Check enclosing statement and method, without walking up to the entire class
        $current = $node->getAttribute('parent');
        while ($current instanceof Node) {
            // Stop at class or namespace boundary
            if ($current instanceof Stmt\Class_ || $current instanceof Stmt\Namespace_) {
                break;
            }

            if (self::hasAnnotationInComments($current->getComments(), $annotation)) {
                return true;
            }

            // If we reached a method or function, stop after checking its docblock
            if ($current instanceof ClassMethod || $current instanceof Function_) {
                break;
            }

            $current = $current->getAttribute('parent');
        }

        // 3. Fallback: check only the immediate preceding non-empty line, and only if it is an actual comment
        $line = $node->getStartLine();
        if ($line > 1 && $sourceLines !== []) {
            $prevLineIndex = $line - 2; // 0-based index for line - 1
            if (isset($sourceLines[$prevLineIndex])) {
                $trimmed = trim($sourceLines[$prevLineIndex]);
                if (self::isCommentLine($trimmed)) {
                    if (
                        str_contains($trimmed, $annotation)
                        || str_contains($trimmed, self::ALIAS_ANNOTATION)
                    ) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * @param array<\PhpParser\Comment> $comments
     */
    private static function hasAnnotationInComments(array $comments, string $annotation): bool
    {
        foreach ($comments as $comment) {
            $text = $comment->getText();
            if (
                str_contains($text, $annotation)
                || str_contains($text, self::ALIAS_ANNOTATION)
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determines if a raw source line is strictly a comment line.
     */
    private static function isCommentLine(string $line): bool
    {
        return str_starts_with($line, '//')
            || str_starts_with($line, '#')
            || str_starts_with($line, '/*')
            || str_starts_with($line, '*')
            || str_ends_with($line, '*/');
    }
}

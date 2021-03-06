<?php

declare(strict_types=1);

namespace EonX\EasyStandard\Rector;

use Nette\Utils\Strings;
use PhpParser\Node;
use PhpParser\Node\Stmt\Class_;
use PHPStan\PhpDocParser\Ast\PhpDoc\GenericTagValueNode;
use PHPStan\PhpDocParser\Ast\PhpDoc\PhpDocTagNode;
use Rector\AttributeAwarePhpDoc\Ast\PhpDoc\AttributeAwarePhpDocTagNode;
use Rector\Core\Contract\Rector\ConfigurableRectorInterface;
use Rector\Core\Rector\AbstractPHPUnitRector;
use Rector\Core\RectorDefinition\CodeSample;
use Rector\Core\RectorDefinition\RectorDefinition;
use Rector\NodeTypeResolver\Node\AttributeKey;

/**
 * @codeCoverageIgnore
 *
 * @SuppressWarnings("unused") Class is used by Rector
 */
final class AddCoversAnnotationRector extends AbstractPHPUnitRector implements ConfigurableRectorInterface
{
    /**
     * @var string
     */
    public const REPLACE_ARRAY = 'replace_array';

    /**
     * @var string[]
     */
    private $replaceArray;

    /**
     * @param mixed[] $configuration
     */
    public function configure(array $configuration): void
    {
        $this->replaceArray = $configuration[self::REPLACE_ARRAY] ?? [];
    }

    /**
     * {@inheritdoc}
     *
     * @noinspection AutoloadingIssuesInspection
     */
    public function getDefinition(): RectorDefinition
    {
        return new RectorDefinition(
            'Adds @covers annotation for test classes',
            [
                new CodeSample(
                    <<<'PHP'
class SomeServiceTest extends \PHPUnit\Framework\TestCase
{
}
PHP
                    ,
                    <<<'PHP'
/**
 * @covers \SomeService
*/
class SomeServiceTest extends \PHPUnit\Framework\TestCase
{
}
PHP
                ),
            ]
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getNodeTypes(): array
    {
        return [Class_::class];
    }

    /**
     * {@inheritdoc}
     */
    public function refactor(Node $node): ?Node
    {
        /** @var \PhpParser\Node\Stmt\Class_ $classNode */
        $classNode = $node;

        if ($this->shouldSkipClass($classNode)) {
            return null;
        }

        $coveredClass = $this->resolveCoveredClassName((string)$this->getName($node));

        /** @var \Rector\BetterPhpDocParser\PhpDocInfo\PhpDocInfo $phpDocInfo */
        $phpDocInfo = $classNode->getAttribute(AttributeKey::PHP_DOC_INFO);

        if ($coveredClass === null) {
            $phpDocInfo->addBareTag('@coversNothing');

            return $classNode;
        }

        $phpDocInfo->addPhpDocTagNode($this->createCoversPhpDocTagNode($coveredClass));

        return $classNode;
    }

    /**
     * Creates `@covers` PHPDoc tag.
     */
    private function createCoversPhpDocTagNode(string $className): PhpDocTagNode
    {
        return new AttributeAwarePhpDocTagNode('@covers', new GenericTagValueNode('\\' . $className));
    }

    /**
     * Resolves covered class name.
     */
    private function resolveCoveredClassName(string $className): ?string
    {
        $className = (string)\preg_replace('/Test$/', '', \str_replace($this->replaceArray, '', $className));

        if (\class_exists($className) === true) {
            return $className;
        }

        return null;
    }

    /**
     * Returns true if class should be skipped.
     */
    private function shouldSkipClass(Class_ $class): bool
    {
        $shouldSkip = false;
        $className = $this->getName($class);

        if ($className === null || $class->isAnonymous() === true || $class->isAbstract()) {
            $shouldSkip = true;
        }

        if ($this->isInTestClass($class) === false) {
            $shouldSkip = true;
        }

        // Is the @covers or @coversNothing annotation already added
        if ($class->getDocComment() !== null) {
            /** @var \PhpParser\Comment\Doc $docComment */
            $docComment = $class->getDocComment();

            if (Strings::match($docComment->getText(), '/(@covers|@coversNothing)(.*?)/') !== null) {
                $shouldSkip = true;
            }
        }

        return $shouldSkip;
    }
}

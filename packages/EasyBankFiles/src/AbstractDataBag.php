<?php

declare(strict_types=1);

namespace EonX\EasyBankFiles;

use Nette\Utils\Strings;

abstract class AbstractDataBag
{
    /**
     * @var string[]
     */
    protected $attributes;

    /**
     * @var mixed[]
     */
    protected $data = [];

    /**
     * BaseResult constructor.
     *
     * @param mixed[]|null $data
     */
    public function __construct(?array $data = null)
    {
        $this->attributes = $this->initAttributes() ?? [];

        foreach ($data ?? [] as $key => $value) {
            if (\in_array($key, $this->attributes, true)) {
                $this->data[$key] = $value;
            }
        }
    }

    /**
     * Return attribute's value
     *
     * @param mixed[] $parameters
     *
     * @return mixed|null
     */
    public function __call(string $method, array $parameters)
    {
        $type = \strtolower(\substr($method, 0, 3));
        $attribute = Strings::firstLower(\substr($method, 3));

        if ($type === 'get' && isset($this->data[$attribute])) {
            return $this->data[$attribute];
        }

        return null;
    }

    /**
     * Return object attributes.
     *
     * @return string[]
     */
    abstract protected function initAttributes(): array;
}

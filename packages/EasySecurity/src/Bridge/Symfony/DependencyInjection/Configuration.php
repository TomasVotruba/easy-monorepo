<?php

declare(strict_types=1);

namespace EonX\EasySecurity\Bridge\Symfony\DependencyInjection;

use EonX\EasySecurity\Interfaces\SecurityContextInterface;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('easy_security');

        $treeBuilder->getRootNode()
            ->children()
                ->scalarNode('context_service_id')->defaultValue(SecurityContextInterface::class)->end()
                ->booleanNode('easy_bugsnag')->defaultTrue()->end()
                ->scalarNode('token_decoder')->defaultNull()->end()
                ->arrayNode('permissions_locations')
                    ->scalarPrototype()->end()
                    ->beforeNormalization()->castToArray()->end()
                ->end()
                ->arrayNode('voters')
                    ->children()
                        ->booleanNode('permission_enabled')->defaultFalse()->end()
                        ->booleanNode('provider_enabled')->defaultFalse()->end()
                        ->booleanNode('role_enabled')->defaultFalse()->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}

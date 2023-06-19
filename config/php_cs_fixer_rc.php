<?php
/*
 * This document has been generated with
 * https://mlocati.github.io/php-cs-fixer-configurator/#version:3.17.0|configurator
 * you can change this configuration by importing this file.
 */
$config = new PhpCsFixer\Config();
return $config
    ->setRiskyAllowed(true)
    ->setRules([
        '@PSR2' => true,
        '@Symfony' => true,
        'align_multiline_comment' => ['comment_type'=>'all_multiline'],
        'array_syntax' => ['syntax'=>'short'],
        'blank_line_before_statement' => ['statements'=>['declare','return']],
        'cast_spaces' => ['space'=>'none'],
        'combine_consecutive_issets' => true,
        'combine_consecutive_unsets' => true,
        'compact_nullable_typehint' => true,
        'concat_space' => ['spacing'=>'one'],
        'declare_equal_normalize' => ['space'=>'single'],
        'doctrine_annotation_array_assignment' => true,
        'doctrine_annotation_braces' => ['syntax'=>'with_braces'],
        'doctrine_annotation_indentation' => ['indent_mixed_lines'=>true],
        'doctrine_annotation_spaces' => true,
        'heredoc_to_nowdoc' => true,
        'increment_style' => ['style'=>'post'],
        'linebreak_after_opening_tag' => true,
        'list_syntax' => true,
        'modernize_types_casting' => true,
        'no_superfluous_elseif' => true,
        'no_useless_else' => true,
        'no_useless_return' => true,
        'ordered_class_elements' => true,
        'ordered_imports' => true,
        'php_unit_test_class_requires_covers' => true,
        'phpdoc_add_missing_param_annotation' => ['only_untyped'=>false],
        'phpdoc_no_alias_tag' => false,
        'phpdoc_order' => true,
        'phpdoc_types_order' => true,
        'phpdoc_var_without_name' => false,
        'random_api_migration' => true,
        'return_type_declaration' => ['space_before'=>'one'],
        'single_line_comment_style' => ['comment_types'=>['hash']],
        'space_after_semicolon' => ['remove_in_empty_for_expressions'=>true],
        'strict_comparison' => true,
        'yoda_style' => false,
    ])
    ->setFinder(PhpCsFixer\Finder::create()
        // ->exclude('folder-to-exclude') // if you want to exclude some folders, you can do it like this!
        ->in(__DIR__)
    )
;

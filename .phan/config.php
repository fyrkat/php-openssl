<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

use Phan\Issue;

/**
 * This configuration file was automatically generated by 'phan --init --init-level=1'
 *
 * TODOs (added by 'phan --init'):
 *
 * - Go through this file and verify that there are no missing/unnecessary files/directories.
 *   (E.g. this only includes direct composer dependencies - You may have to manually add indirect composer dependencies to 'directory_list')
 * - Look at 'plugins' and add or remove plugins if appropriate (see https://github.com/phan/phan/tree/master/.phan/plugins#plugins)
 * - Add global suppressions for pre-existing issues to suppress_issue_types (https://github.com/phan/phan/wiki/Tutorial-for-Analyzing-a-Large-Sloppy-Code-Base)
 *
 * This configuration will be read and overlaid on top of the
 * default configuration. Command line arguments will be applied
 * after this file is read.
 *
 * @see src/Phan/Config.php
 * See Config for all configurable options.
 *
 * A Note About Paths
 * ==================
 *
 * Files referenced from this file should be defined as
 *
 * ```
 *   Config::projectPath('relative_path/to/file')
 * ```
 *
 * where the relative path is relative to the root of the
 * project which is defined as either the working directory
 * of the phan executable or a path passed in via the CLI
 * '-d' flag.
 */
return [

	// Supported values: `'5.6'`, `'7.0'`, `'7.1'`, `'7.2'`, `'7.3'`, `null`.
	// If this is set to `null`,
	// then Phan assumes the PHP version which is closest to the minor version
	// of the php executable used to execute Phan.
	//
	// Note that the **only** effect of choosing `'5.6'` is to infer that functions removed in php 7.0 exist.
	// (See `backward_compatibility_checks` for additional options)
	// Automatically inferred from composer.json requirement for "php" of ">=7.1"
	'target_php_version' => '7.1',

	// If enabled, missing properties will be created when
	// they are first seen. If false, we'll report an
	// error message if there is an attempt to write
	// to a class property that wasn't explicitly
	// defined.
	'allow_missing_properties' => false,

	// If enabled, null can be cast to any type and any
	// type can be cast to null. Setting this to true
	// will cut down on false positives.
	'null_casts_as_any_type' => false,

	// If enabled, allow null to be cast as any array-like type.
	//
	// This is an incremental step in migrating away from `null_casts_as_any_type`.
	// If `null_casts_as_any_type` is true, this has no effect.
	'null_casts_as_array' => false,

	// If enabled, allow any array-like type to be cast to null.
	// This is an incremental step in migrating away from `null_casts_as_any_type`.
	// If `null_casts_as_any_type` is true, this has no effect.
	'array_casts_as_null' => false,

	// If enabled, scalars (int, float, bool, string, null)
	// are treated as if they can cast to each other.
	// This does not affect checks of array keys. See `scalar_array_key_cast`.
	'scalar_implicit_cast' => false,

	// If enabled, any scalar array keys (int, string)
	// are treated as if they can cast to each other.
	// E.g. `array<int,stdClass>` can cast to `array<string,stdClass>` and vice versa.
	// Normally, a scalar type such as int could only cast to/from int and mixed.
	'scalar_array_key_cast' => false,

	// If this has entries, scalars (int, float, bool, string, null)
	// are allowed to perform the casts listed.
	//
	// E.g. `['int' => ['float', 'string'], 'float' => ['int'], 'string' => ['int'], 'null' => ['string']]`
	// allows casting null to a string, but not vice versa.
	// (subset of `scalar_implicit_cast`)
	'scalar_implicit_partial' => [],

	// If enabled, Phan will warn if **any** type in a method invocation's object
	// is definitely not an object,
	// or if **any** type in an invoked expression is not a callable.
	// Setting this to true will introduce numerous false positives
	// (and reveal some bugs).
	'strict_method_checking' => true,

	// If enabled, Phan will warn if **any** type in the argument's union type
	// cannot be cast to a type in the parameter's expected union type.
	// Setting this to true will introduce numerous false positives
	// (and reveal some bugs).
	'strict_param_checking' => true,

	// If enabled, Phan will warn if **any** type in a returned value's union type
	// cannot be cast to the declared return type.
	// Setting this to true will introduce numerous false positives
	// (and reveal some bugs).
	'strict_return_checking' => true,

	// If enabled, Phan will warn if **any** type in a property assignment's union type
	// cannot be cast to a type in the property's declared union type.
	// Setting this to true will introduce numerous false positives
	// (and reveal some bugs).
	'strict_property_checking' => true,

	// If true, seemingly undeclared variables in the global
	// scope will be ignored.
	//
	// This is useful for projects with complicated cross-file
	// globals that you have no hope of fixing.
	'ignore_undeclared_variables_in_global_scope' => false,

	// Set this to false to emit `PhanUndeclaredFunction` issues for internal functions that Phan has signatures for,
	// but aren't available in the codebase, or the internal functions used to run Phan
	// (may lead to false positives if an extension isn't loaded)
	//
	// If this is true(default), then Phan will not warn.
	'ignore_undeclared_functions_with_known_signatures' => false,

	// Backwards Compatibility Checking. This is slow
	// and expensive, but you should consider running
	// it before upgrading your version of PHP to a
	// new version that has backward compatibility
	// breaks.
	//
	// If you are migrating from PHP 5 to PHP 7,
	// you should also look into using
	// [php7cc (no longer maintained)](https://github.com/sstalle/php7cc)
	// and [php7mar](https://github.com/Alexia/php7mar),
	// which have different backwards compatibility checks.
	'backward_compatibility_checks' => false,

	// If true, check to make sure the return type declared
	// in the doc-block (if any) matches the return type
	// declared in the method signature.
	'check_docblock_signature_return_type_match' => true,

	// If true, make narrowed types from phpdoc params override
	// the real types from the signature, when real types exist.
	// (E.g. allows specifying desired lists of subclasses,
	//  or to indicate a preference for non-nullable types over nullable types)
	//
	// Affects analysis of the body of the method and the param types passed in by callers.
	//
	// (*Requires `check_docblock_signature_param_type_match` to be true*)
	'prefer_narrowed_phpdoc_param_type' => true,

	// (*Requires `check_docblock_signature_return_type_match` to be true*)
	//
	// If true, make narrowed types from phpdoc returns override
	// the real types from the signature, when real types exist.
	//
	// (E.g. allows specifying desired lists of subclasses,
	// or to indicate a preference for non-nullable types over nullable types)
	//
	// This setting affects the analysis of return statements in the body of the method and the return types passed in by callers.
	'prefer_narrowed_phpdoc_return_type' => true,

	// If enabled, check all methods that override a
	// parent method to make sure its signature is
	// compatible with the parent's.
	//
	// This check can add quite a bit of time to the analysis.
	//
	// This will also check if final methods are overridden, etc.
	'analyze_signature_compatibility' => true,

	// This setting maps case-insensitive strings to union types.
	//
	// This is useful if a project uses phpdoc that differs from the phpdoc2 standard.
	//
	// If the corresponding value is the empty string,
	// then Phan will ignore that union type (E.g. can ignore 'the' in `@return the value`)
	//
	// If the corresponding value is not empty,
	// then Phan will act as though it saw the corresponding UnionTypes(s)
	// when the keys show up in a UnionType of `@param`, `@return`, `@var`, `@property`, etc.
	//
	// This matches the **entire string**, not parts of the string.
	// (E.g. `@return the|null` will still look for a class with the name `the`, but `@return the` will be ignored with the below setting)
	//
	// (These are not aliases, this setting is ignored outside of doc comments).
	// (Phan does not check if classes with these names exist)
	//
	// Example setting: `['unknown' => '', 'number' => 'int|float', 'char' => 'string', 'long' => 'int', 'the' => '']`
	'phpdoc_type_mapping' => [],

	// Set to true in order to attempt to detect dead
	// (unreferenced) code. Keep in mind that the
	// results will only be a guess given that classes,
	// properties, constants and methods can be referenced
	// as variables (like `$class->$property` or
	// `$class->$method()`) in ways that we're unable
	// to make sense of.
	'dead_code_detection' => false,

	// Set to true in order to attempt to detect unused variables.
	// `dead_code_detection` will also enable unused variable detection.
	//
	// This has a few known false positives, e.g. for loops or branches.
	'unused_variable_detection' => true,

	// If true, this runs a quick version of checks that takes less
	// time at the cost of not running as thorough
	// of an analysis. You should consider setting this
	// to true only when you wish you had more **undiagnosed** issues
	// to fix in your code base.
	//
	// In quick-mode the scanner doesn't rescan a function
	// or a method's code block every time a call is seen.
	// This means that the problem here won't be detected:
	//
	// ```php
	// <?php
	// function test($arg):int {
	//     return $arg;
	// }
	// test("abc");
	// ```
	//
	// This would normally generate:
	//
	// ```
	// test.php:3 PhanTypeMismatchReturn Returning type string but test() is declared to return int
	// ```
	//
	// The initial scan of the function's code block has no
	// type information for `$arg`. It isn't until we see
	// the call and rescan `test()`'s code block that we can
	// detect that it is actually returning the passed in
	// `string` instead of an `int` as declared.
	'quick_mode' => false,

	// If true, then before analysis, try to simplify AST into a form
	// which improves Phan's type inference in edge cases.
	//
	// This may conflict with `dead_code_detection`.
	// When this is true, this slows down analysis slightly.
	//
	// E.g. rewrites `if ($a = value() && $a > 0) {...}`
	// into `$a = value(); if ($a) { if ($a > 0) {...}}`
	'simplify_ast' => true,

	// Enable or disable support for generic templated
	// class types.
	'generic_types_enabled' => true,

	// Override to hardcode existence and types of (non-builtin) globals in the global scope.
	// Class names should be prefixed with `\`.
	//
	// (E.g. `['_FOO' => '\FooClass', 'page' => '\PageClass', 'userId' => 'int']`)
	'globals_type_map' => [],

	// The minimum severity level to report on. This can be
	// set to `Issue::SEVERITY_LOW`, `Issue::SEVERITY_NORMAL` or
	// `Issue::SEVERITY_CRITICAL`. Setting it to only
	// critical issues is a good place to start on a big
	// sloppy mature code base.
	'minimum_severity' => Issue::SEVERITY_LOW,

	// Add any issue types (such as `'PhanUndeclaredMethod'`)
	// to this black-list to inhibit them from being reported.
	'suppress_issue_types' => [],

	// A regular expression to match files to be excluded
	// from parsing and analysis and will not be read at all.
	//
	// This is useful for excluding groups of test or example
	// directories/files, unanalyzable files, or files that
	// can't be removed for whatever reason.
	// (e.g. `'@Test\.php$@'`, or `'@vendor/.*/(tests|Tests)/@'`)
	'exclude_file_regex' => '@^vendor/.*/(tests?|Tests?)/@',

	// A file list that defines files that will be excluded
	// from parsing and analysis and will not be read at all.
	//
	// This is useful for excluding hopelessly unanalyzable
	// files that can't be removed for whatever reason.
	'exclude_file_list' => [],

	// A directory list that defines files that will be excluded
	// from static analysis, but whose class and method
	// information should be included.
	//
	// Generally, you'll want to include the directories for
	// third-party code (such as "vendor/") in this list.
	//
	// n.b.: If you'd like to parse but not analyze 3rd
	//       party code, directories containing that code
	//       should be added to the `directory_list` as well as
	//       to `exclude_analysis_directory_list`.
	'exclude_analysis_directory_list' => [
		'vendor/',
	],

	// Enable this to enable checks of require/include statements referring to valid paths.
	'enable_include_path_checks' => true,

	// The number of processes to fork off during the analysis
	// phase.
	'processes' => 1,

	// List of case-insensitive file extensions supported by Phan.
	// (e.g. `['php', 'html', 'htm']`)
	'analyzed_file_extensions' => [
		'php',
	],

	// You can put paths to stubs of internal extensions in this config option.
	// If the corresponding extension is **not** loaded, then Phan will use the stubs instead.
	// Phan will continue using its detailed type annotations,
	// but load the constants, classes, functions, and classes (and their Reflection types)
	// from these stub files (doubling as valid php files).
	// Use a different extension from php to avoid accidentally loading these.
	// The `tools/make_stubs` script can be used to generate your own stubs (compatible with php 7.0+ right now)
	//
	// (e.g. `['xdebug' => '.phan/internal_stubs/xdebug.phan_php']`)
	'autoload_internal_extension_signatures' => [],

	// A list of plugin files to execute.
	//
	// Plugins which are bundled with Phan can be added here by providing their name (e.g. `'AlwaysReturnPlugin'`)
	//
	// Documentation about available bundled plugins can be found [here](https://github.com/phan/phan/tree/master/.phan/plugins).
	//
	// Alternately, you can pass in the full path to a PHP file with the plugin's implementation (e.g. `'vendor/phan/phan/.phan/plugins/AlwaysReturnPlugin.php'`)
	'plugins' => [
		'AlwaysReturnPlugin',
		'DollarDollarPlugin',
		'DuplicateArrayKeyPlugin',
		'DuplicateExpressionPlugin',
		'PregRegexCheckerPlugin',
		'PrintfCheckerPlugin',
		'SleepCheckerPlugin',
		'UnreachableCodePlugin',
		'UseReturnValuePlugin',
	],

	// A list of directories that should be parsed for class and
	// method information. After excluding the directories
	// defined in `exclude_analysis_directory_list`, the remaining
	// files will be statically analyzed for errors.
	//
	// Thus, both first-party and third-party code being used by
	// your application should be included in this list.
	'directory_list' => [
		'src',
	],

	// A list of individual files to include in analysis
	// with a path relative to the root directory of the
	// project.
	'file_list' => [],
];

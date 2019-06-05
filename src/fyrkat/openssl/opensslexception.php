<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

use Exception;
use Throwable;

/**
 * Exception class that, when instantiated, will consume all queued error
 * messages for OpenSSL and show them when printing a stacktrace.
 *
 * @see http://php.net/manual/en/function.openssl-error-string.php
 */
class OpenSSLException extends Exception
{
	/** @var string[] Error messages from openssl_error_string() */
	private $errorMessages = [];

	/** @var ?string The last openssl_* function called */
	private $functionName = null;

	/**
	 * Construct a new OpenSSL exception and consume error messages
	 *
	 * @see http://php.net/manual/en/function.openssl-error-string.php
	 *
	 * @param ?string    $functionName
	 * @param ?Throwable $previous
	 */
	public function __construct( string $functionName = null, Throwable $previous = null )
	{
		$this->functionName = $functionName;
		while ( $errorMessage = \openssl_error_string() ) {
			$this->errorMessages[] = null === $functionName ? $errorMessage : "${functionName}: ${errorMessage}";
		}
		parent::__construct( \implode( "\n", $this->errorMessages ), 0, $previous );
	}

	/**
	 * Flush all error messages left in openssl_error_string()
	 *
	 * After running this function, openssl_error_string() will return false.
	 *
	 * @see http://php.net/manual/en/function.openssl-error-string.php
	 */
	public static function flushErrorMessages(): void
	{
		while ( false !== \openssl_error_string() );
	}

	/**
	 * Get all OpenSSL error messages
	 *
	 * @return string[]
	 */
	public function getErrorMessages()
	{
		return $this->errorMessages;
	}
}

<?php declare( strict_types=1 );

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

use Exception;
use Throwable;

class OpenSSLException extends Exception
{
	/** @var string[] */
	private $errorMessages = [];

	/**
	 * @param Throwable $previous
	 */
	public function __construct( Throwable $previous = null )
	{
		while ( $errorMessage = \openssl_error_string() ) {
			$this->errorMessages[] = $errorMessage;
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

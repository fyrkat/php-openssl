<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

class PublicKey
{
	use ResourceOwner;

	/**
	 * Create a pkey resource and wrap around it
	 *
	 * @see http://php.net/openssl_pkey_get_public
	 *
	 * @param mixed $key
	 *
	 * @throws OpenSSLException
	 */
	public function __construct( $key )
	{
		if ( $key instanceof X509 ) {
			$key = $key->getResource();
		}
		\assert( \is_resource( $key ) || \is_string( $key ), 'PublicKey constructed with X509, string or resource' );

		OpenSSLException::flushErrorMessages();
		$resource = \openssl_pkey_get_public( $key );
		if ( false === $resource ) {
			throw new OpenSSLException();
		}
		$this->setResource( $resource );
	}

	/**
	 * Free the resource
	 */
	public function __destruct()
	{
		\openssl_free_key( $this->getResource() );
	}

	/**
	 * Returns an array with the key details
	 *
	 * @see http://php.net/manual/en/function.openssl-pkey-get-details.php
	 *
	 * @throws OpenSSLException
	 *
	 * @return array<string,int|string|array<int|string>> key details
	 */
	public function getDetails(): array
	{
		OpenSSLException::flushErrorMessages();
		$result = \openssl_pkey_get_details( $this->getResource() );
		\assert( false === $result || \is_array( $result ), 'openssl_pkey_get_details returns array or false' );
		if ( false === $result ) {
			throw new OpenSSLException();
		}

		return $result;
	}
}

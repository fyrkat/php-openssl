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
	 * @param resource|string|X509 $key Resource, file:/{path} or PEM
	 * @psalm-suppress RedundantConditionGivenDocblockType
	 *
	 * @throws OpenSSLException
	 */
	public function __construct( $key )
	{
		if ( $key instanceof X509 ) {
			$key = $key->getResource();
		}
		\assert( \is_resource( $key ) || \is_string( $key ), 'PublicKey constructor expects X509, string or resource' );

		OpenSSLException::flushErrorMessages();
		$resource = \openssl_pkey_get_public( $key );
		if ( false === $resource ) {
			throw new OpenSSLException( 'openssl_pkey_get_public' );
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

	/** @psalm-suppress InvalidToString */
	public function __toString()
	{
		return $this->getDetails()['key'];
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
		/** @psalm-suppress RedundantCondition */
		\assert( false === $result || \is_array( $result ), 'openssl_pkey_get_details returns array or false' );
		if ( false === $result ) {
			throw new OpenSSLException( 'openssl_pkey_get_details' );
		}

		return $result;
	}

	/**
	 * Exports the public key as a string
	 *
	 * @param string &$output String to write PEM encoded CSR in
	 *
	 * @throws OpenSSLException
	 *
	 * @psalm-suppress ReferenceConstraintViolation
	 */
	public function export( string &$output ): void
	{
		$output = $this->getDetails()['key'];
	}

	/**
	 * Export the public key to a file
	 *
	 * @param string $outputFileName Path to the output file
	 *
	 * @throws OpenSSLException
	 */
	public function exportToFile( string $outputFileName ): void
	{
		\file_put_contents( $outputFileName, $this->getDetails()['key'] );
	}

	/**
	 * Calculate the fingerprint, or digest, of the public key
	 *
	 * @see http://php.net/manual/en/function.openssl-get-md-methods.php
	 *
	 * @param string $hashAlgorithm The digest method or hash algorithm to use
	 * @param bool   $rawOutput     TRUE to output raw binary data, or FALSE to output lowercase hexits
	 *
	 * @throws OpenSSLException
	 */
	public function fingerprint( string $hashAlgorithm = 'sha1', bool $rawOutput = false ): string
	{
		/** @var string */
		$key = '';
		$this->export( $key );
		\preg_match( '/-----BEGIN PUBLIC KEY-----\\s+(.*)\\s+-----END PUBLIC KEY-----/ms', $key, $matches );

		return \hash( $hashAlgorithm, \base64_decode( $matches[1], true ), $rawOutput );
	}
}

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
	use PKeyDetails;

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

	public function __toString()
	{
		return $this->getPublicKeyPem();
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
		/**
		 * According to the comments on the documentation on openssl_pkey_export,
		 * that function can only export private keys.
		 *
		 * @see http://php.net/manual/en/function.openssl-pkey-export.php#44553
		 * @see http://php.net/manual/en/function.openssl-pkey-get-details.php
		 */
		$output = $this->getPublicKeyPem();
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
		/**
		 * According to the comments on the documentation on openssl_pkey_export,
		 * that function can only export private keys.
		 *
		 * @see http://php.net/manual/en/function.openssl-pkey-export.php#44553
		 * @see http://php.net/manual/en/function.openssl-pkey-get-details.php
		 */
		\file_put_contents( $outputFileName, $this->getPublicKeyPem() );
	}

	/**
	 * Calculate the fingerprint, or digest, of the key
	 *
	 * @see http://php.net/manual/en/function.openssl-digest.php
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
		$key = $this->getPublicKeyPem();
		\preg_match( '/-----BEGIN PUBLIC KEY-----\\s+(.*)\\s+-----END PUBLIC KEY-----/ms', $key, $matches );

		return \openssl_digest( \base64_decode( $matches[1], true ), $hashAlgorithm, $rawOutput );
	}

	/**
	 * Check if a private key corresponds to this certificate
	 *
	 * @param PrivateKey $key The private key to check against
	 *
	 * @return bool Returns True if $key is the private key that corresponds to cert, or false otherwise
	 */
	public function checkPrivateKey( PrivateKey $key ): bool
	{
		$myDetails = $this->getDetails();
		$theirDetails = $key->getDetails();
		if ( \array_key_exists( 'key', $myDetails ) && \array_key_exists( 'key', $theirDetails) ) {
			if ( $myDetails['key'] === $theirDetails['key'] ) {
				return true;
			}
		}

		return false;
	}
}

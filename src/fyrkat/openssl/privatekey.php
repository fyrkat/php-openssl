<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

class PrivateKey
{
	use ResourceOwner;

	/**
	 * Create a pkey resource and wrap around it
	 *
	 * @see http://php.net/manual/en/function.openssl-pkey-get-private.php
	 * @see http://php.net/manual/en/function.openssl-pkey-new.php
	 *
	 * @param ?ConfigArgs|?string $keyOrConfig A PEM formatted private key or
	 *                                         a `file://path/to/file.pem` or
	 *                                         configuration for a new key (or null)
	 * @param ?string             $passphrase  Passphrase used if key is encrypted
	 *
	 * @psalm-suppress RedundantConditionGivenDocblockType
	 */
	public function __construct( $keyOrConfig = null, string $passphrase = null )
	{
		$result = null;
		OpenSSLException::flushErrorMessages();
		if ( null === $keyOrConfig ) {
			$result = \openssl_pkey_new();
			\assert( false === $result || \is_resource( $result ), 'openssl_pkey_new returns resource or false' );
		} elseif ( $keyOrConfig instanceof ConfigArgs ) {
			\assert( null !== $passphrase, 'PrivateKey cannot have a passphrase when creating a new key' );
			$result = \openssl_pkey_new( $keyOrConfig->getArray() );
			\assert( false === $result || \is_resource( $result ), 'openssl_pkey_new returns resource or false' );
		} elseif ( \is_string( $keyOrConfig ) ) {
			if ( null === $passphrase ) {
				$result = \openssl_pkey_get_private( $keyOrConfig );
				\assert( false === $result || \is_resource( $result ), 'openssl_pkey_get_private returns resource or false' );
			} else {
				$result = \openssl_pkey_get_private( $keyOrConfig, $passphrase );
				\assert( false === $result || \is_resource( $result ), 'openssl_pkey_get_private returns resource or false' );
			}
		} else {
			// Should never happen, but let's crash if it does
			\assert( false, 'PrivateKey constructor requires string, null or ConfigArgs as first argument' );
		}
		if ( false === $result ) {
			throw new OpenSSLException();
		}

		// Should never happen, but let's crash if it does
		\assert( null !== $result, 'Code path fell through, no OpenSSL resource was set' );

		$this->setResource( $result );
	}

	/**
	 * Free the resource
	 *
	 * @see http://php.net/manual/en/function.openssl-pkey-free.php
	 */
	public function __destruct()
	{
		\openssl_pkey_free( $this->getResource() );
	}

	/**
	 * Get an exportable representation of a key into a file
	 *
	 * @see http://php.net/manual/en/function.openssl-pkey-export-to-file.php
	 *
	 * @throws OpenSSLException
	 */
	public function exportToFile( string $outputFileName, string $passphrase, ConfigArgs $configargs ): void
	{
		OpenSSLException::flushErrorMessages();
		$result = \openssl_pkey_export_to_file( $this->getResource(), $outputFileName, $passphrase, $configargs->getArray() );
		\assert( \is_bool( $result ), 'openssl_pkey_export_to_file returns boolean' );
		if ( false === $result ) {
			throw new OpenSSLException();
		}
	}

	/**
	 * Get an exportable representation of a key into a string
	 *
	 * @see http://php.net/manual/en/function.openssl-pkey-export.php
	 *
	 * @param string $output     Pointer to a string where the output is written
	 * @param string $passphrase Passphrase used to encrypt the output
	 * @param ConfigArgs Configuration for overriding the OpenSSL configuration file
	 *
	 * @throws OpenSSLException
	 */
	public function export( string &$output, string $passphrase, ConfigArgs $configargs = null ): void
	{
		OpenSSLException::flushErrorMessages();
		if ( null === $configargs ) {
			$result = \openssl_pkey_export( $this->getResource(), $output, $passphrase );
		} else {
			$result = \openssl_pkey_export( $this->getResource(), $output, $passphrase, $configargs->getArray() );
		}
		\assert( \is_bool( $result ), 'openssl_pkey_export returns boolean' );
		if ( false === $result ) {
			throw new OpenSSLException();
		}
	}

	/**
	 * @return PublicKey The PublicKey corresponding to this PrivateKey
	 */
	public function getPublicKey(): PublicKey
	{
		return new PublicKey( $this->getResource() );
	}
}

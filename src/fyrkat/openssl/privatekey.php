<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

class PrivateKey extends OpenSSLKey
{
	/**
	 * Create a pkey resource and wrap around it
	 *
	 * @see http://php.net/manual/en/function.openssl-pkey-get-private.php
	 * @see http://php.net/manual/en/function.openssl-pkey-new.php
	 *
	 * @param null|ConfigArgs|string $keyOrConfig A PEM formatted private key or
	 *                                            a `file://path/to/file.pem` or
	 *                                            configuration for a new key or
	 *                                            null for a new key
	 * @param ?string                $passphrase  Passphrase used if existing key is encrypted.
	 *                                            Must be null for new key
	 *
	 * @throws OpenSSLException
	 */
	public function __construct( $keyOrConfig = null, string $passphrase = null )
	{
		\assert(
				null === $keyOrConfig
				|| \is_string( $keyOrConfig )
				|| $keyOrConfig instanceof ConfigArgs,
				'PrivateKey constructor expects ConfigArgs, string or null'
			);

		$result = null;
		OpenSSLException::flushErrorMessages();
		if ( \is_string( $keyOrConfig ) ) {
			// Import existing key

			if ( null === $passphrase ) {
				$result = \openssl_pkey_get_private( $keyOrConfig );
			} else {
				$result = \openssl_pkey_get_private( $keyOrConfig, $passphrase );
			}

			/** @psalm-suppress RedundantCondition */
			\assert(
					false === $result || \is_resource( $result ),
					'openssl_pkey_get_private returns resource or false'
				);

			if ( false === $result ) {
				throw new OpenSSLException( 'openssl_pkey_get_private' );
			}
		} else {
			if ( null === $keyOrConfig ) {
				// Create new key without configuration

				$result = \openssl_pkey_new();
			} elseif ( $keyOrConfig instanceof ConfigArgs ) {
				// Create new key with configuration

				\assert(
						null !== $passphrase,
						'PrivateKey cannot have a passphrase when creating a new key'
					);
				$result = \openssl_pkey_new( $keyOrConfig->getArray() );
			}

			/** @psalm-suppress RedundantCondition */
			\assert(
					false === $result || \is_resource( $result ),
					'openssl_pkey_new returns resource or false'
				);

			if ( false === $result ) {
				throw new OpenSSLException( 'openssl_pkey_new' );
			}
		}

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
	 * @param string      $outputFileName Path to the output file
	 * @param ?string     $passphrase     Passphrase used to encrypt the output
	 * @param ?ConfigArgs $configargs     Configuration for overriding the OpenSSL configuration file
	 *
	 * @throws OpenSSLException
	 *
	 * @psalm-suppress PossiblyNullArgument $passphrase is allowed to be null
	 *
	 * @see http://github.com/vimeo/psalm/pull/1718
	 */
	public function exportToFile( string $outputFileName, ?string $passphrase, ?ConfigArgs $configargs = null ): void
	{
		OpenSSLException::flushErrorMessages();
		if ( null === $configargs ) {
			$result = \openssl_pkey_export_to_file( $this->getResource(), $outputFileName, $passphrase );
		} else {
			$result = \openssl_pkey_export_to_file( $this->getResource(), $outputFileName, $passphrase, $configargs->getArray() );
		}
		/** @psalm-suppress RedundantCondition */
		\assert(
				\is_bool( $result ),
				'openssl_pkey_export_to_file returns boolean'
			);
		if ( false === $result ) {
			throw new OpenSSLException( 'openssl_pkey_export_to_file' );
		}
	}

	/**
	 * Get an exportable representation of a key into a string
	 *
	 * @see http://php.net/manual/en/function.openssl-pkey-export.php
	 *
	 * @param string      $output     Pointer to a string where the output is written
	 * @param ?string     $passphrase Passphrase used to encrypt the output
	 * @param ?ConfigArgs $configargs Configuration for overriding the OpenSSL configuration file
	 *
	 * @throws OpenSSLException
	 *
	 * @psalm-suppress PossiblyNullArgument $passphrase is allowed to be null
	 *
	 * @see http://github.com/vimeo/psalm/pull/1718
	 */
	public function export( string &$output, ?string $passphrase, ConfigArgs $configargs = null ): void
	{
		OpenSSLException::flushErrorMessages();
		if ( null === $configargs ) {
			$result = \openssl_pkey_export( $this->getResource(), $output, $passphrase );
		} else {
			$result = \openssl_pkey_export( $this->getResource(), $output, $passphrase, $configargs->getArray() );
		}
		/** @psalm-suppress RedundantCondition */
		\assert(
				\is_bool( $result ),
				'openssl_pkey_export returns boolean'
			);
		if ( false === $result ) {
			throw new OpenSSLException( 'openssl_pkey_export' );
		}
	}

	/**
	 * Get the public key associated with this private key
	 *
	 * @see http://php.net/manual/en/function.openssl-pkey-get-details.php
	 * @see http://bugs.php.net/bug.php?id=25614
	 *
	 * @throws OpenSSLException
	 *
	 * @return PublicKey The PublicKey corresponding to this PrivateKey
	 */
	public function getPublicKey(): PublicKey
	{
		return new PublicKey( $this->getPublicKeyPem() );
	}
}

<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

class X509
{
	use ResourceOwner;

	/**
	 * Create a x.509 resource and wrap around it
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-read.php
	 * @see http://php.net/manual/en/openssl.certparams.php
	 *
	 * @param mixed $x509certdata File path to PEM file, or contents of a PEM file
	 */
	public function __construct( $x509certdata )
	{
		$this->setResource( \openssl_x509_read( $x509certdata ) );
	}

	/**
	 * Free the resource
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-free.php
	 */
	public function __destruct()
	{
		\openssl_x509_free( $this->getResource() );
	}

	/**
	 * Check if a private key corresponds to this certificate
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-check-private-key.php
	 */
	public function checkPrivateKey( PrivateKey $key ): bool
	{
		return \openssl_x509_check_private_key( $this->getResource(), $key->getResource() );
	}

	/**
	 * Verify if a certificate can be used for a particular purpose
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-checkpurpose.php
	 * @see http://php.net/manual/en/openssl.cert.verification.php
	 * @see Purpose
	 *
	 * @param int           $purpose       See {Purpose}
	 * @param array<string> $ca            File and directory names that specify the locations of trusted CA files
	 * @param string        $untrustedfile PEM encoded file holding certificates that can be used to help verify this certificate
	 *
	 * @throws OpenSSLException
	 *
	 * @return bool The certificate can be used for $purpose
	 */
	public function checkPurpose( int $purpose, array $ca = [], string $untrustedfile = null ): bool
	{
		OpenSSLException::flushErrorMessages();
		if ( null === $untrustedfile ) {
			$result = \openssl_x509_checkpurpose(
					$this->getResource(),
					$purpose,
					$ca
				);
		} else {
			$result = \openssl_x509_checkpurpose(
					$this->getResource(),
					$purpose,
					$ca
				);
		}
		\assert( -1 === $result || \is_bool( $result ), 'openssl_x509_checkpurpose returns -1 or boolean' );
		if ( -1 === $result ) {
			throw new OpenSSLException();
		}

		return $result;
	}

	/**
	 * Export a certificate to file
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-export-to-file.php
	 *
	 * @throws OpenSSLException
	 */
	public function exportToFile( string $outputFileName, bool $withText = false ): void
	{
		OpenSSLException::flushErrorMessages();
		$result = \openssl_x509_export_to_file( $this->getResource(), $outputFileName, !$withText );
		\assert( \is_bool( $result ), 'openssl_x509_export_to_file returns boolean' );
		if ( !$result ) {
			throw new OpenSSLException();
		}
	}

	/**
	 * Export a certificate as a string
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-export.php
	 *
	 * @throws OpenSSLException
	 */
	public function export( string &$output, bool $withText = false ): void
	{
		OpenSSLException::flushErrorMessages();
		$result = \openssl_x509_export( $this->getResource(), $output, !$withText );
		\assert( \is_bool( $result ), 'openssl_x509_export returns boolean' );
		if ( !$result ) {
			throw new OpenSSLException();
		}
	}

	/**
	 * Calculate the fingerprint, or digest, of the X.509 certificate
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-fingerprint.php
	 *
	 * @throws OpenSSLException
	 */
	public function fingerprint( string $hashAlgorithm = 'sha1', bool $rawOutput = false ): string
	{
		OpenSSLException::flushErrorMessages();
		$result = \openssl_x509_fingerprint( $this->getResource(), $hashAlgorithm, $rawOutput );
		\assert( false === $result || \is_string( $result ), 'openssl_x509_fingerprint returns string or false' );
		if ( false === $result ) {
			throw new OpenSSLException();
		}

		return $result;
	}
}

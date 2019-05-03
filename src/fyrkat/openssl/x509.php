<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

/** @psalm-suppress PropertyNotSetInConstructor */
class X509
{
	use ResourceOwner;

	/**
	 * Create a x.509 resource and wrap around it
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-read.php
	 * @see http://php.net/manual/en/openssl.certparams.php
	 *
	 * @param resource|string $x509certdata File path to PEM file, or contents of a PEM file
	 */
	public function __construct( $x509certdata )
	{
		OpenSSLException::flushErrorMessages();
		$data = @\openssl_x509_read( $x509certdata );
		/** @psalm-suppress RedundantCondition */
		\assert( false === $data || \is_resource( $data ), 'openssl_x509_read returns resource or false' );
		if ( false === $data ) {
			throw new OpenSSLException();
		}

		$this->setResource( $data );
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

	public function __toString()
	{
		$out = '';
		$this->export( $out, false );

		return $out;
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
		/** @psalm-suppress RedundantCondition */
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
		/** @psalm-suppress RedundantCondition */
		\assert( \is_bool( $result ), 'openssl_x509_export returns boolean' );
		if ( !$result ) {
			throw new OpenSSLException();
		}
	}

	/**
	 * Calculate the fingerprint, or digest, of the X.509 certificate
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-fingerprint.php
	 * @see http://php.net/manual/en/function.openssl-get-md-methods.php
	 *
	 * @param string $hashAlgorithm The digest method or hash algorithm to use
	 * @param bool   $rawOutput     TRUE to output raw binary data, or FALSE to output lowercase hexits
	 *
	 * @throws OpenSSLException
	 */
	public function fingerprint( string $hashAlgorithm = 'sha1', bool $rawOutput = false ): string
	{
		OpenSSLException::flushErrorMessages();
		$result = \openssl_x509_fingerprint( $this->getResource(), $hashAlgorithm, $rawOutput );
		/** @psalm-suppress RedundantCondition */
		\assert( false === $result || \is_string( $result ), 'openssl_x509_fingerprint returns string or false' );
		if ( false === $result ) {
			throw new OpenSSLException();
		}

		return $result;
	}

	/**
	 * Parse the X.509 certificate
	 *
	 * @param bool $longNames Whether to use short or long names, e.g. CN or commonName
	 *
	 * @return X509Data The parsed data from the certificate
	 */
	public function parse( bool $longNames = false ): X509Data
	{
		OpenSSLException::flushErrorMessages();
		$result = \openssl_x509_parse( $this->getResource(), !$longNames );
		/** @psalm-suppress RedundantCondition */
		\assert( false === $result || \is_array( $result ), 'openssl_x509_fingerprint returns array or false' );
		if ( false === $result ) {
			throw new OpenSSLException();
		}

		return new X509Data( $result, $longNames );
	}
}

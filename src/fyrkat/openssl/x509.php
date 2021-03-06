<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

use DateTimeImmutable;

/**
 * Wrapper class around a public key resource
 *
 * This class provides functions parallel to openssl_x509_*.
 */
class X509 extends OpenSSLResource
{
	const PURPOSE_SSL_CLIENT = \X509_PURPOSE_SSL_CLIENT;

	const PURPOSE_SSL_SERVER = \X509_PURPOSE_SSL_SERVER;

	const PURPOSE_NS_SSL_SERVER = \X509_PURPOSE_NS_SSL_SERVER;

	const PURPOSE_SMIME_SIGN = \X509_PURPOSE_SMIME_SIGN;

	const PURPOSE_SMIME_ENCRYPT = \X509_PURPOSE_SMIME_ENCRYPT;

	const PURPOSE_CRL_SIGN = \X509_PURPOSE_CRL_SIGN;

	const PURPOSE_ANY = \X509_PURPOSE_ANY;

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
			throw new OpenSSLException( 'openssl_x509_read' );
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

	/**
	 * Get the certificate as a PEM string
	 *
	 * @see $this->export(string)
	 *
	 * @return string
	 */
	public function __toString(): string
	{
		return $this->getX509Pem();
	}

	/**
	 * Check if a private key corresponds to this certificate
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-check-private-key.php
	 *
	 * @param PrivateKey $key The private key to check against
	 *
	 * @return bool Returns True if $key is the private key that corresponds to cert, or false otherwise
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
	 * @param int           $purpose       Any PURPOSE_ value
	 * @param array<string> $ca            File and directory names that specify the locations of trusted CA files
	 * @param ?string       $untrustedfile PEM encoded file holding certificates that can be used to help verify this certificate
	 *
	 * @throws OpenSSLException
	 *
	 * @return bool The certificate can be used for $purpose
	 */
	public function checkPurpose( int $purpose, array $ca = [], string $untrustedfile = null ): bool
	{
		OpenSSLException::flushErrorMessages();
		if ( null === $untrustedfile ) {
			$result = @\openssl_x509_checkpurpose(
					$this->getResource(),
					$purpose,
					$ca
				);
		} else {
			$result = @\openssl_x509_checkpurpose(
					$this->getResource(),
					$purpose,
					$ca,
					$untrustedfile
				);
		}
		\assert(
				-1 === $result || \is_bool( $result ),
				'openssl_x509_checkpurpose returns -1 or boolean'
			);
		if ( -1 === $result ) {
			throw new OpenSSLException( 'openssl_x509_checkpurpose' );
		}

		return $result;
	}

	/**
	 * Export a certificate to file
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-export-to-file.php
	 *
	 * @param string $outputFileName Path to the output file
	 * @param bool   $withText       Add additional human-readable information
	 *
	 * @throws OpenSSLException
	 */
	public function exportToFile( string $outputFileName, bool $withText = false ): void
	{
		OpenSSLException::flushErrorMessages();
		$result = \openssl_x509_export_to_file( $this->getResource(), $outputFileName, !$withText );
		/** @psalm-suppress RedundantCondition */
		\assert(
				\is_bool( $result ),
				'openssl_x509_export_to_file returns boolean'
			);
		if ( !$result ) {
			throw new OpenSSLException( 'openssl_x509_export_to_file' );
		}
	}

	/**
	 * Export a certificate as a string
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-export.php
	 *
	 * @param string &$output  String to write PEM encoded X509 certificate in
	 * @param bool   $withText Add additional human-readable information
	 *
	 * @throws OpenSSLException
	 */
	public function export( string &$output, bool $withText = false ): void
	{
		OpenSSLException::flushErrorMessages();
		$result = \openssl_x509_export( $this->getResource(), $output, !$withText );
		/** @psalm-suppress RedundantCondition */
		\assert(
				\is_bool( $result ),
				'openssl_x509_export returns boolean'
			);
		if ( !$result ) {
			throw new OpenSSLException( 'openssl_x509_export' );
		}
	}

	/**
	 * Get the public key associated with this certificate
	 *
	 * @return PublicKey the public key associated with this certificate
	 */
	public function getPublicKey(): PublicKey
	{
		return new PublicKey( $this );
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
	 *
	 * @return string The fingerprint
	 */
	public function fingerprint( string $hashAlgorithm = 'sha1', bool $rawOutput = false ): string
	{
		OpenSSLException::flushErrorMessages();
		$result = @\openssl_x509_fingerprint( $this->getResource(), $hashAlgorithm, $rawOutput );
		/** @psalm-suppress RedundantCondition */
		\assert(
				false === $result || \is_string( $result ),
				'openssl_x509_fingerprint returns string or false'
			);
		if ( false === $result ) {
			throw new OpenSSLException( 'openssl_x509_fingerprint' );
		}

		return $result;
	}

	/**
	 * Parse the X.509 certificate
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-parse.php
	 *
	 * @param bool $longNames Whether to use short or long names, e.g. CN or commonName
	 *
	 * @throws OpenSSLException
	 *
	 * @return array The parsed data from the certificate
	 */
	public function parse( bool $longNames = false ): array
	{
		OpenSSLException::flushErrorMessages();
		$result = \openssl_x509_parse( $this->getResource(), !$longNames );
		/** @psalm-suppress RedundantCondition */
		\assert(
				false === $result || \is_array( $result ),
				'openssl_x509_parse returns array or false'
			);
		if ( false === $result ) {
			throw new OpenSSLException( 'openssl_x509_parse' );
		}

		return $result;
	}

	/**
	 * Get the X.509 PEM
	 *
	 * @param bool $withText Add additional human-readable information
	 *
	 * @throws OpenSSLException
	 *
	 * @return string PEM encoded X.509 certificate
	 */
	public function getX509Pem( bool $withText = false )
	{
		$result = '';
		$this->export( $result, $withText );

		return $result;
	}

	/**
	 * Get the hash of the certificate
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-parse.php
	 *
	 * @return string The hash of the certificate
	 */
	public function getHash(): string
	{
		return $this->parse( false )['hash'];
	}

	/**
	 * Get the serial number of the certificate as a numeric string
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-parse.php
	 *
	 * @return string The serial number of the certificate
	 */
	public function getSerialNumber(): string
	{
		return $this->parse( false )['serialNumber'];
	}

	/**
	 * Get the serial number of the certificate as a HEX string
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-parse.php
	 *
	 * @return string The serial number of the certificate
	 */
	public function getSerialNumberHex(): string
	{
		return $this->parse( false )['serialNumberHex'];
	}

	/**
	 * Get the subject of the certificate
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-parse.php
	 *
	 * @param bool $longNames Whether to use short or long names, e.g. CN or commonName
	 *
	 * @return DN The subject of the certificate
	 */
	public function getSubject( bool $longNames = false ): DN
	{
		return new DN( $this->parse( $longNames )['subject'] );
	}

	/**
	 * Get the subject of the issuer (CA)
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-parse.php
	 *
	 * @param bool $longNames Whether to use short or long names, e.g. CN or commonName
	 *
	 * @return DN The subject of the issuer (CA)
	 */
	public function getIssuerSubject( bool $longNames = false ): DN
	{
		return new DN( $this->parse( $longNames )['issuer'] );
	}

	/**
	 * Get the name of the certificate, this is based on the subject
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-parse.php
	 *
	 * @return string The name of the certificate
	 */
	public function getName(): string
	{
		return $this->parse( false )['name'];
	}

	/**
	 * Get the version of the certificate
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-parse.php
	 *
	 * @return int The version of the certificate
	 */
	public function getVersion(): int
	{
		return $this->parse( false )['version'];
	}

	/**
	 * Get the earliest date the certificate is valid
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-parse.php
	 *
	 * @return DateTimeImmutable Valid from
	 */
	public function getValidFrom(): DateTimeImmutable
	{
		return new DateTimeImmutable( \sprintf( '@%d', $this->parse( false )['validFrom_time_t'] ) );
	}

	/**
	 * Get the latest date the certificate is valid
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-parse.php
	 *
	 * @return DateTimeImmutable Valid to
	 */
	public function getValidTo(): DateTimeImmutable
	{
		return new DateTimeImmutable( \sprintf( '@%d', $this->parse( false )['validTo_time_t'] ) );
	}

	/**
	 * Get a string representation of the algorithm used to generate the signature
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-parse.php
	 *
	 * @param bool $longNames Whether to use short or long names, e.g. CN or commonName
	 *
	 * @return string signature algorithm
	 */
	public function getSignatureType( bool $longNames = false ): string
	{
		return $longNames
			? $this->parse( true )['signatureTypeLN']
			: $this->parse( false )['signatureTypeSN']
			;
	}

	/**
	 * Get the numeric ID of the algorithm used to generate the signature
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-parse.php
	 *
	 * @return int signature algorithm
	 */
	public function getSignatureNID(): int
	{
		return $this->parse( false )['signatureTypeNID'];
	}

	/**
	 * Get the purposes of this certificate
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-parse.php
	 *
	 * @return array purposes
	 */
	public function getRawPurposes(): array
	{
		return $this->parse( false )['purposes'];
	}

	/**
	 * Get the extensions of this certificate
	 *
	 * @see http://php.net/manual/en/function.openssl-x509-parse.php
	 *
	 * @return array extensions
	 */
	public function getRawExtensions(): array
	{
		return $this->parse( false )['extensions'];
	}
}

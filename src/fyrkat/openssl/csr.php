<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

use DateTimeInterface;
use DomainException;

/**
 * Wrapper class around a CSR variable
 *
 * This class provides functions parallel to openssl_pkey_*.
 */
class CSR
{
	/**
	 * @var resource|string The CSR variable
	 */
	private $csr;

	/**
	 * Construct a CSR object from an existing CSR-string
	 *
	 * @see http://php.net/manual/en/openssl.certparams.php
	 *
	 * @param resource|string $csr PEM formatted CSR, or file://path to CSR PEM
	 */
	public function __construct( $csr )
	{
		\assert(
				\is_string( $csr ) || \is_resource( $csr ),
				'CSR constructor needs resource or string as first argument'
			);
		$this->csr = $csr;
	}

	/**
	 * Get the certificate as a PEM string
	 *
	 * @see $this->getRequestPem(bool)
	 *
	 * @return string The PEM string
	 */
	public function __toString()
	{
		return $this->getRequestPem();
	}

	/**
	 * Generates a CSR
	 *
	 * @see http://php.net/manual/en/function.openssl-csr-new.php
	 *
	 * @param DN                   $dn
	 * @param PrivateKey           $key
	 * @param ?OpenSSLConfig       $configargs
	 * @param ?array<string,mixed> $extraattribs
	 *
	 * @throws OpenSSLException
	 *
	 * @return CSR A CSR from the provided key with the provided DN
	 */
	public static function generate( DN $dn, PrivateKey $key, ?OpenSSLConfig $configargs = null, array $extraattribs = null ): self
	{
		if ( null === $configargs ) {
			$configargs = new OpenSSLConfig();
		}
		$res = $key->getResource();
		OpenSSLException::flushErrorMessages();
		if ( null === $extraattribs ) {
			$result = \openssl_csr_new( $dn->toArray(), $res, $configargs->toArray() );
		} else {
			$result = \openssl_csr_new( $dn->toArray(), $res, $configargs->toArray(), $extraattribs );
		}
		/** @psalm-suppress RedundantCondition */
		\assert(
				false === $result || \is_resource( $result ),
				'openssl_csr_new returns resource or false'
			);
		if ( false === $result ) {
			throw new OpenSSLException( 'openssl_csr_new' );
		}

		return new static( $result );
	}

	/**
	 * Convert date to amount of days in the future, rounded up, from current date
	 *
	 * @param DateTimeInterface $date The object to read the time from
	 *
	 * @return int The amount of days in the future
	 */
	public static function dateToDays( DateTimeInterface $date ): int
	{
		// We could use (new Date())->diff($date)->d
		// but we want to round the amount of days up
		$time = \time();
		$target = $date->getTimestamp();
		if ( $time > $target ) {
			throw new DomainException( 'Provided date is in the past' );
		}

		return (int)\ceil( ( $target - $time ) / 86400 );
	}

	/**
	 * Export the CSR to a file
	 *
	 * @see http://php.net/manual/en/function.openssl-csr-export-to-file.php
	 *
	 * @param string $outputFileName Path to the output file
	 * @param bool   $withText       Add human-readable text to the output
	 *
	 * @throws OpenSSLException
	 */
	public function exportToFile( string $outputFileName, bool $withText = false ): void
	{
		OpenSSLException::flushErrorMessages();
		$result = \openssl_csr_export_to_file( $this->csr, $outputFileName, !$withText );
		/** @psalm-suppress RedundantCondition */
		\assert(
				\is_bool( $result ),
				'openssl_csr_export_to_file returns boolean'
			);
		if ( false === $result ) {
			throw new OpenSSLException( 'openssl_csr_export_to_file' );
		}
	}

	/**
	 * Exports the CSR as a string
	 *
	 * @see http://php.net/manual/en/function.openssl-csr-export.php
	 *
	 * @param string &$output  String to write PEM encoded CSR in
	 * @param bool   $withText Add human-readable text to the output
	 *
	 * @throws OpenSSLException
	 */
	public function export( string &$output, bool $withText = false ): void
	{
		OpenSSLException::flushErrorMessages();
		$result = \openssl_csr_export( $this->csr, $output, !$withText );
		/** @psalm-suppress RedundantCondition */
		\assert(
				\is_bool( $result ),
				'openssl_csr_export returns boolean'
			);
		if ( false === $result ) {
			throw new OpenSSLException( 'openssl_csr_export' );
		}
	}

	/**
	 * Return the public key of a CSR
	 *
	 * @see http://php.net/manual/en/function.openssl-csr-get-public-key.php
	 *
	 * @throws OpenSSLException
	 *
	 * @return PublicKey The public key associated with the CSR
	 */
	public function getPublicKey(): PublicKey
	{
		OpenSSLException::flushErrorMessages();
		$result = \openssl_csr_get_public_key( $this->csr );
		/** @psalm-suppress RedundantCondition */
		\assert(
				false === $result || \is_resource( $result ),
				'openssl_csr_get_public_key returns resource or false'
			);
		if ( false === $result ) {
			throw new OpenSSLException( 'openssl_csr_get_public_key' );
		}

		return new PublicKey( $result );
	}

	/**
	 * Returns the subject of the CSR
	 *
	 * @see http://php.net/manual/en/function.openssl-csr-get-subject.php
	 *
	 * @param bool $longNames Whether to use short or long names, e.g. CN or commonName
	 *
	 * @throws OpenSSLException
	 *
	 * @return DN The subject of the CSR
	 */
	public function getSubject( bool $longNames = false ): DN
	{
		OpenSSLException::flushErrorMessages();
		$result = \openssl_csr_get_subject( $this->csr, !$longNames );
		/** @psalm-suppress RedundantCondition */
		\assert(
				false === $result || \is_array( $result ),
				'openssl_csr_get_subject returns array or false'
			);
		if ( false === $result ) {
			throw new OpenSSLException( 'openssl_csr_get_subject' );
		}

		return new DN( $result );
	}

	/**
	 * Sign a CSR with another certificate (or itself) and generate a certificate
	 *
	 * The validity is in $days from the current date/time.  It may be provided as DateTimeInterface,
	 * but the validity will be rounded up to an integer amount of days from the current date/time,
	 * due to the way the OpenSSL signing function works in PHP.
	 *
	 * @see http://php.net/manual/en/function.openssl-csr-sign.php
	 * @see http://php.net/manual/en/function.random-int.php
	 *
	 * @param ?X509                 $issuerCA   The CA certificate used to sign this CSR, null for self-sign
	 * @param PrivateKey            $issuerKey  The private key corresponding to $issuerCA (if $issuerCA is null,
	 *                                          use the PrivateKey that was used to generate this CSR)
	 * @param DateTimeInterface|int $validDays  the amount of days this certificate must be valid
	 *                                          DateTime is rounded up to the nearest integer amount of days
	 * @param OpenSSLConfig         $configargs OpenSSL Configuration for this signing operation
	 * @param ?int                  $serial     Serial number, generate a random one if omitted
	 *
	 * @throws OpenSSLException
	 * @throws \Exception       an appropriate source of randomness cannot be found
	 *
	 * @return X509 Certificate
	 */
	public function sign( ?X509 $issuerCA, PrivateKey $issuerKey, $validDays, OpenSSLConfig $configargs, int $serial = null ): X509
	{
		\assert(
				\is_int( $validDays ) || $validDays instanceof DateTimeInterface,
				'$validDays must be an integer or DateTimeInterface'
			);
		/** @var int */
		$days = ( $validDays instanceof DateTimeInterface )
			? static::dateToDays( $validDays )
			: $validDays
			;
		if ( $days <= 0 ) {
			throw new DomainException( '$validDays must be a positive integer' );
		}
		if ( null !== $issuerCA && !$issuerCA->checkPrivateKey( $issuerKey ) ) {
			throw new DomainException( 'PrivateKey $issuerKey must match the PublicKey from $issuerCA' );
		}
		if ( null === $serial ) {
			/**
			 * Not ideal, because the serial must be between 0 and 2^159.
			 * PHP uses a signed integer which depends on the architecture,
			 * but rarely is larger than 2^63-1.
			 *
			 * @see https://crypto.stackexchange.com/questions/257/unpredictability-of-x-509-serial-numbers
			 * @see https://stackoverflow.com/questions/37031043/minimum-and-maximum-length-of-x509-serialnumber
			 */
			$serial = \random_int( 0, \PHP_INT_MAX );
		}
		$issuerCertResource = null === $issuerCA ? null : $issuerCA->getResource();
		$issuerKeyResource = $issuerKey->getResource();
		OpenSSLException::flushErrorMessages();
		$result = \openssl_csr_sign( $this->csr, $issuerCertResource, $issuerKeyResource, $days, $configargs->toArray(), $serial );
		/** @psalm-suppress RedundantCondition */
		\assert(
				false === $result || \is_resource( $result ),
				'openssl_csr_sign returns resource or false'
			);
		if ( false === $result ) {
			throw new OpenSSLException( 'openssl_csr_sign' );
		}

		return new X509( $result );
	}

	/**
	 * Exports the CSR as a PEM encoded string
	 *
	 * @see http://php.net/manual/en/function.openssl-csr-export.php
	 *
	 * @param bool $withText Add human-readable text to the output
	 *
	 * @throws OpenSSLException
	 *
	 * @return string The PEM string
	 */
	public function getRequestPem( bool $withText = false )
	{
		$result = '';
		$this->export( $result, $withText );

		return $result;
	}
}

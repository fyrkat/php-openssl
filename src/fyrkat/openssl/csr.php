<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

class CSR
{
	/** @var mixed */
	private $csr;

	/**
	 * Construct a CSR object
	 *
	 * @see http://php.net/manual/en/openssl.certparams.php
	 *
	 * @param resource|string $csr
	 */
	public function __construct( $csr )
	{
		\assert( \is_string( $csr ) || \is_resource( $csr ), 'CSR constructor needs resource or string as first argument' );
		$this->csr = $csr;
	}

	/**
	 * Generates a CSR
	 *
	 * @see http://php.net/manual/en/function.openssl-csr-new.php
	 *
	 * @param DN                  $dn
	 * @param PrivateKey          $key
	 * @param ConfigArgs          $configargs
	 * @param array<string,mixed> $extraattribs
	 *
	 * @throws OpenSSLException
	 *
	 * @return self A CSR from the provided key with the provided DN
	 */
	public static function generate( DN $dn, PrivateKey $key, ConfigArgs $configargs, array $extraattribs = null ): self
	{
		$res = $key->getResource();
		OpenSSLException::flushErrorMessages();
		if ( null === $extraattribs ) {
			$result = \openssl_csr_new( $dn->getArray(), $res, $configargs->getArray() );
		} else {
			$result = \openssl_csr_new( $dn->getArray(), $res, $configargs->getArray(), $extraattribs );
		}
		\assert( false === $result || \is_resource( $result ), 'openssl_csr_new returns resource or false' );
		if ( false === $result ) {
			throw new OpenSSLException();
		}

		return new self( $result );
	}

	/**
	 * Export a CSR to a file
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
		$result = !\openssl_csr_export_to_file( $this->csr, $outputFileName, !$withText );
		\assert( \is_bool( $result ), 'openssl_csr_export_to_file returns boolean' );
		if ( false === $result ) {
			throw new OpenSSLException();
		}
	}

	/**
	 * Exports a CSR as a string
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
		$result = !\openssl_csr_export( $this->csr, $output, !$withText );
		\assert( \is_bool( $result ), 'openssl_csr_export returns boolean' );
		if ( false === $result ) {
			throw new OpenSSLException();
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
		\assert( false === $result || \is_resource( $result ), 'openssl_csr_get_public_key returns resource or false' );
		if ( false === $result ) {
			throw new OpenSSLException();
		}

		return new PublicKey( $result );
	}

	/**
	 * Returns the subject of the CSR
	 *
	 * @see http://php.net/manual/en/function.openssl-csr-get-subject.php
	 *
	 * @todo Should return a DN object instead?
	 *
	 * @param bool $longNames Whether to use short or long names, e.g. CN or commonName
	 *
	 * @return array<string,string> The subject of the CSR
	 */
	public function getSubject( bool $longNames = false ): array
	{
		OpenSSLException::flushErrorMessages();
		$result = \openssl_csr_get_subject( $this->csr, !$longNames );
		/**
		 * Psalm thinks that openssl_csr_get_subject only returns array,
		 * but it can also return false.
		 *
		 * @see https://github.com/php/php-src/blob/ee939b70d316fba104a2d41b72b2c17ac711be6c/ext/openssl/openssl.c#L3667
		 * @psalm-suppress TypeDoesNotContainType
		 */
		\assert( false === $result || \is_array( $result ), 'openssl_csr_get_subject returns array or false' );
		if ( false === $result ) {
			throw new OpenSSLException();
		}

		return $result;
	}

	/**
	 * Sign a CSR with another certificate (or itself) and generate a certificate
	 *
	 * @see http://php.net/manual/en/function.openssl-csr-sign.php
	 *
	 * @param ?X509      $ca   The CA certificate used to sign this CSR, null for self-sign
	 * @param PrivateKey $key  The private key corresponding to $ca (if $ca is null, use the PrivateKey that was used to generate this CSR)
	 * @param int        $days The amount of days this certificate must be valid
	 * @param ConfigArgs OpenSSL Configuration for this signing operation
	 * @param int $serial Serial number, generate a random one if omitted
	 *
	 * @return X509 Certificate
	 */
	public function sign( ?X509 $ca, PrivateKey $key, int $days, ConfigArgs $configargs, int $serial = null ): X509
	{
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
		$cacert = null === $ca ? null : $ca->getResource();
		$privKey = $key->getResource();
		OpenSSLException::flushErrorMessages();
		/**
		 * Psalm thinks that $cacert cannot be null, but documentation says otherwise
		 *
		 * @see http://php.net/manual/en/function.openssl-csr-sign.php
		 * @psalm-suppress PossiblyNullArgument
		 */
		$result = \openssl_csr_sign( $this->csr, $cacert, $privKey, $days, $configargs->getArray(), $serial );
		\assert( false === $result || \is_resource( $result ), 'openssl_csr_sign returns resource or false' );
		if ( false === $result ) {
			throw new OpenSSLException();
		}

		return new X509( $result );
	}
}

<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

use DomainException;

/**
 * Wrapper class around DN arrays
 *
 * Typically, this is an array<string,string>, but sometimes it will
 * be array<string,array<string>> when there are multiple values for the same key.
 *
 * @see http://php.net/manual/en/function.openssl-csr-new.php
 */
class DN
{
	const TRANSLATE_LONG = [
		'countryName' => 'C',
		'stateOrProvinceName' => 'ST',
		'localityName' => 'L',
		'organizationName' => 'O',
		'organizationalUnitName' => 'OU',
		'commonName' => 'CN',
	];

	/**
	 * @var array<string,string|array<string>> Internal DN array
	 */
	private $dnData;

	/**
	 * Construct a new DN
	 *
	 * @param array<string,string|array<string>> $dn
	 */
	public function __construct( array $dn = [] )
	{
		foreach ( $dn as $key => $value ) {
			/** @psalm-suppress DocblockTypeContradiction */
			if ( !\is_string( $key ) ) {
				throw new DomainException( 'DN array keys must be strings' );
			}
			if ( \array_key_exists( $key, self::TRANSLATE_LONG ) ) {
				$dn[self::TRANSLATE_LONG[$key]] = $value;
				unset( $dn[$key] );
			}
		}
		$this->dnData = $dn;
	}

	/**
	 * Get a string representation for this DN
	 *
	 * @return string String representation for this DN
	 */
	public function __toString(): string
	{
		$result = [];
		foreach ( $this->dnData as $key => $values ) {
			\assert( \is_string( $key ), 'All DN keys must be strings' );
			if ( \is_string( $values ) ) {
				$values = [$values];
			}
			foreach ( $values as $value ) {
				$value = \str_replace( ['\\', ','], ['\\\\', '\\,'], $value );
				$result[] = "${key}=${value}";
			}
		}

		return \implode( ', ', $result );
	}

	/**
	 * Get the DN array
	 *
	 * @return array<string,string|array<string>>
	 */
	public function toArray(): array
	{
		return $this->dnData;
	}

	/**
	 * Convenience function for setting the commonName in a new DN
	 * using function chaining
	 *
	 * @return DN A new DN with the commonName set
	 */
	public function setCommonName( string $commonName ): self
	{
		return new self( ['CN' => $commonName] + $this->dnData );
	}

	/**
	 * Convenience function for setting the countryName in a new DN
	 * using function chaining
	 *
	 * @return DN A new DN with the countryName set
	 */
	public function setCountryName( string $countryName ): self
	{
		return new self( ['C' => $countryName] + $this->dnData );
	}

	/**
	 * Convenience function for setting the stateOrProvinceName in a new DN
	 * using function chaining
	 *
	 * @return DN A new DN with the stateOrProvinceName set
	 */
	public function setStateOrProvinceName( string $stateOrProvinceName ): self
	{
		return new self( ['ST' => $stateOrProvinceName] + $this->dnData );
	}

	/**
	 * Convenience function for setting the localityName in a new DN
	 * using function chaining
	 *
	 * @return DN A new DN with the localityName set
	 */
	public function setLocalityName( string $localityName ): self
	{
		return new self( ['L' => $localityName] + $this->dnData );
	}

	/**
	 * Convenience function for setting the organizationName in a new DN
	 * using function chaining
	 *
	 * @return DN A new DN with the organizationName set
	 */
	public function setOrganizationName( string $organizationName ): self
	{
		return new self( ['O' => $organizationName] + $this->dnData );
	}

	/**
	 * Convenience function for setting the organizationalUnitName in a new DN
	 * using function chaining
	 *
	 * @return DN A new DN with the organizationalUnitName set
	 */
	public function setOrganizationalUnitName( string $organizationalUnitName ): self
	{
		return new self( ['OU' => $organizationalUnitName] + $this->dnData );
	}

	/**
	 * Convenience function for setting the emailAddress in a new DN
	 * using function chaining
	 *
	 * @return DN A new DN with the emailAddress set
	 */
	public function setEmailAddress( string $emailAddress ): self
	{
		return new self( ['emailAddress' => $emailAddress] + $this->dnData );
	}
}

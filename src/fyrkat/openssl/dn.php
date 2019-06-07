<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

use ArrayIterator;
use Iterator;
use IteratorAggregate;

/**
 * Wrapper class around DN arrays
 *
 * Typically, this is an array<string,string>, but sometimes it will
 * be array<string,array<string>> when there are multiple values for the same key.
 *
 * @see http://php.net/manual/en/function.openssl-csr-new.php
 */
class DN implements IteratorAggregate
{
	/**
	 * @var array<string,string|array<string>> Internal DN array
	 */
	private $dnData;

	/**
	 * Construct a new DN
	 *
	 * @param array<string,string|array<string>> $dn
	 */
	public function __construct( array $dn )
	{
		$this->dnData = $dn;
	}

	/**
	 * Get a string representation for this DN
	 *
	 * @return string String representation for this DN
	 */
	public function __toString(): string
	{
		$result = '';
		foreach ( $this->dnData as $key => $values ) {
			if ( \is_string( $values ) ) {
				$values = [$values];
			}
			foreach ( $values as $value ) {
				$result .= "/${key}=${value}";
			}
		}

		return $result;
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
	 * Get an iterator for the DN array
	 *
	 * @return Iterator<string,string|array<string>>
	 */
	public function getIterator(): Iterator
	{
		return new ArrayIterator( $this->toArray() );
	}
}

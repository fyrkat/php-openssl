<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

abstract class OpenSSLKey extends OpenSSLResource
{
	/**
	 * Get a (PEM encoded) string representation of the public key
	 *
	 * @see http://php.net/manual/en/function.openssl-pkey-get-details.php
	 *
	 * @return string String starting with -----BEGIN PUBLIC KEY----- and ending with -----EBD PUBLIC KEY-----
	 */
	public function getPublicKeyPem(): string
	{
		$details = $this->getDetails();
		\assert(
				\array_key_exists( 'key', $details ),
				'openssl_pkey_get_details returns array with element "key"'
			);
		\assert(
				\is_string( $details['key'] ),
				'openssl_pkey_get_details returns array with element "key" of type string'
			);

		return $details['key'];
	}

	/**
	 * Get the number of bits
	 *
	 * @see http://php.net/manual/en/function.openssl-pkey-get-details.php
	 *
	 * @return int The number of bits
	 */
	public function getBits(): int
	{
		$details = $this->getDetails();
		\assert(
				\array_key_exists( 'bits', $details ),
				'openssl_pkey_get_details returns array with element "bits"'
			);
		\assert(
				\is_int( $details['bits'] ),
				'openssl_pkey_get_details returns array with element "bits" of type int'
			);

		return $details['bits'];
	}

	/**
	 * Get the type of the key which is one of KeyType::RSA, KeyType::DSA, KeyType::DH, KeyType::EC or KeyType::UNKNOWN
	 *
	 * @see http://php.net/manual/en/function.openssl-pkey-get-details.php
	 * @see {KeyType}
	 *
	 * @return int The type of the key
	 */
	public function getType(): int
	{
		$details = $this->getDetails();
		\assert(
				\array_key_exists( 'type', $details ),
				'openssl_pkey_get_details returns array with element "type"'
			);
		\assert(
				\is_int( $details['type'] ),
				'openssl_pkey_get_details returns array with element "type" of type int'
			);

		return $details['type'];
	}

	/**
	 * Returns an array with the key details
	 *
	 * @see http://php.net/manual/en/function.openssl-pkey-get-details.php
	 *
	 * @throws OpenSSLException
	 *
	 * @return array<string,int|string|array<int|string>>
	 */
	public function getDetails(): array
	{
		OpenSSLException::flushErrorMessages();
		$details = \openssl_pkey_get_details( $this->getResource() );
		/** @psalm-suppress RedundantCondition */
		\assert(
				false === $details || \is_array( $details ),
				'openssl_pkey_get_details returns array or false'
			);
		if ( false === $details ) {
			throw new OpenSSLException( 'openssl_pkey_get_details' );
		}

		return $details;
	}
}

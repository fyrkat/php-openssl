<?php declare(strict_types=1 );

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

class ConfigArgs
{
	/** @var ?string */
	private $digestAlg = null;

	/** @var ?string */
	private $x509Extensions = null;

	/** @var ?string */
	private $reqExtensions = null;

	/** @var ?int */
	private $privateKeyBits = null;

	/** @var ?int */
	private $privateKeyType = null;

	/** @var ?bool */
	private $encryptKey = null;

	/** @var ?int */
	private $encryptKeyCipher = null;

	/** @var ?string */
	private $curveName = null;

	/** @var ?string */
	private $config = null;

	/**
	 * @param array<string,bool|int|string> $configargs
	 */
	public function __construct(array $configargs = [] )
	{
		foreach ($configargs as $key => $value ) {
			switch ($key ) {
				case 'digest_alg':
					\assert(\is_string($value ), 'digest_alg is string' );
					$this->digestAlg = $value;
					continue;
				case 'x509_extensions':
					\assert(\is_string($value ), 'x509_extensions is string' );
					$this->x509Extensions = $value;
					continue;
				case 'req_extensions':
					\assert(\is_string($value ), 'req_extensions is string' );
					$this->reqExtensions = $value;
					continue;
				case 'private_key_bits':
					\assert(\is_int($value ), 'private_key_bits is int' );
					$this->privateKeyBits = $value;
					continue;
				case 'private_key_type':
					\assert(\is_int($value ), 'private_key_type is int' );
					$this->privateKeyType = $value;
					continue;
				case 'encrypt_key':
					\assert(\is_bool($value ), 'encrypt_key is bool' );
					$this->encryptKey = $value;
					continue;
				case 'encrypt_key_cipher':
					\assert(\is_int($value ), 'encrypt_key_cipher is int' );
					$this->encryptKeyCipher = $value;
					continue;
				case 'curve_name':
					\assert(\is_string($value ), 'curve_name is string' );
					$this->curveName = $value;
					continue;
				case 'config':
					\assert(\is_string($value ), 'config is string' );
					$this->config = $value;
					continue;
				default: \assert(false, "Illegal \$configargs key ${key}" );
			}
		}
	}

	/**
	 * @return array<string,mixed>
	 */
	public function getArray(): array
	{
		$result = [];
		if (null !== $this->digestAlg ) {
			$result['digest_alg'] = $this->digestAlg;
		}
		if (null !== $this->x509Extensions ) {
			$result['x509_extensions'] = $this->x509Extensions;
		}
		if (null !== $this->reqExtensions ) {
			$result['req_extensions'] = $this->reqExtensions;
		}
		if (null !== $this->privateKeyBits ) {
			$result['private_key_bits'] = $this->privateKeyBits;
		}
		if (null !== $this->privateKeyType ) {
			$result['private_key_type'] = $this->privateKeyType;
		}
		if (null !== $this->encryptKey ) {
			$result['encrypt_key'] = $this->encryptKey;
		}
		if (null !== $this->encryptKeyCipher ) {
			$result['encrypt_key_cipher'] = $this->encryptKeyCipher;
		}
		if (null !== $this->curveName ) {
			$result['curve_name'] = $this->curveName;
		}
		if (null !== $this->config ) {
			$result['config'] = $this->config;
		}

		return $result;
	}
}

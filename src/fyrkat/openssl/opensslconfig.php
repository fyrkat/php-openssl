<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

class OpenSSLConfig
{
	const COMPAT_MODERN = [
		'digest_alg' => 'SHA256',
		'private_key_bits' => 2048,
		'private_key_type' => KeyType::EC,
		'curve_name' => 'prime256v1',
	];

	const COMPAT_INTERMEDIATE = [
		'digest_alg' => 'SHA256',
		'private_key_bits' => 2048,
		'private_key_type' => KeyType::RSA,
		'curve_name' => 'prime256v1',
	];

	const COMPAT_OLD = [
		'digest_alg' => 'SHA256',
		'private_key_bits' => 2048,
		'private_key_type' => KeyType::RSA,
		'curve_name' => 'prime256v1',
	];

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
	public function __construct( array $configargs = [] )
	{
		foreach ( $configargs as $key => $value ) {
			switch ( $key ) {
				case 'digest_alg':
					\assert( \is_string( $value ), 'digest_alg is string' );
					$this->digestAlg = $value;
					break;
				case 'x509_extensions':
					\assert( \is_string( $value ), 'x509_extensions is string' );
					$this->x509Extensions = $value;
					break;
				case 'req_extensions':
					\assert( \is_string( $value ), 'req_extensions is string' );
					$this->reqExtensions = $value;
					break;
				case 'private_key_bits':
					\assert( \is_int( $value ), 'private_key_bits is int' );
					$this->privateKeyBits = $value;
					break;
				case 'private_key_type':
					\assert( \is_int( $value ), 'private_key_type is int' );
					$this->privateKeyType = $value;
					break;
				case 'encrypt_key':
					\assert( \is_bool( $value ), 'encrypt_key is bool' );
					$this->encryptKey = $value;
					break;
				case 'encrypt_key_cipher':
					\assert( \is_int( $value ), 'encrypt_key_cipher is int' );
					$this->encryptKeyCipher = $value;
					break;
				case 'curve_name':
					\assert( \is_string( $value ), 'curve_name is string' );
					$this->curveName = $value;
					break;
				case 'config':
					\assert( \is_string( $value ), 'config is string' );
					$this->config = $value;
					break;
				default: \assert( false, "Illegal \$configargs key ${key}" );
			}
		}
	}

	public static function getOpenSSLConfigFilePath(): string
	{
		return \implode( \DIRECTORY_SEPARATOR, [__DIR__, 'openssl.cnf'] );
	}

	public static function caReq( array $compat = self::COMPAT_INTERMEDIATE ): self
	{
		return new static( \array_merge( $compat, [
			'x509_extensions' => 'ca_req',
			'config' => static::getOpenSSLConfigFilePath(),
		] ) );
	}

	public static function clientReq( array $compat = self::COMPAT_INTERMEDIATE ): self
	{
		return new static( \array_merge( $compat, [
			'x509_extensions' => 'client_req',
			'config' => static::getOpenSSLConfigFilePath(),
		] ) );
	}

	public static function serverReq( array $compat = self::COMPAT_INTERMEDIATE ): self
	{
		return new static( \array_merge( $compat, [
			'x509_extensions' => 'server_req',
			'config' => static::getOpenSSLConfigFilePath(),
		] ) );
	}

	/**
	 * @return array<string,bool|int|string>
	 */
	public function getArray(): array
	{
		$result = [];
		if ( null !== $this->digestAlg ) {
			$result['digest_alg'] = $this->digestAlg;
		}
		if ( null !== $this->x509Extensions ) {
			$result['x509_extensions'] = $this->x509Extensions;
		}
		if ( null !== $this->reqExtensions ) {
			$result['req_extensions'] = $this->reqExtensions;
		}
		if ( null !== $this->privateKeyBits ) {
			$result['private_key_bits'] = $this->privateKeyBits;
		}
		if ( null !== $this->privateKeyType ) {
			$result['private_key_type'] = $this->privateKeyType;
		}
		if ( null !== $this->encryptKey ) {
			$result['encrypt_key'] = $this->encryptKey;
		}
		if ( null !== $this->encryptKeyCipher ) {
			$result['encrypt_key_cipher'] = $this->encryptKeyCipher;
		}
		if ( null !== $this->curveName ) {
			$result['curve_name'] = $this->curveName;
		}
		if ( null !== $this->config ) {
			$result['config'] = $this->config;
		}

		return $result;
	}
}

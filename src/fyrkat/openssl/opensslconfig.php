<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

use Throwable;
use ArrayAccess;
use DomainException;

/**
 * Class for OpenSSL configuration as used by openssl_* functions
 *
 * @see http://php.net/manual/en/function.openssl-csr-new.php
 * @see http://php.net/manual/en/function.openssl-csr-sign.php
 * @see http://php.net/manual/en/function.openssl-pkey-new.php
 */
class OpenSSLConfig implements ArrayAccess
{
	/** @var array Configuration for using an elliptic curve key */
	const KEY_EC = [
		'private_key_type' => OpenSSLKey::KEYTYPE_EC,
	];

	/** @var array Configuration for using an RSA key */
	const KEY_RSA = [
		'private_key_type' => OpenSSLKey::KEYTYPE_RSA,
	];

	/** @var array Configuration for signing a CA certificate */
	const X509_CA = [
		'x509_extensions' => 'x509_ca',
	];

	/** @var array Configuration for signing a client certificate */
	const X509_CLIENT = [
		'x509_extensions' => 'x509_client',
	];

	/** @var array Configuration for signing a server certificate */
	const X509_SERVER = [
		'x509_extensions' => 'x509_server',
	];

	const CIPHER_RC2_40 = \OPENSSL_CIPHER_RC2_40;

	const CIPHER_RC2_128 = \OPENSSL_CIPHER_RC2_128;

	const CIPHER_RC2_64 = \OPENSSL_CIPHER_RC2_64;

	const CIPHER_DES = \OPENSSL_CIPHER_DES;

	const CIPHER_3DES = \OPENSSL_CIPHER_3DES;

	const CIPHER_AES_128_CBC = \OPENSSL_CIPHER_AES_128_CBC;

	const CIPHER_AES_192_CBC = \OPENSSL_CIPHER_AES_192_CBC;

	const CIPHER_AES_256_CBC = \OPENSSL_CIPHER_AES_256_CBC;

	const CIPHERS = [self::CIPHER_RC2_40, self::CIPHER_RC2_128, self::CIPHER_RC2_64, self::CIPHER_DES, self::CIPHER_3DES, self::CIPHER_AES_128_CBC, self::CIPHER_AES_192_CBC, self::CIPHER_AES_256_CBC];

	/** @var ?string hash method used for digest or signature hash */
	private $digestAlg = null;

	/** @var ?string which extensions should be used when creating an x509 certificate */
	private $x509Extensions = null;

	/** @var ?string which extensions should be used when creating a CSR */
	private $reqExtensions = null;

	/** @var ?int bits used to generate a private key */
	private $privateKeyBits = null;

	/** @var ?int type of private key to create */
	private $privateKeyType = null;

	/** @var ?bool whether the private key must be encrypted with a passphrase */
	private $encryptKey = null;

	/** @var ?int cipher to use for encrypting the private key */
	private $encryptKeyCipher = null;

	/** @var ?string curve to use for elliptic curve calculation */
	private $curveName = null;

	/** @var ?string path to OpenSSL config file */
	private $config = null;

	/**
	 * Construct an OpenSSL configuration object
	 *
	 * Use one of KEY_EC, KEY_RSA for generating a keypair
	 * Use one of X509_CA, X509_CLIENT, X509_SERVER for signing
	 * For making a CSR you can use the default config
	 *
	 * @see http://php.net/manual/en/function.openssl-csr-new.php
	 *
	 * @param array<string,bool|int|string> $configargs Config args
	 */
	public function __construct( array $configargs = [] )
	{
		if ( !\array_key_exists( 'digest_alg', $configargs ) ) {
			$configargs['digest_alg'] = 'sha256';
		}
		if ( !\array_key_exists( 'private_key_type', $configargs ) ) {
			$configargs['private_key_type'] = OpenSSLKey::KEYTYPE_RSA;
		}
		if ( !\array_key_exists( 'private_key_bits', $configargs ) ) {
			$configargs['private_key_bits'] = 2048;
		}
		if ( !\array_key_exists( 'curve_name', $configargs ) ) {
			$configargs['curve_name'] = 'prime256v1';
		}
		if ( !\array_key_exists( 'encrypt_key', $configargs ) ) {
			$configargs['encrypt_key'] = false;
		}
		if ( !\array_key_exists( 'config', $configargs ) ) {
			$configargs['config'] = \implode( \DIRECTORY_SEPARATOR, [__DIR__, 'openssl.cnf'] );
		}

		foreach ( $configargs as $key => $value ) {
			switch ( $key ) {
				case 'digest_alg':
					static::assertType( $key, $value, 'string' );
					\assert( \is_string( $value ), 'static::assertType must verify that digest_alg is a string' );
					$this->setDigestAlg( $value );
					break;
				case 'x509_extensions':
					static::assertType( $key, $value, 'string' );
					\assert( \is_string( $value ), 'static::assertType must verify that x509_extensions is a string' );
					$this->setX509Extensions( $value );
					break;
				case 'req_extensions':
					static::assertType( $key, $value, 'string' );
					\assert( \is_string( $value ), 'static::assertType must verify that req_extensions is a string' );
					$this->setReqExtensions( $value );
					break;
				case 'private_key_bits':
					static::assertType( $key, $value, 'integer' );
					\assert( \is_int( $value ), 'static::assertType must verify that private_key_bits is an integer;' );
					$this->setPrivateKeyBits( $value );
					break;
				case 'private_key_type':
					static::assertType( $key, $value, 'integer' );
					\assert( \is_int( $value ), 'static::assertType must verify that private_key_type is an integer;' );
					$this->setPrivateKeyType( $value );
					break;
				case 'encrypt_key':
					static::assertType( $key, $value, 'boolean' );
					\assert( \is_bool( $value ), 'static::assertType must verify that encrypt_key is a boolean' );
					$this->setEncryptKey( $value );
					break;
				case 'encrypt_key_cipher':
					static::assertType( $key, $value, 'integer' );
					\assert( \is_int( $value ), 'static::assertType must verify that encrypt_key_cipher is an integer;' );
					$this->setEncryptKeyCipher( $value );
					break;
				case 'curve_name':
					static::assertType( $key, $value, 'string' );
					\assert( \is_string( $value ), 'static::assertType must verify that curve_name is a string' );
					$this->setCurveName( $value );
					break;
				case 'config':
					static::assertType( $key, $value, 'string' );
					\assert( \is_string( $value ), 'static::assertType must verify that config is a string' );
					$this->setConfig( $value );
					break;
				default: \assert( false, "Illegal \$configargs key ${key}" );
			}
		}
	}

	/**
	 * Get list of available curve names for ECC
	 *
	 * @see http://php.net/manual/en/function.openssl-get-curve-names.php
	 *
	 * @return array Available curve names
	 * @psalm-suppress RedundantCondition
	 */
	public static function getCurveNames(): array
	{
		$result = \openssl_get_curve_names();
		\assert( \is_array( $result ), 'openssl_get_curve_names returns array' );

		return $result;
	}

	/**
	 * Get available digest methods
	 *
	 * @see http://php.net/manual/en/function.openssl-get-md-methods.php
	 *
	 * @param bool $aliases digest aliases should be included
	 *
	 * @return array Available digest methods
	 * @psalm-suppress RedundantCondition
	 */
	public static function getMdMethods( bool $aliases = false ): array
	{
		$result = \openssl_get_md_methods( $aliases );
		\assert( \is_array( $result ), 'openssl_get_md_methods returns array' );

		return $result;
	}

	/**
	 * Build the array that can be used in an openssl_ function
	 *
	 * @see http://php.net/manual/en/function.openssl-csr-new.php
	 * @see http://php.net/manual/en/function.openssl-csr-sign.php
	 *
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

	/**
	 * Get hash method used for digest or signature hash
	 *
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 * @see https://www.php.net/manual/en/function.openssl-get-md-methods.php
	 *
	 * @return string hash method used for digest or signature hash
	 */
	public function getDigestAlg(): string
	{
		\assert( null !== $this->digestAlg, 'digest_alg must not be null' );

		return $this->digestAlg;
	}

	/**
	 * Set hash method used for digest or signature hash
	 *
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 * @see https://www.php.net/manual/en/function.openssl-get-md-methods.php
	 *
	 * @param ?string $digestAlg hash method used for digest or signature hash
	 */
	public function setDigestAlg( ?string $digestAlg ): void
	{
		if ( null === $digestAlg || !\in_array( $digestAlg, $this->getMdMethods( true ), true ) ) {
			throw new DomainException( \sprintf( 'Attempted to set digest_alg to %s but it is not supported according to openssl_get_md_methods()', $digestAlg ?? 'null' ) );
		}
		$this->digestAlg = $digestAlg;
	}

	/**
	 * Get which extensions should be used when creating an x509 certificate
	 *
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 *
	 * @return ?string which extensions should be used when creating an x509 certificate
	 */
	public function getX509Extensions(): ?string
	{
		return $this->x509Extensions;
	}

	/**
	 * Set which extensions should be used when creating an x509 certificate
	 *
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 *
	 * @param ?string $x509Extensions which extensions should be used when creating an x509 certificate
	 */
	public function setX509Extensions( ?string $x509Extensions ): void
	{
		$this->x509Extensions = $x509Extensions;
	}

	/**
	 * Get which extensions should be used when creating a CSR
	 *
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 *
	 * @return ?string which extensions should be used when creating a CSR
	 */
	public function getReqExtensions(): ?string
	{
		return $this->reqExtensions;
	}

	/**
	 * Set which extensions should be used when creating a CSR
	 *
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 *
	 * @param ?string $reqExtensions which extensions should be used when creating a CSR
	 */
	public function setReqExtensions( ?string $reqExtensions ): void
	{
		$this->reqExtensions = $reqExtensions;
	}

	/**
	 * Get how many bits should be used to generate a private key
	 *
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 *
	 * @return int how many bits should be used to generate a private key
	 */
	public function getPrivateKeyBits(): int
	{
		\assert( null !== $this->privateKeyBits, 'private_key_bits should never be null' );

		return $this->privateKeyBits;
	}

	/**
	 * Set how many bits should be used to generate a private key
	 *
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 *
	 * @param ?int $privateKeyBits how many bits should be used to generate a private key
	 */
	public function setPrivateKeyBits( ?int $privateKeyBits ): void
	{
		if ( null === $privateKeyBits || $privateKeyBits < 384 ) {
			throw new DomainException( \sprintf( 'private_key_bits is too small; it needs to be at least 384 bits, not %s', $privateKeyBits ?? 'null' ) );
		}
		$this->privateKeyBits = $privateKeyBits;
	}

	/**
	 * Get the type of private key to create
	 *
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 *
	 * @return int The type of private key to create, one of OpenSSLKey::KEYTYPES
	 */
	public function getPrivateKeyType(): int
	{
		\assert( null !== $this->privateKeyType, 'private_key_type should never be null' );

		return $this->privateKeyType;
	}

	/**
	 * Set the type of private key to create
	 *
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 *
	 * @param ?int $privateKeyType The type of private key to create, one of OpenSSLKey::KEYTYPES
	 */
	public function setPrivateKeyType( ?int $privateKeyType ): void
	{
		if ( null === $privateKeyType || !\in_array( $privateKeyType, OpenSSLKey::KEYTYPES, true ) ) {
			throw new DomainException( \sprintf( 'Attempted to set private_key_type to %s but only one of the following is supported: %s', $privateKeyType ?? 'null', \implode( ',', OpenSSLKey::KEYTYPES ) ) );
		}
		$this->privateKeyType = $privateKeyType;
	}

	/**
	 * Get whether the private key must be encrypted with a passphrase
	 *
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 * @see OpenSSLConfig::getEncryptKeyCipher()
	 *
	 * @return ?bool private key must be encrypted with a passphrase
	 */
	public function getEncryptKey(): ?bool
	{
		return $this->encryptKey;
	}

	/**
	 * Set whether the private key must be encrypted with a passphrase
	 *
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 * @see OpenSSLConfig::setEncryptKeyCipher(string)
	 *
	 * @param ?bool $encryptKey private key must be encrypted with a passphrase
	 */
	public function setEncryptKey( ?bool $encryptKey ): void
	{
		$this->encryptKey = $encryptKey;
	}

	/**
	 * Get cipher to use for encrypting the private key
	 *
	 * @see OpenSSLConfig::getEncryptKey()
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 *
	 * @return ?int One of OpenSSLConfig::CIPHERS
	 */
	public function getEncryptKeyCipher(): ?int
	{
		return $this->encryptKeyCipher;
	}

	/**
	 * Set cipher to use for encrypting the private key
	 *
	 * @see OpenSSLConfig::setEncryptKey(bool)
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 *
	 * @param ?int $encryptKeyCipher One of OpenSSLConfig::CIPHERS
	 */
	public function setEncryptKeyCipher( ?int $encryptKeyCipher ): void
	{
		$this->encryptKeyCipher = $encryptKeyCipher;
	}

	/**
	 * Get curve to use for elliptic curve calculation
	 *
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 * @see https://www.php.net/manual/en/function.openssl-get-curve-names.php
	 *
	 * @return ?string Curve name, one of openssl_get_curve_names()
	 */
	public function getCurveName(): ?string
	{
		return $this->curveName;
	}

	/**
	 * Set curve to use for elliptic curve calculation
	 *
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 * @see https://www.php.net/manual/en/function.openssl-get-curve-names.php
	 *
	 * @param ?string $curveName Curve name, one of openssl_get_curve_names()
	 */
	public function setCurveName( ?string $curveName ): void
	{
		if ( null === $curveName || !\in_array( $curveName, $this->getCurveNames(), true ) ) {
			throw new DomainException( \sprintf( 'Attempted to set curve_name to %s but it is not supported according to openssl_get_curve_names()', $curveName ?? 'null' ) );
		}
		$this->curveName = $curveName;
	}

	/**
	 * Get path to OpenSSL config file
	 * There is a built-in openssl.cnf file in the same directory as this file.
	 * This is the file used if the configuration is not provided by any other means.
	 *
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 *
	 * @return ?string Path to your own alternative openssl.conf file
	 */
	public function getConfig(): ?string
	{
		return $this->config;
	}

	/**
	 * Get path to OpenSSL config file
	 * There is a built-in openssl.cnf file in the same directory as this file.
	 * This is the file used if the configuration is not provided by any other means.
	 *
	 * @see https://www.php.net/manual/en/function.openssl-csr-new.php
	 *
	 * @param ?string $config Path to your own alternative openssl.conf file
	 */
	public function setConfig( ?string $config ): void
	{
		$this->config = $config;
	}

	/**
	 * Check if the provided config argument exists in the configuration array
	 *
	 * @param mixed $configArg The config argument to check
	 *
	 * @return bool The config argument exists
	 */
	public function offsetexists( $configArg ): bool
	{
		try {
			return null !== $this->offsetget( $configArg );
		} catch ( Throwable $_ ) {
			return false;
		}
	}

	/**
	 * Get the value of the provided config argument
	 *
	 * @param mixed $configArg The config argument to retrieve
	 *
	 * @return mixed The value of the config argument
	 */
	public function offsetget( $configArg )
	{
		switch ( $configArg ) {
			case 'digest_alg':return $this->getDigestAlg();
			case 'x509_extensions':return $this->getX509Extensions();
			case 'req_extensions':return $this->getReqExtensions();
			case 'private_key_bits':return $this->getPrivateKeyBits();
			case 'private_key_type':return $this->getPrivateKeyType();
			case 'encrypt_key':return $this->getEncryptKey();
			case 'encrypt_key_cipher':return $this->getEncryptKeyCipher();
			case 'curve_name':return $this->getCurveName();
			case 'config':return $this->getConfig();
			default: return;
		}
	}

	/**
	 * Set the value of the provided config argument
	 *
	 * @param mixed $configArg The config argument to set
	 * @param mixed $value     The new value of the config argument
	 */
	public function offsetset( $configArg, $value ): void
	{
		switch ( $configArg ) {
			case 'digest_alg':$this->setDigestAlg( $value ); break;
			case 'x509_extensions':$this->setX509Extensions( $value ); break;
			case 'req_extensions':$this->setReqExtensions( $value ); break;
			case 'private_key_bits':$this->setPrivateKeyBits( $value ); break;
			case 'private_key_type':$this->setPrivateKeyType( $value ); break;
			case 'encrypt_key':$this->setEncryptKey( $value ); break;
			case 'encrypt_key_cipher':$this->setEncryptKeyCipher( $value ); break;
			case 'curve_name':$this->setCurveName( $value ); break;
			case 'config':$this->setConfig( $value ); break;
		}
	}

	/**
	 * Unset the value of the provided config argument
	 *
	 * @param mixed $configArg The config argument to unset
	 */
	public function offsetunset( $configArg ): void
	{
		$this->offsetset( $configArg, null );
	}

	/**
	 * Check that $value (named $name) is of type $type
	 *
	 * @param string $name  The name of the variable (used in error if check fails)
	 * @param mixed  $value The value to test
	 * @param string $type  The expected type
	 *
	 * @throws DomainException If the tested type doesn't match the expected type
	 */
	private static function assertType( string $name, $value, string $type ): void
	{
		if ( \gettype( $value ) !== $type ) {
			throw new DomainException( \sprintf( 'Expected %s to be %s but is %s', $name, $type, \gettype( $value ) ) );
		}
	}
}

<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl\tests;

use DateInterval;
use DateTimeImmutable;

use fyrkat\openssl\CSR;
use fyrkat\openssl\OpenSSLConfig;

use PHPUnit\Framework\TestCase;

class ConfigTest extends TestCase
{
	public function testCasting(): void
	{
		$emptyConfig = new OpenSSLConfig();
		$this->assertSame(
				[
					'digest_alg' => 'sha256',
					'private_key_bits' => 2048,
					'private_key_type' => 0,
					'encrypt_key' => false,
					'curve_name' => 'prime256v1',
					'config' => \dirname( __DIR__ ) . '/src/fyrkat/openssl/openssl.cnf',
				],
				$emptyConfig->toArray()
			);
	}

	public function testFuture(): void
	{
		$future = ( new DateTimeImmutable() )->add( new DateInterval('P1D') );
		$this->assertSame( 1, CSR::dateToDays( $future ) );
	}

	public function testPast(): void
	{
		$this->expectException( 'DomainException' );
		$past = ( new DateTimeImmutable() )->sub( new DateInterval('P1D') );
		CSR::dateToDays( $past );
	}

	public function testTooFewBitsConfig(): void
	{
		$this->expectException( 'DomainException' );
		$config = new OpenSSLConfig( ['private_key_bits' => 256] );
		$key = new PrivateKey( $config );
	}
}

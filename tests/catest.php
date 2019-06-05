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

use fyrkat\openssl\DN;
use fyrkat\openssl\CSR;
use fyrkat\openssl\X509;
use fyrkat\openssl\Purpose;

use fyrkat\openssl\PrivateKey;

use PHPUnit\Framework\TestCase;

use fyrkat\openssl\OpenSSLConfig;

class CATest extends TestCase
{
	/** @var X509 */
	private $ca;

	public function setUp(): void
	{
		$this->modernConfig = OpenSSLConfig::caReq( OpenSSLConfig::COMPAT_MODERN );
		$this->key = new PrivateKey( $this->modernConfig );
		$csr = CSR::generate(
				new DN( ['CN' => 'unittest'] ),
				$this->key,
				$this->modernConfig
			);
		$this->ca = $csr->sign( null, $this->key, 1, $this->modernConfig );
		$this->caFile = \tempnam( \sys_get_temp_dir(), 'php_openssl_catest_ca_' );
		\file_put_contents( $this->caFile, $this->ca );
	}

	public function tearDown(): void
	{
		\unlink( $this->caFile );
	}

	public function testSign(): void
	{
		$modernConfig = OpenSSLConfig::serverReq( OpenSSLConfig::COMPAT_MODERN );
		$key = new PrivateKey( $this->modernConfig );
		$csr = CSR::generate(
				new DN( ['CN' => 'example.com'] ),
				$this->key,
				$this->modernConfig
			);
		$signed = $csr->sign( $this->ca, $this->key, 1, $modernConfig );
		$this->assertSame(
				$this->ca->getSubject()->getArray(),
				$signed->getIssuerSubject()->getArray()
			);
		$this->assertTrue( $signed->checkPurpose( Purpose::SSL_SERVER, [$this->caFile] ) );
		$this->assertFalse( $signed->checkPurpose( Purpose::SSL_CLIENT, [$this->caFile] ) );
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
}

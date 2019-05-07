<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

use DateTimeImmutable;

class X509Data
{
	/** @var array */
	private $x509data;

	/** @var bool */
	private $longNames;

	public function __construct( array $x509data, bool $longNames )
	{
		$this->x509data = $x509data;
		$this->longNames = $longNames;
	}

	public function getRawArray(): array
	{
		return $this->x509data;
	}

	public function hasLongNames(): bool
	{
		return $this->longNames;
	}

	public function getHash(): string
	{
		return $this->x509data['hash'];
	}

	public function getSerialNumber(): string
	{
		return $this->x509data['serialNumber'];
	}

	public function getSerialNumberHex(): string
	{
		return $this->x509data['serialNumberHex'];
	}

	public function getSubject(): DN
	{
		return new DN( $this->x509data['subject'] );
	}

	public function getIssuerSubject(): DN
	{
		return new DN( $this->x509data['issuer'] );
	}

	public function getName(): string
	{
		return $this->x509data['name'];
	}

	public function getVersion(): int
	{
		return $this->x509data['version'];
	}

	public function getValidFrom(): DateTimeImmutable
	{
		return new DateTimeImmutable( \sprintf( '@%d', $this->x509data['validFrom_time_t'] ) );
	}

	public function getValidTo(): DateTimeImmutable
	{
		return new DateTimeImmutable( \sprintf( '@%d', $this->x509data['validTo_time_t'] ) );
	}

	public function getSignatureType(): string
	{
		return $this->longNames
			? $this->x509data['signatureTypeLN']
			: $this->x509data['signatureTypeSN']
			;
	}

	public function getSignatureNID(): int
	{
		return $this->x509data['signatureTypeNID'];
	}

	public function getRawPurposes(): array
	{
		return $this->x509data['purposes'];
	}

	public function getRawExtensions(): array
	{
		return $this->x509data['extensions'];
	}
}

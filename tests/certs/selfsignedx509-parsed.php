<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

return
[
	'name' => '/CN=fyrkat\\x509 test',
	'subject' => ['CN' => 'fyrkat\\x509 test'],
	'hash' => 'a30f7f23',
	'issuer' => ['CN' => 'fyrkat\\x509 test'],
	'version' => 0,
	'serialNumber' => '17650764870988449858',
	'serialNumberHex' => 'F4F41D21E535C842',
	'validFrom' => '190101225147Z',
	'validTo' => '30180504225147Z',
	'validFrom_time_t' => 1546383107,
	'validTo_time_t' => 33082383107,
	'signatureTypeSN' => 'RSA-SHA256',
	'signatureTypeLN' => 'sha256WithRSAEncryption',
	'signatureTypeNID' => 668,
	'purposes' => [
		1 => [
			0 => true,
			1 => true,
			2 => 'sslclient',
		],
		2 => [
			0 => true,
			1 => true,
			2 => 'sslserver',
		],
		3 => [
			0 => true,
			1 => true,
			2 => 'nssslserver',
		],
		4 => [
			0 => true,
			1 => true,
			2 => 'smimesign',
		],
		5 => [
			0 => true,
			1 => true,
			2 => 'smimeencrypt',
		],
		6 => [
			0 => true,
			1 => true,
			2 => 'crlsign',
		],
		7 => [
			0 => true,
			1 => true,
			2 => 'any',
		],
		8 => [
			0 => true,
			1 => true,
			2 => 'ocsphelper',
		],
		9 => [
			0 => false,
			1 => true,
			2 => 'timestampsign',
		],
	],
	'extensions' => [],
];

<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

abstract class KeyType
{
	const RSA = \OPENSSL_KEYTYPE_RSA;

	const DSA = \OPENSSL_KEYTYPE_DSA;

	const DH = \OPENSSL_KEYTYPE_DH;

	const EC = \OPENSSL_KEYTYPE_EC;

	const UNKNOWN = -1;
}

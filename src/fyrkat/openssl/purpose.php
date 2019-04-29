<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

abstract class Purpose
{
	const SSL_CLIENT = \X509_PURPOSE_SSL_CLIENT;

	const SSL_SERVER = \X509_PURPOSE_SSL_SERVER;

	const NS_SSL_SERVER = \X509_PURPOSE_NS_SSL_SERVER;

	const SMIME_SIGN = \X509_PURPOSE_SMIME_SIGN;

	const SMIME_ENCRYPT = \X509_PURPOSE_SMIME_ENCRYPT;

	const CRL_SIGN = \X509_PURPOSE_CRL_SIGN;

	const ANY = \X509_PURPOSE_ANY;
}

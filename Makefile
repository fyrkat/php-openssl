x509:

camera-ready: syntax codestyle phpunit psalm phan

clean:
	rm -rf composer.phar php-cs-fixer-v2.phar phpDocumentor.phar psalm.phar vendor phpdoc dev

test: syntax phpunit

composer.phar:
	curl -sSLO https://getcomposer.org/composer.phar || wget https://getcomposer.org/composer.phar

php-cs-fixer-v2.phar:
	curl -sSLO https://cs.sensiolabs.org/download/php-cs-fixer-v2.phar || wget https://cs.sensiolabs.org/download/php-cs-fixer-v2.phar

phpDocumentor.phar:
	curl -sSLO http://phpdoc.org/phpDocumentor.phar || wget http://phpdoc.org/phpDocumentor.phar

psalm.phar:
	curl -sSLO https://github.com/vimeo/psalm/releases/download/3.2.10/psalm.phar || wget https://github.com/vimeo/psalm/releases/download/3.2.10/psalm.phar

phpunit-7.phar:
	curl -sSLO https://phar.phpunit.de/phpunit-7.phar || wget https://phar.phpunit.de/phpunit-7.phar

phan.phar:
	curl -sSLO https://github.com/phan/phan/releases/download/1.3.5/phan.phar || wget https://github.com/phan/phan/releases/download/1.3.5/phan.phar

vendor: composer.phar
	php composer.phar install

psalm: psalm.phar vendor
	php psalm.phar

phan: phan.phar
	php phan.phar --allow-polyfill-parser

codestyle: php-cs-fixer-v2.phar
	php php-cs-fixer-v2.phar fix

phpunit: phpunit-7.phar
	php phpunit-7.phar

syntax:
	find . ! -path './vendor/*' -name \*.php -print0 | xargs -0 -n1 php -l

.PHONY: camera-ready codestyle psalm phan phpunit phpcs clean syntax test

x509:

camera-ready: syntax codestyle psalm phpunit

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
	curl -sSLO https://github.com/vimeo/psalm/releases/download/2.0.8/psalm.phar || wget https://github.com/vimeo/psalm/releases/download/2.0.8/psalm.phar

phpunit-7.phar:
	curl -sSLO https://phar.phpunit.de/phpunit-7.phar || wget https://phar.phpunit.de/phpunit-7.phar

vendor: composer.phar
	php composer.phar install

psalm: psalm.phar vendor
	php psalm.phar

codestyle: php-cs-fixer-v2.phar
	php php-cs-fixer-v2.phar fix

phpunit: phpunit-7.phar
	php phpunit-7.phar

syntax:
	find . -name \*.php -print0 | xargs -0 -n1 php -l

.PHONY: camera-ready codestyle psalm phpunit phpcs clean syntax test

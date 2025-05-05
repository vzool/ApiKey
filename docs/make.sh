#!/bin/bash

rm -rf .phpdoc ./docs/api
./phpDocumentor.phar -v -f ApiKey.php -t ./docs/api

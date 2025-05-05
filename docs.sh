#!/bin/bash

rm -rf .phpdoc ./docs
./phpDocumentor.phar -v -f ApiKey.php -t ./docs

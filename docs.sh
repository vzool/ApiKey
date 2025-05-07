#!/bin/bash

rm -rf .phpdoc ./docs
./phpDocumentor.phar -v --title="ApiKey" -f ApiKey.php -t ./docs

#!/bin/bash

rm -rf .phpdoc ./docs
./phpDocumentor.phar -v --validate --sourcecode --title="ApiKey" -f ApiKey.php -t ./docs

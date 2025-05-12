#!/bin/bash

rm -rf .phpdoc ./docs

if [ ! -f phpDocumentor.phar ]; then
  echo "phpDocumentor.phar not found. Downloading..."
  curl -Lo phpDocumentor.phar https://phpdoc.org/phpDocumentor.phar
  if [ $? -eq 0 ]; then
    echo "phpDocumentor.phar downloaded successfully."
  else
    echo "Error downloading phpDocumentor.phar."
    exit 1
  fi
fi

echo "phpDocumentor.phar exists."

php phpDocumentor.phar -v --validate --sourcecode --title="ApiKey" -f ApiKey.php -t ./docs

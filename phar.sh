#!/bin/bash

rm -rf app
mkdir app
cp ApiKey.php app/
php --define phar.readonly=0 create-phar.php

## API Key Management Library (ApiKey)

<a href="https://github.com/vzool/ApiKey/actions/workflows/php.yml">
    <img src="https://github.com/vzool/ApiKey/actions/workflows/php.yml/badge.svg"/>
</a>

This library provides a simple and secure way to generate, store, and validate API keys. It supports storing keys in memory or in the file system.

## Core Class: `Key`

The `Key` class is the core of the library. It handles the generation, hashing, and validation of API keys.

### Features

* **Key Generation:** Generates a random, secure API key.
* **Hashing:** Hashes the public key using a provided `APP_KEY` and a strong hashing algorithm (default: `SHA3-384`).
* **Token Creation:** Creates a token by combining the public key and a hash of a private key.
* **Token Parsing:** Parses a token to extract the public and shared keys.
* **Validation:** Validates a token by comparing the provided shared key with a newly generated hash.
* **Customization:**
    * `label`:  A label for the API key.
    * `ip`: The IP address associated with the API key.
    * `APP_KEY`:  A secret key used for hashing.  **This is required and must be kept secret.**
    * `KEY_LENGTH`:  The length of the generated API key (default: 33 bytes).
    * `HASH_ALGO`:  The hashing algorithm to use (default: `sha3-384`).  See `hash_hmac_algos()` for supported algorithms.
* **Static Helper Functions:**
    * `hmac()`:  Computes the HMAC hash of a given `text` using the provided `APP_KEY` and hashing algorithm.
    * `parse()`:  Parses a token into its public and shared key components.
    * `create()`:  Reconstructs a `Key` object from stored data (hashed public key and data).
* **Testing:** Includes a `test()` method with comprehensive unit tests.

### Usage

```php
<?php

define('API_KEY_LIB', time());
require_once 'ApiKey.php';

// Generate a new API key.
$key = new Key(
    label: 'My Application Key',
    ip: '127.0.0.1',
    APP_KEY: 'your-secret-app-key', // Replace with your actual secret key
    KEY_LENGTH: 64, //example of setting key length
    HASH_ALGO: 'sha512' // Example of setting the hashing algorithm
);

$token = $key->token();  // Get the token
echo "Token: $token\n";
echo "Hashed Public Key: $key->hashed_public_key\n";

// Validate an API key (token).
$isValid = $key->valid($token);
if ($isValid) {
    echo "Token is valid.\n";
} else {
    echo "Token is invalid.\n";
}

//Reconstruct Key from known data.
$key2 = Key::create(
    hashed_public_key: $key->hashed_public_key,
    data: $key->data,
    APP_KEY: 'your-secret-app-key', // Use the same APP_KEY
    label: 'My Application Key',
    ip: '127.0.0.1',
    KEY_LENGTH: 64,
    HASH_ALGO: 'sha512'
);

$isValid2 = $key2->valid($token); //You can validate the token with the reconstructed key
if ($isValid2) {
    echo "Token is valid.\n";
} else {
    echo "Token is invalid.\n";
}
?>
```

### Storage Implementations
The library provides two implementations for storing API keys:

#### 1. ApiKeyMemory
Stores API keys in a static memory array. This is suitable for short-lived processes or testing, but not recommended for production due to its non-persistent nature.

##### Features

- `save()`: Saves the hashed public key and associated data to a static array.
- `load()`: Loads data associated with a hashed public key from the static array.
- `make()`: Generates a new API key and stores it in memory. Returns the token.
- `check()`: Checks the validity of a token by retrieving the key from memory.
- `test()`: Includes a test() method with unit tests.

##### Usage

```php
<?php
define('API_KEY_LIB', time());
require_once 'ApiKey.php';

define('APP_KEY', 'your-secret-app-key'); // Define APP_KEY

// Generate and store a key in memory.
$token = ApiKeyMemory::make(label: 'My Memory Key', ip: '192.168.1.100');
echo "Token: $token\n";

// Validate a token from memory.
$isValid = ApiKeyMemory::check($token);
if ($isValid) {
    echo "Token is valid (from memory).\n";
} else {
    echo "Token is invalid (from memory).\n";
}
?>
```

#### 2. ApiKeyFS

Stores API keys in the file system. This provides persistence across requests and is suitable for production use. Keys are stored in individual files, with the hashed public key used as the filename.

##### Features

- `path()`: Generates the file path for storing a key, creating the directory if it doesn't exist. The path can be customized using the `API_KEY_PATH` constant.
- `save()`: Saves the key data to a file.
- `load()`: Loads key data from a file.
- `make()`: Generates a new API key and stores it in the file system. Returns the token.
- `check()`: Checks the validity of a token by retrieving the key from the file system.
- `test()`: Includes a `test()` method with unit tests.

##### Usage

```php
<?php
define('API_KEY_LIB', time());
require_once 'ApiKey.php';

define('API_KEY_PATH', 'tmp/path/to/your/storage'); // Define where to store the keys.  Make sure this directory is writable.
define('APP_KEY', 'your-secret-app-key');  //Define APP_KEY

// Generate and store a key in the file system.
$token = ApiKeyFS::make(label: 'My File System Key', ip: '192.168.1.101');
echo "Token: $token\n";

// Validate a token from the file system.
$isValid = ApiKeyFS::check($token);
if ($isValid) {
    echo "Token is valid (from file system).\n";
} else {
    echo "Token is invalid (from file system).\n";
}
?>
```

### Installation

1. Ensure you have PHP 8.0+ or later.
2. Copy the `ApiKey.php` file to your project.
3. Include the file in your PHP script:
```php
<?php
define('API_KEY_LIB', time());
require_once 'ApiKey.php';
?>
```

### Testing

```shell
php ApiKey.php
```

OR

```php
<?php require_once 'ApiKey.php'; ?>
```

### Security Considerations

- **`APP_KEY` is Critical**: The `APP_KEY` is used to hash the API keys. It must be kept secret. Do not expose it in your code or configuration files. Use environment variables or a secure configuration management system.
- **Storage**: Choose the appropriate storage mechanism for your needs. `ApiKeyMemory` is only suitable for testing. For production, use `ApiKeyFS` or implement your own storage class (e.g., to store keys in a database) by extending the `ApiKeyMemory` or `ApiKeyFS` class and overriding the `save()` and `load()` methods.
- **File System Permissions**: If using `ApiKeyFS`, ensure that the directory specified by `API_KEY_PATH` is not publicly accessible and is writable by the PHP process.
- **Hashing Algorithm**: The default hashing algorithm (`sha3-384`) is strong, but you can choose a different algorithm if needed. Use `hash_hmac_algos()` to get a list of supported algorithms.
- **Key Length**: The default key length (33 bytes) is secure, but you can adjust it using the `KEY_LENGTH` parameter. Longer keys are more secure but also take up more storage space.
- **Token Transmission**: Transmit tokens securely (e.g., over HTTPS) to prevent them from being intercepted.
- **Error Handling**: The code uses assert statements and throws exceptions. In a production environment, you should replace these with proper error logging and handling.
- **Testing**: The code includes `test()` methods. It is highly recommended to run these tests to ensure that the library is working correctly in your environment.

### Extending the Library
You can extend the library to support other storage mechanisms by creating a new class that extends the Key class and overrides the `save()` and `load()` methods. For example, you could create an `ApiKeyDatabase` class to store keys in a database.

### Debugging

The `Key` class, and the `ApiKeyMemory` and `ApiKeyFS` classes have a static `$debug` property. When set to true, the classes will output additional information to help with debugging.

```php
<?php
Key::$debug = true; # core
ApiKeyMemory::$debug = true; # memory storage
ApiKeyFS::$debug = true; # filesystem storage
```

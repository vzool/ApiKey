<img alt="logo" width="256px" src="images/logo_600.jpg" />

## API Key Management Library (ApiKey)

<a href="https://github.com/vzool/ApiKey/actions/workflows/php.yml">
    <img src="https://github.com/vzool/ApiKey/actions/workflows/php.yml/badge.svg"/>
</a>

This library offers a simple and secure solution for API key management. It generates, stores, and validates keys in a way that prevents leakage and impersonation by avoiding a direct link between tokens and stored data. It supports storing keys in memory or in the file system.

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
    * `ttl`: The Time-to-live (in seconds) associated with the API key. (default: 0) means no expiration.
    * `APP_KEY`: A secret key used for hashing.  **This is required and must be kept secret.**
    * `KEY_LENGTH`: The length of the generated API key (default: 33 bytes).
    * `HASH_ALGO`: The hashing algorithm to use (default: `sha3-384`).  See `hash_hmac_algos()` for supported algorithms.
* **Static Helper Functions:**
    * `hmac()`: Computes the HMAC hash of a given `text` using the provided `APP_KEY` and hashing algorithm.
    * `parse()`: Parses a token into its public and shared key components.
    * `create()`: Reconstructs a `Key` object from stored data (hashed public key and data).
* **Testing:** Includes a `test()` method with comprehensive unit tests.

### Installation

```bash
composer require vzool/api-key
```

```php
<?php
require_once 'vendor/autoload.php';
?>
```

**Manual Installation**

1. Ensure you have PHP 8.0+ or later.
2. Copy the `ApiKey.php` file to your project.
3. Include the file in your PHP script:
```php
<?php
define('API_KEY_LIB', time());
require_once 'ApiKey.php';
?>
```

### Usage

```php
<?php

define('API_KEY_LIB', time()); # not needed when installed by composer
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
- `test()`: Includes a `test()` method with unit tests.

##### Usage

```php
<?php
define('API_KEY_LIB', time());
require_once 'ApiKey.php';

define('APP_KEY', 'your-secret-app-key'); // Define APP_KEY

// Generate and store a key in memory.
$key = ApiKeyMemory::make(label: 'My Memory Key', ip: '192.168.1.100');
$token = $key->token();
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
$key = ApiKeyFS::make(label: 'My File System Key', ip: '192.168.1.101');
$token = $key->token();
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

#### 3. ApiKeyDatabase

Stores API keys in a database using PDO (PHP Data Objects). This allows for API keys to be stored and retrieved across multiple application instances or requests. It leverages any PDO databases for storage and automatically creates the necessary table schema if it doesn't exist.

**Features:**

* **Database Persistence:** Stores API keys in a database.
* **Automatic Schema Creation:** Creates the `api_keys` table if it's not already present.
* **Integration with PDO:** Requires a PDO instance for database interaction.
* **Extends `ApiKeyMemory`:** Inherits the core API key generation and validation logic.
* **Supports Key Attributes:** Stores hashed public key, creation timestamp, optional IP address restriction, label, time-to-live (TTL), and associated data.

**Usage:**

1.  **Initialize the PDO instance:**

    Before using any of the database functionalities, you need to set up a PDO connection. For a SQLite database in a file, you would do something like this:

    ```php
    try {
        ApiKeyDatabase::$pdo = new PDO('sqlite:./api_keys.db');
        ApiKeyDatabase::$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (PDOException $e) {
        die("Failed to connect to the database: " . $e->getMessage());
    }
    ```

    For an in-memory SQLite database (useful for testing or temporary storage):

    ```php
    try {
        ApiKeyDatabase::$pdo = new PDO('sqlite::memory:');
        ApiKeyDatabase::$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (PDOException $e) {
        die("Failed to connect to the database: " . $e->getMessage());
    }
    ```

2.  **Use the API key generation and validation methods:**

    The `ApiKeyDatabase` class inherits the `make()` and `check()` methods from `ApiKeyMemory`. These methods will now automatically save new keys to the database and load existing keys from the database for validation.

    ```php
    <?php
    define('API_KEY_LIB', time());
    require_once 'ApiKey.php';

    try {
        ApiKeyDatabase::$pdo = new PDO('sqlite::memory:'); // or 'sqlite:./api_keys.db'
        ApiKeyDatabase::$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (PDOException $e) {
        die("Failed to connect to the database: " . $e->getMessage());
    }

    define('APP_KEY', 'your-secret-app-key'); // Define APP_KEY
    
    // Generate a new API key with optional parameters
    $apiKey = ApiKeyDatabase::make(
        label: 'My Application Key',
        ip: '192.168.1.100',
        ttl: 1, // Time-to-live in seconds
    );

    if ($apiKey) {
        $token = $apiKey->token();
        echo "Generated API Token: " . $token . "\n";

        // Check if a token is valid
        if (ApiKeyDatabase::check($token)) {
            echo "Token is valid.\n";
        } else {
            echo "Token is invalid.\n";
        }

        // Check if a token is valid for a specific IP address
        if (ApiKeyDatabase::check($token, ip: '192.168.1.100')) {
            echo "Token is valid for IP 192.168.1.100.\n";
        } else {
            echo "Token is not valid for IP 192.168.1.100.\n";
        }

        // Check if a token is valid for a different IP address
        if (ApiKeyDatabase::check($token, ip: '192.168.1.101')) {
            echo "Token is valid for IP 192.168.1.101.\n";
        } else {
            echo "Token is not valid for IP 192.168.1.101.\n";
        }

        // Wait for the TTL to expire (if set)
        sleep(2);

        // Check if the token is still valid after TTL
        if (ApiKeyDatabase::check($token)) {
            echo "Token is still valid after TTL (this should not happen if TTL was set correctly).\n";
        } else {
            echo "Token is invalid after TTL.\n";
        }
    } else {
        echo "Failed to generate API key.\n";
    }
    ?>
    ```

3.  **Database Table:**

    The `ApiKeyDatabase` class will automatically create a table named `api_keys` (by default) with the following schema:

    | Column             | Type             | Nullable | Unique | Primary Key | Auto Increment | Description                                     |
    | ------------------ | ---------------- | -------- | ------ | ----------- | -------------- | ----------------------------------------------- |
    | `id`               | INTEGER          | No       |        | Yes         | Yes            | Unique identifier for the API key record.       |
    | `hashed_public_key`| VARCHAR(255)     | No       | Yes    | No          | No             | Unique, hashed representation of the public key. |
    | `created`          | INTEGER          | No       |        | No          | No             | Unix timestamp of when the key was created.     |
    | `ip`               | VARCHAR(255)     | Yes      |        | No          | No             | Optional IP address restriction.                |
    | `label`            | VARCHAR(255)     | No       |        | No          | No             | Optional label for the API key.                 |
    | `ttl`              | INTEGER          | No       |        | No          | No             | Optional time-to-live in seconds.              |
    | `data`             | TEXT             | No       |        | No          | No             | Optional packed data associated with the key.|

    You can change the table name by modifying the static `$tableName` property:

    ```php
    ApiKeyDatabase::$tableName = 'my_api_keys';
    ```

**Internal Methods (Not for Direct Use):**

* `protected static ?PDO $pdo = NULL`: PDO instance for database interaction.
* `protected static string $tableName = 'api_keys'`: The name of the database table.
* `protected static function schema()`: Defines and creates the database schema if it doesn't exist.
* `protected static function save(Key $key) : bool`: Saves a new API key to the database.
* `protected static function load(string $hashed_public_key, int $created)`: Loads an API key from the database.


### Testing

```shell
php ApiKey.php test
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
You can extend the library to support other storage mechanisms by creating a new class that extends the `Key`, `ApiKeyMemory`, `ApiKeyFS` or `ApiKeyDatabase` class and overrides the `save()` and `load()` methods if applicable. For example, you could create an `ApiKeyMongoDB` class to store keys in a NoSQL database.

### Debugging

The `Key` class, and the `ApiKeyMemory` and `ApiKeyFS` classes have a static `$debug` property. When set to `true`, the classes will output additional information to help with debugging.

```php
<?php
Key::$debug = true; # core
ApiKeyMemory::$debug = true; # memory storage
ApiKeyFS::$debug = true; # filesystem storage
```

## CLI Class

This PHP class provides a command-line interface for generating and checking API keys using `ApiKeyFS`.

## Commands

* **`generate`**: Generate a new API key and store it.
* **`check`**: Check the validity of an API key.
* **`test`**: Run the internal tests.
* **`help`**: Display this help message.

## Options

| Option                     | Description                                               | Required for `generate` | Required for `check` | Default Value |
| :------------------------- | :-------------------------------------------------------- | :--------------------: | :-------------------: | :------------: |
| `--app-key=<app-key>`      | Application key.                                        |          Yes           |          Yes          |       -       |
| `--path=<api-keys-path>`   | API Keys storage path.                                  |          Yes           |          Yes          |       -       |
| `--label=<label>`          | Label for the API key.                                  |          Yes           |           No          |       -       |
| `--ip=<ip>`                | IP address of the client.                               |           No           |           No          |      ''       |
| `--token=<token>`          | The API key token to check.                             |           No           |          Yes          |       -       |
| `--key-length=<key-length>`| The size of key building block.                         |           No           |           No          |       33      |
| `--algo=<algo>`            | The algorithm used for HMAC hashing. See `hash_hmac_algos()` for supported algorithms. |           No           |           No          |   `sha3-384`  |
| `--verbose`                | Print verbose messages.   

### Examples

#### Generating an API Key

To generate a new API key with a label, application key, and storage path:

```bash
php ApiKey.php generate --app-key=your-app-identifier --path=/path/to/store/keys --label=my-service
```

You can also specify an IP address for the key:

```bash
php ApiKey.php generate --app-key=your-app-identifier --path=/path/to/store/keys --label=user-123 --ip=192.168.1.100
```

To customize the key length and hashing algorithm:

```bash
php ApiKey.php generate --app-key=your-app-identifier --path=/path/to/store/keys --label=admin-key --key-length=64 --algo=sha512
```

Use the `--verbose` flag for more output:

```bash
php ApiKey.php generate --app-key=your-app-identifier --path=/path/to/store/keys --label=debug-key --verbose
```

### Checking an API Key

To check the validity of an API key token:

```bash
php ApiKey.php check --app-key=your-app-identifier --path=/path/to/store/keys --token=the-api-key-token-here
```

You can also specify a custom key length and algorithm if the key was generated with different settings:

```bash
php ApiKey.php check --app-key=your-app-identifier --path=/path/to/store/keys --token=the-api-key-token-here --key-length=64 --algo=sha512
```

### Running Tests

To run the internal tests:

```bash
php ApiKey.php test
```

For verbose test output:

```bash
php ApiKey.php test --verbose
```

### Getting Help

To display the help message:

```bash
php ApiKey.php help
```

#!/usr/bin/env php
<?php declare(strict_types=1);

namespace vzool\ApiKey;

/**
 * @license MIT
 * @author Abdelaziz Elarashed Elshaikh Mohamed
 * @copyright 2025
 * @package ApiKey
 * @link https://github.com/vzool/ApiKey
 */

/**
 * API Key Version: This constant defines the current version of the API key structure and format.
 * It can be used for version control and to handle potential changes in future updates.
 *
 * @since 0.0.1
 */
define('API_KEY_VERSION', '0.0.1');

/**
 * Default API Key Length: This constant specifies the default length (in characters) of newly generated API keys.
 * It provides a standard length for security and consistency.
 *
 * @since 0.0.1
 */
define('API_KEY_DEFAULT_LENGTH', 33);

/**
 * Default API Key Hashing Algorithm: This constant defines the default hashing algorithm used when generating API keys.
 * It specifies the cryptographic hash function employed for security purposes.
 *
 * @since 0.0.1
 */
define('API_KEY_DEFAULT_ALGO', 'sha3-384');

/**
 * Class base64: Provides static methods for encoding and decoding strings using a URL-safe
 * variant of Base64. This encoding scheme replaces the standard Base64
 * characters '+' and '/' with '-' and '_', respectively, and removes
 * any trailing '=' padding characters. This makes the encoded strings
 * suitable for use in URLs and filenames without requiring further encoding.
 *
 * @since 0.0.1
 */
class base64
{
    /**
     * Converts a plain text string to its URL-safe Base64 representation.
     *
     * This method first performs standard Base64 encoding on the input string
     * and then replaces any '+' characters with '-', '/' characters with '_',
     * and removes any trailing '=' padding.
     *
     * @param string $plainText The plain text string to convert.
     * @return string The URL-safe Base64 representation of the input string.
     *
     * @example
     * ```php
     * $text = "Hello World!";
     * $urlSafeBase64 = base64::encode($text); // Output: SGVsbG8gV29ybGQh
     *
     * $textWithSpecial = "String with + and /=";
     * $urlSafeBase64Special = base64::encode($textWithSpecial); // Output: U3RyaW5nIHdpdGggLSBhbmQgXw
     * ```
     *
     * @since 0.0.1
     */
    public static function encode(string $plainText) : string
    {
        $base64 = base64_encode($plainText);
        return str_replace(['+', '/', '='], ['-', '_', ''], $base64);
    }

    /**
     * Converts a URL-safe Base64 string back to its original plain text.
     *
     * This method reverses the URL-safe modifications by replacing '-' with '+'
     * and '_' with '/'. It also adds back any necessary '=' padding characters
     * before performing standard Base64 decoding.
     *
     * @param string $base64Url The URL-safe Base64 string to convert.
     * @return string The original plain text representation.
     *
     * @example
     * ```php
     * $urlSafe = "SGVsbG8gV29ybGQh";
     * $originalText = base64::decode($urlSafe); // Output: Hello World!
     *
     * $urlSafeSpecial = "U3RyaW5nIHdpdGggLSBhbmQgXw";
     * $originalTextSpecial = base64::decode($urlSafeSpecial); // Output: String with + and /=
     * ```
     *
     * @since 0.0.1
     */
    public static function decode(string $base64Url) : string
    {
        $base64 = str_replace(['-', '_'], ['+', '/'], $base64Url);
        // Add padding if necessary
        $remainder = strlen($base64) % 4;
        if ($remainder) {
            $base64 .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode($base64);
    }

    /**
     * Tests the URL-safe Base64 encoding and decoding methods.
     *
     * This method performs a series of tests with various input strings,
     * including those with special characters and different padding scenarios,
     * to ensure that the `encode()` and `decode()` methods function correctly.
     * It uses PHP's `assert()` function to verify the expected outcomes.
     *
     * @param bool $debug Optional. If set to `true`, detailed debug information
     * will be displayed for each test case, including the encoded string,
     * the decoded string, and whether the decoded string matches the
     * original. Defaults to `false`.
     * @return void
     *
     * @example
     * ```php
     * base64::test(); // Runs the tests. No output on success, errors on failure.
     * base64::test(true); // Runs the tests with detailed debug output.
     * ```
     *
     * @since 0.0.1
     */
    public static function test(bool $debug = false)
    {
        $testStrings = [
            '',
            'A',
            'Hello',
            'World!',
            '12345',
            '~!@#$%^&*()_+=-`',
            'السلام عليكم ورحمة الله تعالى وبركاته', // Arabic characters
            '你好，世界', // Chinese characters
            '你好 👋 世界🌍', // Chinese characters with emojis
            'This string has + and /',
            'Ends with one =',
            'Ends with two ==',
        ];

        foreach($testStrings as $originalText) {
            $encoded = self::encode($originalText);
            $decoded = self::decode($encoded);
            $match = $decoded === $originalText;
            if($debug){
                var_dump([
                    $encoded,
                    $decoded,
                    $match,
                ]);
            }
            assert($match);
        }
    }
}

/**
 * Class XoRx: Provides simple XOR-based encryption and decryption functionalities.
 *
 * This class offers static methods for encrypting and decrypting strings using a provided key.
 * It employs a bitwise XOR operation and extends the key if it's shorter than the plaintext
 * by repeatedly hashing it.
 * 
 * REF https://www.codecauldron.dev/2021/02/12/simple-xor-encryption-in-php/
 *
 * @since 0.0.1
 */
class XoRx
{
    /**
     * Enables or disables debugging output within the encryption and decryption processes.
     *
     * When set to `true`, detailed information about each step of the encryption and
     * decryption will be echoed to the output. Defaults to `false`.
     *
     * @var bool
     *
     * @since 0.0.1
     */
    public static bool $debug = false;

    /**
     * Generates an encryption key that is at least as long as the plaintext.
     *
     * If the provided key is shorter than the plaintext, this function repeatedly hashes
     * the key using the specified algorithm until its length is sufficient.
     *
     * @param string $plainText The plaintext whose length determines the minimum key length.
     * @param string $key       The initial encryption key.
     * @param string $algo      The hashing algorithm to use for key extension (default: API_KEY_DEFAULT_ALGO).
     * @return string The generated key, guaranteed to be at least as long as the plaintext.
     *
     * @since 0.0.1
     */
    public static function key(string $plainText, string $key, string $algo = API_KEY_DEFAULT_ALGO) : string
    {
        $data_length = strlen($plainText);
        $key_length = strlen($key);
        if($key_length < $data_length){
            $count = 0;
            do{
                $key .= hash($algo, $key);
                $data_length = strlen($plainText);
                $key_length = strlen($key);
                $count = ($data_length - $key_length) / $data_length;
            }while($count > 0);
        }
        return $key;
    }

    /**
     * Encrypts a given plaintext string using a provided key.
     *
     * This function iterates through each character of the plaintext. For each character,
     * it performs a bitwise XOR operation with the corresponding character in the key.
     * The key is repeated cyclically if it is shorter than the plaintext. The resulting
     * character is then converted to its hexadecimal representation.
     *
     * @param string $plainText The string to be encrypted.
     * @param string $key       The encryption key.
     * @param string $algo      The hashing algorithm used to extend the key (default: API_KEY_DEFAULT_ALGO).
     * @return string The encrypted string in lowercase hexadecimal format.
     *
     * @since 0.0.1
     */
    public static function encrypt(string $plainText, string $key, string $algo = API_KEY_DEFAULT_ALGO) : string
    {
        if(self::$debug) echo('[encrypt]' . PHP_EOL);
        $output = "";
        $keyPos = 0;
        $length = strlen($plainText);
        $key = self::key($key, $algo);
        for ($p = 0; $p < $length; $p++) {
            if ($keyPos > strlen($key) - 1) {
                $keyPos = 0;
            }
            if(self::$debug)
                echo(json_encode([$p => $plainText[$p], $keyPos => $key[$keyPos]]));
            $char = $plainText[$p] ^ $key[$keyPos];
            $bin = str_pad(decbin(ord($char)), 8, "0", STR_PAD_LEFT);

            $hex1 = dechex(bindec($bin));
            $hex2 = str_pad($hex1, 2, "0", STR_PAD_LEFT);
            if(self::$debug)
                echo(json_encode([$bin, $hex1, $hex2]) . PHP_EOL);
            $output .= $hex2;
            $keyPos++;
        }
        return $output;
    }

    /**
     * Decrypts a hexadecimal encrypted string using the corresponding key.
     *
     * This function takes a hexadecimal encrypted string. It iterates through the string,
     * taking two characters at a time to convert them back to their ASCII representation.
     * It then performs a bitwise XOR operation with the corresponding character in the key
     * (which must be the same key used for encryption). The key is repeated cyclically if
     * it is shorter than the decrypted text.
     *
     * @param string $encryptedText The hexadecimal encrypted string.
     * @param string $key           The decryption key (must match the encryption key).
     * @param string $algo      The hashing algorithm used to extend the key during encryption (default: API_KEY_DEFAULT_ALGO).
     * @return string The original decrypted plaintext string.
     *
     * @since 0.0.1
     */
    public static function decrypt(string $encryptedText, string $key, string $algo = API_KEY_DEFAULT_ALGO) : string
    {
        if(self::$debug) echo('[decrypt]' . PHP_EOL);
        $hex_arr = explode(" ", trim(chunk_split($encryptedText, 2, " ")));
        $output = "";
        $keyPos = 0;
        $length = sizeof($hex_arr);
        $key = self::key($key, $algo);
        for ($p = 0; $p < $length; $p++) {
            if ($keyPos > strlen($key) - 1) {
                $keyPos = 0;
            }
            if(self::$debug)
                echo(json_encode([$p => $hex_arr[$p], $keyPos => $key[$keyPos]]) . PHP_EOL);
            $char = chr(hexdec($hex_arr[$p])) ^ $key[$keyPos];

            $output .= $char;
            $keyPos++;
        }
        return $output;
    }

    /**
     * Performs basic self-tests to verify the encryption and decryption functionality.
     *
     * This method encrypts and then decrypts sample text strings using simple keys.
     * It uses assertions to check if the encryption produces a non-empty and different
     * string from the original, and if the decryption successfully recovers the original text.
     * Optionally, it can output debugging information during the tests.
     *
     * @param bool $debug Enables or disables debugging output for the tests (default: false).
     * @return void
     *
     * @since 0.0.1
     */
    public static function test(bool $debug = false)
    {
        // self::$debug = $debug;

        foreach([
            "Salam World!!!",
            str_repeat('x', 1000),
            uniqid('', true),
        ] as $text){
            $key = strval(strlen($text));
            $encrypted = self::encrypt($text, $key);
            $decrypted = self::decrypt($encrypted, $key);
            if($debug) var_dump([
                'key1' => $key,
                'key2' => self::key($text, $key),
                'encrypted' => $encrypted,
                'decrypted' => $decrypted,
                'assert1' => ! empty($encrypted),
                'assert2' => $text !== $encrypted,
                'assert3' => $text === $decrypted,
            ]);
            assert( ! empty($encrypted));
            assert($text !== $encrypted);
            assert($text === $decrypted);
        }
    }
}

/**
 * Class Key: Represents a cryptographic key with associated metadata and functionality
 * for generating, validating, and parsing tokens.
 *
 * @since 0.0.1
 */
class Key
{
    /**
     * The public key associated with this Key object.
     *
     * @var string
     *
     * @since 0.0.1
     */
    public string $public_key;

    /**
     * A static flag to enable or disable debug output.
     * Defaults to false.
     *
     * @var bool
     *
     * @since 0.0.1
     */
    public static bool $debug = false;

    /**
     * Key constructor.
     *
     * Initializes a new Key object. If `$hashed_public_key` or `$data` are not provided,
     * it generates a new public key, a corresponding hashed public key, and associated data.
     *
     * @param string $label A label for this key.
     * @param string $ip The IP address associated with this key.
     * @param string $APP_KEY The application-specific secret key used for hashing. This is required.
     * @param int $KEY_LENGTH The length of the generated random keys in bytes. Defaults to API_KEY_DEFAULT_LENGTH.
     * @param string $HASH_ALGO The hashing algorithm to use for HMAC. Defaults to API_KEY_DEFAULT_ALGO.
     * Must be a supported algorithm by `hash_hmac_algos()`.
     * @param string $hashed_public_key An optional pre-computed hashed public key.
     * @param string $data Optional pre-existing data associated with the key.
     * @param int $created Optional pre-existing creation timestamp. If not provided.
     * @param int $ttl The time-to-live (in seconds) for this key. After this duration, the key is considered expired. A value of 0 indicates that the key never expires. Defaults to 0.
     * @throws Exception If `$APP_KEY` is empty or if the `$HASH_ALGO` is not supported.
     *
     * @since 0.0.1
     */
    public function __construct(
        public string $label,
        public string $ip,
        private string $APP_KEY,
        private int $KEY_LENGTH = API_KEY_DEFAULT_LENGTH,
        private string $HASH_ALGO = API_KEY_DEFAULT_ALGO,
        public string $hashed_public_key = '',
        public string $data = '',
        public int $created = 0,
        public int $ttl = 0,
    ) {
        if( ! $APP_KEY) throw new \Exception('APP_KEY is required.');
        if( ! in_array($HASH_ALGO, hash_hmac_algos()))
            throw new \Exception('Unsupported hash algorithm(' . $HASH_ALGO . ')');

        if($hashed_public_key || $data || $created) return;

        $this->public_key = $this->random_key();
        $private_key = $this->random_key() . $this->random_key();
        $this->hashed_public_key = self::hmac(
            text: $this->public_key,
            APP_KEY: $this->APP_KEY,
            HASH_ALGO: $this->HASH_ALGO,
        );
        $time = time();
        $this->created = $time;
        $payload = json_encode([$label, $ip, $time, $ttl]);
        $length = strlen($payload);
        $encrypted_payload = XoRx::encrypt($payload, $private_key);
        $terminator = hash(
            algo: $HASH_ALGO,
            data: $private_key,
            binary: false,
        );
        $data = bin2hex(random_bytes(random_int(1, $this->KEY_LENGTH)))
            . $this->hashed_public_key
            . $private_key
            . $length
            . $terminator
            . $encrypted_payload
            . bin2hex(random_bytes(random_int(1, $this->KEY_LENGTH)))
            ;
        $this->data($data);
        if(self::$debug){
            echo('[KEY]' . PHP_EOL);
            var_dump([
                'hashed_public_key' => $this->hashed_public_key,
                'private_key' => $private_key,
                'length' => $length,
                'terminator' => $terminator,
                'encrypted_payload' => $encrypted_payload,
                'data_hex' => $data,
                'data_base64' => $this->data,
                'time' => $time,
                'time_hex' => dechex($time),
            ]);
        }
    }

    /**
     * Manages the internal data of the object, allowing retrieval in hexadecimal format
     * or setting it from a hexadecimal string.
     *
     * When called without any arguments, this method decodes the internal base64
     * encoded data and returns its hexadecimal representation.
     *
     * When called with a hexadecimal string as an argument, it encodes this string
     * into base64 and updates the internal data of the object. In this case,
     * the method returns an empty string.
     *
     * @param string $data_hex Optional. A hexadecimal string to set as the internal data.
     * Defaults to an empty string, in which case the current
     * data is returned in hexadecimal format.
     * @return string The hexadecimal representation of the internal data if no
     * argument is provided. An empty string if a hexadecimal string
     * is provided as an argument.
     *
     * @since 0.0.1
     */
    private function data(string $data_hex = '') : string
    {
        if(empty($data_hex)) return bin2hex(base64::decode($this->data));
        $this->data = base64::encode(hex2bin($data_hex));
        return '';
    }

    /**
     * Constructs a file path based on a given timestamp and an optional filename.
     *
     * This static method generates a directory structure using the year, month, and day
     * extracted from the provided timestamp. The resulting path can optionally
     * include a filename at the end.
     *
     * @param int $created A timestamp representing the creation date. This timestamp
     * is expected to be an integer with a length of 8 digits
     * (YYYYMMDD format). An assertion will fail if this condition
     * is not met.
     * @param string $file An optional filename to append to the generated directory path.
     * Defaults to an empty string.
     * @return string The generated file path, with directory separators appropriate
     * for the operating system. The path will be in the format:
     * `YYYY/MM/DD[/filename]`.
     * @throws \AssertionError If the `$created` timestamp is not a non-zero integer
     * or if its string representation does not have a
     * length of 8 characters.
     *
     * @since 0.0.1
     */
    public static function file(int $created, string $file = '') : string
    {
        $date = getdate($created);
        return implode(DIRECTORY_SEPARATOR, [
            $date['year'],
            $date['mon'],
            $date['mday'],
        ])
        . DIRECTORY_SEPARATOR
        . $file
        ;
    }

    /**
     * Generates the specific file path for this instance's data storage.
     *
     * This method leverages the `file()` static method to create a structured file path.
     * The path is determined by the instance's creation timestamp and a unique
     * identifier derived from its hashed public key. This strategy ensures a
     * well-organized and distributed storage system.
     *
     * @return string The generated file path. The path is composed of subdirectories
     * representing the year, month, and day of creation, followed by
     * the instance's hashed public key as the filename. The directory
     * separators are platform-specific.
     *
     * @throws \AssertionError If the `hashed_public_key` property of this instance
     * is not yet set (i.e., is falsy).
     *
     * @since 0.0.1
     */
    public function file_path() : string
    {
        assert($this->hashed_public_key);
        return self::file(
            created: $this->created,
            file: $this->hashed_public_key,
        );
    }

    /**
     * Generates a random key of the specified length.
     *
     * @return string A hexadecimal representation of the random key.
     *
     * @since 0.0.1
     */
    private function random_key() : string
    {
        return bin2hex(random_bytes($this->KEY_LENGTH));
    }

    /**
     * Extracts the private key from the `$data` property.
     *
     * This function assumes that the `$data` property has a specific structure:
     * random bytes (1 to KEY_LENGTH) + hashed public key + private key + random bytes (1 to KEY_LENGTH).
     * It extracts the private key based on the position of the `$hashed_public_key`.
     *
     * @return array The extracted private key with IP.
     * @throws AssertionFailedError If the length of `$this->data` is less than four times `$this->KEY_LENGTH` in non-debug mode.
     *
     * @since 0.0.1
     */
    private function private_key()
    {
        $stored_data = $this->data();
        if(static::$debug){
            echo('[private_key]' . PHP_EOL);
            var_dump([
                'assert' => [
                    'strlen' => strlen($stored_data),
                    'KEY_LENGTH * 4' => $this->KEY_LENGTH * 4,
                    'result' => strlen($stored_data) >= $this->KEY_LENGTH * 4,
                ],
            ]);
        }
        assert(strlen($stored_data) >= $this->KEY_LENGTH * 4);
        $data = explode($this->hashed_public_key, $stored_data);
        $private_key = substr($data[1], 0, $this->KEY_LENGTH * 4);
        if(static::$debug){
            var_dump([
                'substr' => [
                    $data[1],
                    0,
                    $this->KEY_LENGTH * 2,
                ],
                'result' => $private_key,
            ]);
        }
        $terminator = hash(
            algo: $this->HASH_ALGO,
            data: $private_key,
            binary: false,
        );
        $terminal = explode($terminator, $stored_data);
        if(static::$debug){
            echo("terminator($terminator)" . PHP_EOL);
            var_dump($terminal);
        }
        $y = explode($private_key, $terminal[0]);
        $length = $y[1];
        if(static::$debug){
            var_dump([
                'length' => $length,
            ]);
        }
        $encrypted_payload = substr($terminal[1], 0, intval($length) * 2);
        if(static::$debug){
            var_dump([
                'encrypted_payload' => $encrypted_payload,
            ]);
        }
        $payload_json = XoRx::decrypt($encrypted_payload, $private_key);
        if(static::$debug){
            var_dump([
                'payload_json' => $payload_json,
            ]);
        }
        $payload = json_decode($payload_json, associative: true);
        return [
            $private_key,
            $payload,
        ];
    }

    /**
     * Computes the HMAC (Hash-based Message Authentication Code) of a given text.
     *
     * @param string $text The input string to hash.
     * @param string $APP_KEY The secret key to use for the HMAC.
     * @param string $HASH_ALGO The hashing algorithm to use. Defaults to API_KEY_DEFAULT_ALGO.
     * @return string The hexadecimal representation of the HMAC.
     *
     * @since 0.0.1
     */
    public static function hmac(
        string $text,
        string $APP_KEY,
        string $HASH_ALGO = API_KEY_DEFAULT_ALGO,
    ) : string
    {
        if(self::$debug){
            echo('hmac[get_defined_vars]: ' . PHP_EOL);
            var_dump(get_defined_vars());
        }
        return hash_hmac(
            algo: $HASH_ALGO,
            data: $text,
            key: $APP_KEY,
            binary: false,
        );
    }

    /**
     * Generates a token by concatenating the public key and the HMAC of the private key.
     *
     * @return string The generated token.
     * @throws AssertionFailedError If `$this->public_key` is empty in non-debug mode.
     *
     * @since 0.0.1
     */
    public function token() : string
    {
        assert( ! empty($this->created));
        assert( ! empty($this->public_key));
        list($private_key, $payload) = $this->private_key();
        $token = $this->public_key
                . self::hmac(
                    text: $private_key,
                    APP_KEY: $this->APP_KEY,
                    HASH_ALGO: $this->HASH_ALGO,
                )
                . XoRx::encrypt(
                    plainText: dechex($this->created),
                    key: hash(
                        $this->HASH_ALGO,
                        $this->APP_KEY . $this->public_key,
                    ),
                    algo: $this->HASH_ALGO,
                )
                ;
        return base64::encode(hex2bin($token));
    }

    /**
     * Parses a token to extract the public key and the shared key (HMAC of the private key).
     *
     * @param string $token The token to parse.
     * @param int $KEY_LENGTH The expected length of the public key in bytes. Defaults to API_KEY_DEFAULT_LENGTH.
     * @param string $HASH_ALGO The hashing algorithm that was used to generate the HMAC. Defaults to API_KEY_DEFAULT_ALGO.
     * @return array An array containing the public key (at index 0) and the shared key (at index 1),
     * or an empty array if the token format is invalid or the hash algorithm is unsupported.
     * @throws Exception If the `$HASH_ALGO` is not supported.
     *
     * @since 0.0.1
     */
    public static function parse(
        string $token,
        int $KEY_LENGTH = API_KEY_DEFAULT_LENGTH,
        string $HASH_ALGO = API_KEY_DEFAULT_ALGO,
    ) : array
    {
        if( ! in_array($HASH_ALGO, hash_hmac_algos()))
            throw new \Exception('Unsupported hash algorithm(' . $HASH_ALGO . ')');

        $public_key_length = $KEY_LENGTH * 2;
        $shared_key_length = strlen(hash($HASH_ALGO, ''));
        $random_time = dechex(time());
        $encrypted_time = XoRx::encrypt(
            plainText: $random_time,
            key: bin2hex(random_bytes(strlen($random_time))),
            algo: $HASH_ALGO,
        );
        $time_length = strlen($encrypted_time);

        $token = bin2hex(base64::decode($token));
        $expected_length = $public_key_length + $shared_key_length + $time_length;
        if(static::$debug){
            echo('[parse]' . PHP_EOL);
            var_dump([
                'public_key_length' => $public_key_length,
                'shared_key_length' => $shared_key_length,
                'time_length' => $time_length,
                'expected_length' => $expected_length,
                'encrypted_time' => $encrypted_time,
                'token' => $token,
            ]);
        }

        if(strlen($token) !== $expected_length)
            return [];

        $public_key = substr($token, 0, $public_key_length);
        $shared_key = substr($token, $public_key_length, $shared_key_length);
        $encrypted_time = substr($token, $public_key_length + $shared_key_length, $time_length);

        if(static::$debug){
            echo('[public_key]' . PHP_EOL);
            var_dump([
                'substr' => [
                    $token,
                    0,
                    $public_key_length,
                ],
                'result' => $public_key,
            ]);
            echo('[shared_key]' . PHP_EOL);
            var_dump([
                'substr' => [
                    $token,
                    $public_key_length,
                    $shared_key_length,
                ],
                'result' => $shared_key,
            ]);
            echo('[encrypted_time]' . PHP_EOL);
            var_dump([
                'substr' => [
                    $token,
                    $public_key_length + $shared_key_length,
                    $time_length,
                ],
                'result' => $encrypted_time,
            ]);
        }

        return [
            $public_key,
            $shared_key,
            $encrypted_time,
        ];
    }

    /**
     * Validates a given token against the current Key object's private key and application key.
     * 
     * @param string $ip The IP address associated with this key. Defaults to an empty string.
     *
     * @param string $token The token to validate.
     * @return bool True if the token is valid, false otherwise.
     *
     * @since 0.0.1
     */
    public function valid(string $token, string $ip = '') : bool
    {
        $parsed = self::parse(
            token: $token,
            KEY_LENGTH: $this->KEY_LENGTH,
            HASH_ALGO: $this->HASH_ALGO,
        );

        if( ! $parsed) return false;

        list($public_key, $shared_key, $encrypted_time) = $parsed;
        list($private_key, $payload) = $this->private_key();
        list($label, $stored_ip, $created, $ttl) = $payload;

        $decrypted_time = XoRx::decrypt(
            $encrypted_time,
            key: hash(
                $this->HASH_ALGO,
                $this->APP_KEY . $public_key,
            ),
            algo: $this->HASH_ALGO,
        );
        $time = hexdec($decrypted_time);
        if(self::$debug){
            var_dump([
                'encrypted_time' => $encrypted_time,
                'decrypted_time' => $decrypted_time,
                'time' => $time,
            ]);
        }
        $this->created = $time;
        $hash = self::hmac(
            text: $private_key,
            APP_KEY: $this->APP_KEY,
            HASH_ALGO: $this->HASH_ALGO,
        );
        $valid_token = hash_equals(
            known_string: $hash,
            user_string: $shared_key,
        );

        $valid_ip = ( ! empty($ip) && ! empty($stored_ip)) ? $ip === $stored_ip : true;
        $expired = ($ttl === 0) ? false : ($created + $ttl) < time();

        if(static::$debug){
            echo('[valid]' . PHP_EOL);
            var_dump([
                'hash' => $hash,
                'shared_key' => $shared_key,
                'valid_token' => $valid_token,
                'valid_ip' => $valid_ip,
                'expired' => $expired,
            ]);
        }
        return $valid_token && $valid_ip && !$expired;
    }

    /**
     * Returns an associative array representing the Key object's label, IP address, and data.
     *
     * @return array An associative array with keys 'label', 'ip', and 'data'.
     *
     * @since 0.0.1
     */
    public function dict()
    {
        return [
            'label' => $this->label,
            'ip' => $this->ip,
            'ttl' => $this->ttl,
            'data' => $this->data,
        ];
    }

    /**
     * Analyzes a token and provides its anatomy in relation to a given Key object.
     *
     * @param string $token The token to analyze.
     * @param Key $key The Key object to compare against.
     * @return array An associative array containing the token, extracted public key, shared key,
     * the Key object's public key and hashed public key, the Key object's data,
     * and a boolean indicating if the token is valid for the given Key object.
     *
     * @since 0.0.1
     */
    public static function anatomy(string $token, Key $key)
    {
        $parsed = Key::parse(token: $token);
        
        list($public_key, $shared_key, $time) = $parsed ?? [NULL, NULL, NULL];

        return [
            'token' => $token,
            'token_hex' => bin2hex(base64::decode($token)),
            'time' => $time,
            'public_key[0]' => $key->public_key,
            'public_key[1]' => $public_key,
            'shared_key' => $shared_key,
            'hashed_public_key' => $key->hashed_public_key,
            'data_hex' => $key->data(),
            'data_base64' => $key->data,
            'valid' => $key->valid($token),
        ];
    }

    /**
     * Creates a new Key object with pre-defined hashed public key and data.
     *
     * This static method is useful for reconstructing a Key object from stored data.
     *
     * @param string $hashed_public_key The pre-computed hashed public key.
     * @param string $data The pre-existing data associated with the key.
     * @param string $APP_KEY The application-specific secret key used for hashing.
     * @param string $label An optional label for this key. Defaults to an empty string.
     * @param string $ip The IP address associated with this key. Defaults to an empty string.
     * @param int $ttl The time-to-live (in seconds) for this key. After this duration, the key is considered expired. A value of 0 indicates that the key never expires. Defaults to 0.
     * @param int $created Optional pre-existing creation timestamp. If not provided.
     * @param int $KEY_LENGTH The length of the original random keys in bytes. Defaults to API_KEY_DEFAULT_LENGTH.
     * @param string $HASH_ALGO The hashing algorithm used for HMAC. Defaults to API_KEY_DEFAULT_ALGO.
     * @return self A new Key object initialized with the provided data.
     *
     * @since 0.0.1
     */
    public static function create(
        string $hashed_public_key,
        string $data,
        string $APP_KEY,
        string $label = '',
        string $ip = '',
        int $ttl = 0,
        int $created = 0,
        int $KEY_LENGTH = API_KEY_DEFAULT_LENGTH,
        string $HASH_ALGO = API_KEY_DEFAULT_ALGO,
    ) : self
    {
        return new self(
            label: $label,
            ip: $ip,
            ttl: $ttl,
            APP_KEY: $APP_KEY,
            KEY_LENGTH: $KEY_LENGTH,
            HASH_ALGO: $HASH_ALGO,
            hashed_public_key: $hashed_public_key,
            data: $data,
            created: $created,
        );
    }

    /**
     * Performs a series of tests to verify the functionality of the Key class.
     *
     * @param bool $debug If true, enables verbose output during the tests. Defaults to false.
     * @return void
     *
     * @since 0.0.1
     */
    public static function test(bool $debug = false)
    {
       $failed = false;
       try{
            new self('x', '127.0.0.1', '');
        }catch(\Exception $ex) { $failed = true; }
        assert($failed);
        $APP_KEY = '1bd4145f-30cd-46f2-aa7e-598039a34850';
        for($KEY_LENGTH = 1; $KEY_LENGTH < 34; $KEY_LENGTH++){
            foreach(hash_hmac_algos() as $algo){
                if($debug) echo("###### ALGO($algo) - KEY_LENGTH($KEY_LENGTH) ######" . PHP_EOL);
                $key = new self(
                    'x',
                    '127.0.0.1',
                    APP_KEY: $APP_KEY,
                    KEY_LENGTH: $KEY_LENGTH,
                    HASH_ALGO: $algo,
                );
                assert( ! empty($key));
                if($debug) var_dump($key);
                $token = $key->token();
                if($debug) var_dump($token);
                assert( ! empty($token));
                assert($key->valid($token));
                assert( ! $key->valid($token . base64::encode('x')));
                assert( ! $key->valid('x'));
                assert( ! $key->valid(''));
                $key->file_path();
                $key2 = Key::create(
                    hashed_public_key: $key->hashed_public_key,
                    data: $key->data,
                    APP_KEY: $APP_KEY,
                    KEY_LENGTH: $KEY_LENGTH,
                    HASH_ALGO: $algo,
                    created: $key->created,
                );
                $key2->file_path();
                if($debug) var_dump($key2);
                assert( ! empty($key2));
                $failed = false;
                try{
                    //$key2->token();
                }catch(\Exception $ex) { $failed = true; }
                //assert($failed);
                assert($key2->valid($token));
                assert($key2->valid($token, '127.0.0.1'));
                assert( ! $key2->valid($token, '127.0.0.2'));
                assert( ! $key2->valid($token . base64::encode('y')));
                assert( ! $key2->valid('y'));
                assert( ! $key2->valid(''));
                assert( ! empty($token));
            }
        }
    }
}

/**
 * Class ApiKeyMemory: Extends the Key class to provide an in-memory storage mechanism for API keys.
 * This class is primarily intended for development or testing environments
 * where persistent storage is not required.
 *
 * @since 0.0.1
 */
class ApiKeyMemory extends Key
{
    /**
     * @var array $memory
     * A static array that holds the API keys in memory.
     * The keys of this array are the hashed public keys, and the values
     * are arrays representing the key data.
     *
     * @since 0.0.1
     */
    private static $memory = [];

    /**
     * Saves a Key object's data into the in-memory storage.
     *
     * @param Key $key The Key object to save.
     * @return bool Returns true if the key was successfully saved.
     *
     * @since 0.0.1
     */
    protected static function save(Key $key) : bool
    {
        assert($key->hashed_public_key);
        self::$memory[$key->hashed_public_key] = $key->dict();
        return true;
    }

    /**
     * Loads a key's data from the in-memory storage based on its hashed public key.
     *
     * @param string $hashed_public_key The hashed version of the public key to look up.
     * @param int $created pre-existing creation timestamp. If not provided.
     * @return array|null Returns an array containing the key's data if found, otherwise NULL.
     *
     * @since 0.0.1
     */
    protected static function load(string $hashed_public_key, int $created)
    {
        return self::$memory[$hashed_public_key] ?? NULL;
    }

    /**
     * Generates a new API key, saves it in memory, and returns the token.
     *
     * @param string $label A descriptive label for the API key.
     * @param string $ip The IP address associated with this key (optional, defaults to '').
     * @param int $ttl The time-to-live (in seconds) for this key. After this duration, the key is considered expired. A value of 0 indicates that the key never expires. Defaults to 0.
     * @param string $APP_KEY The application-specific secret key used for signing (defaults to the global APP_KEY constant).
     * @param int $KEY_LENGTH The desired length of the public and private keys (defaults to API_KEY_DEFAULT_LENGTH).
     * @param string $HASH_ALGO The hashing algorithm to use (defaults to API_KEY_DEFAULT_ALGO).
     * @return Key The generated API token object.
     *
     * @since 0.0.1
     */
    public static function make(
        string $label,
        string $ip = '',
        int $ttl = 0,
        string $APP_KEY = APP_KEY,
        int $KEY_LENGTH = API_KEY_DEFAULT_LENGTH,
        string $HASH_ALGO = API_KEY_DEFAULT_ALGO,
    ) : Key
    {
        if(self::$debug){
            echo('=================================================' . PHP_EOL);
            echo("MAKE(token)" . PHP_EOL);
        }
        $key = new self(
            label: $label . '@' . date('Y-m-d H:i:s'),
            ip: $ip,
            ttl: $ttl,
            APP_KEY: $APP_KEY,
            KEY_LENGTH: $KEY_LENGTH,
            HASH_ALGO: $HASH_ALGO,
        );
        assert(static::save($key));
        if(self::$debug){
            echo('=================================================' . PHP_EOL);
            echo("SAVE hashed_public_key: ({$key->hashed_public_key})" . PHP_EOL);
            echo("- public_key: ({$key->public_key})" . PHP_EOL);
            echo('------------------------- [DATA] ------------------------' . PHP_EOL);
            var_dump($key->data);
            echo('------------------------- [MEMORY] ------------------------' . PHP_EOL);
            var_dump(self::$memory);
            echo('-------------------------------------------------' . PHP_EOL);
        }
        return $key;
    }

    /**
     * Checks if a given API token is valid by retrieving the corresponding key from memory.
     *
     * @param string $token The API token to check.
     * @param string $ip The IP address associated with this key (optional, defaults to '').
     * @param string $APP_KEY The application-specific secret key used for signing (defaults to the global APP_KEY constant).
     * @param int $KEY_LENGTH The expected length of the public and private keys (defaults to API_KEY_DEFAULT_LENGTH).
     * @param string $HASH_ALGO The hashing algorithm used (defaults to API_KEY_DEFAULT_ALGO).
     * @return bool Returns true if the token is valid, false otherwise.
     *
     * @since 0.0.1
     */
    public static function check(
        string $token,
        string $ip = '',
        string $APP_KEY = APP_KEY,
        int $KEY_LENGTH = API_KEY_DEFAULT_LENGTH,
        string $HASH_ALGO = API_KEY_DEFAULT_ALGO,
    ) : bool
    {
        if(self::$debug){
            echo('=================================================' . PHP_EOL);
            echo("CHECK(token: $token)" . PHP_EOL);
        }
        $parsed = self::parse(
            token: $token,
            KEY_LENGTH: $KEY_LENGTH,
            HASH_ALGO: $HASH_ALGO,
        );

        if( ! $parsed) return false;

        list($public_key, $shared_key, $encrypted_time) = $parsed;

        $decrypted_time = XoRx::decrypt(
            $encrypted_time,
            key: hash(
                $HASH_ALGO,
                $APP_KEY . $public_key,
            ),
            algo: $HASH_ALGO,
        );
        $time = hexdec($decrypted_time);

        $hashed_public_key = self::hmac(
            text: $public_key,
            APP_KEY: $APP_KEY,
            HASH_ALGO: $HASH_ALGO,
        );
        $key_dict = static::load($hashed_public_key, created: $time);
        $data = $key_dict['data'];
        if(self::$debug){
            echo('=================================================' . PHP_EOL);
            echo("LOAD hashed_public_key: ($hashed_public_key)" . PHP_EOL);
            echo("LOAD token: ($token)" . PHP_EOL);
            echo("LOAD public_key: ($public_key)" . PHP_EOL);
            echo("LOAD shared_key: ($shared_key)" . PHP_EOL);
            echo('------------------------- [DATA] ------------------------' . PHP_EOL);
            var_dump($data);
            echo('------------------------- [MEMORY] ------------------------' . PHP_EOL);
            var_dump(self::$memory);
            echo('-------------------------------------------------' . PHP_EOL);
        }
        assert( ! empty($data));
        $key = self::create(
            label: $key_dict['label'],
            ip: $key_dict['ip'],
            ttl: $key_dict['ttl'],
            hashed_public_key: $hashed_public_key,
            data: $data,
            APP_KEY: $APP_KEY,
            KEY_LENGTH: $KEY_LENGTH,
            HASH_ALGO: $HASH_ALGO,
        );

        if( ! $key) return false;
        return $key->valid($token, $ip);
    }

    /**
     * A static method for basic testing of the ApiKeyMemory class.
     *
     * @param bool $debug Enables or disables debug output (defaults to false).
     * @return void
     *
     * @since 0.0.1
     */
    public static function test(bool $debug = false)
    {
        $APP_KEY = '65162b0b-784d-4e15-88b4-459d5caadf3f';
        self::$debug = $debug;
        $key = self::make(
            label: 'x',
            APP_KEY: $APP_KEY,
            ip: '127.0.0.1',
            ttl: 1,
        );
        assert( ! empty($key));
        $token = $key->token();
        assert( ! empty($token));
        assert(self::check($token, APP_KEY: $APP_KEY));
        assert(self::check($token, APP_KEY: $APP_KEY, ip: '127.0.0.1'));
        assert( ! self::check($token, APP_KEY: $APP_KEY, ip: '127.0.0.2'));
        assert( ! self::check('', APP_KEY: $APP_KEY));
        assert( ! self::check('123', APP_KEY: $APP_KEY));
        sleep(2);
        assert( ! self::check($token, APP_KEY: $APP_KEY, ip: '127.0.0.1'));
        assert( ! self::check($token, APP_KEY: $APP_KEY, ip: '127.0.0.2'));
    }
}

/**
 * Class ApiKeyAPCu: Extends ApiKeyMemory to provide API key storage and retrieval using the APCu cache.
 *
 * APCu (Alternative PHP Cache User Cache) is an in-memory key-value store for PHP.
 * This class leverages APCu to efficiently store and retrieve API key data, offering
 * potentially faster performance compared to storing keys solely in memory within
 * a single request lifecycle.
 *
 * @since 0.0.1
 */
class ApiKeyAPCu extends ApiKeyMemory
{
    /**
     * Saves a Key object to the APCu cache.
     *
     * The key for storage in APCu is the hashed public key of the API key.
     * The value stored is an associative array representing the key's attributes.
     *
     * @param Key $key The Key object to save.
     * @return bool True on successful storage, false otherwise.
     */
    protected static function save(Key $key) : bool
    {
        return \apcu_add(
            $key->hashed_public_key,
            $key->dict(),
        );
    }

    /**
     * Loads API key data from the APCu cache based on the hashed public key and creation timestamp.
     *
     * This method checks if a key exists in the APCu cache using the provided
     * hashed public key. If it exists, the associated data is fetched and returned.
     * If the key does not exist, NULL is returned. The `$created` timestamp is included
     * in the method signature for potential future use or consistency with other
     * storage mechanisms, although it is not directly used in this APCu implementation.
     *
     * @param string $hashed_public_key The hashed public key of the API key to load.
     * @param int $created The creation timestamp of the API key (not directly used in this implementation).
     * @return array|null An associative array representing the API key data if found, NULL otherwise.
     */
    protected static function load(string $hashed_public_key, int $created)
    {
        return \apcu_fetch($hashed_public_key) ?: NULL;
    }

    /**
     * Performs a basic test of the API key functionality using APCu for storage.
     *
     * This method is designed to verify that the API key generation, storage (via APCu),
     * and validation mechanisms are working correctly. It defines a constant for the
     * application key (which would typically be defined elsewhere in a real application),
     * optionally enables debugging output, creates a new API key with specific parameters,
     * and then performs a series of assertions to validate different aspects of the key.
     * These assertions include checking if a key and its token are generated, if the
     * key is valid with the correct token and IP address, if it's invalid with a wrong
     * IP address or an empty/invalid token, and if the time-to-live (TTL) mechanism
     * is working as expected.
     *
     * **Note:** This test relies on the APCu extension being enabled and configured
     * in your PHP environment.
     *
     * @param bool $debug Optional. If true, enables debugging output using `self::debug()`. Defaults to false.
     * @return void
     *
     * @since 0.0.1
     */
    public static function test(bool $debug = false)
    {
        /**
         * @ignore
         */
        define('APP_KEY', '55CD1C6B-4104-4C89-AE9F-5E867A75DB67');
        self::$debug = $debug;
        $key = self::make(
            label: 'x',
            ip: '127.0.0.1',
            ttl: 1,
        );
        assert( ! empty($key));
        $token = $key->token();
        assert( ! empty($token));
        assert(self::check($token));
        assert(self::check($token, ip: '127.0.0.1'));
        assert( ! self::check($token, ip: '127.0.0.2'));
        assert( ! self::check(''));
        assert( ! self::check('123'));
        sleep(2);
        assert( ! self::check($token, ip: '127.0.0.1'));
        assert( ! self::check($token, ip: '127.0.0.2'));
    }
}

/**
 * Class ApiKeyMemcached: Extends the ApiKeyMemory class to store and retrieve API keys using Memcached.
 *
 * This class leverages Memcached for persistent storage of API key data,
 * offering potential performance benefits over in-memory storage, especially
 * in distributed environments or for longer-lived API keys. It inherits
 * the core API key generation and validation logic from ApiKeyMemory
 * and overrides the storage mechanisms to interact with a Memcached instance.
 *
 * @since 0.0.1
 */
class ApiKeyMemcached extends ApiKeyMemory
{
    /**The Memcached instance used for storing and retrieving API keys.
     *
     * This static property holds the connection to the Memcached server.
     * It needs to be initialized elsewhere in the application before
     * the methods of this class are used.
     *
     * @var \Memcached|null
     *
     * @since 0.0.1
     */
    public static ?\Memcached $memcached = NULL;

    /**
     * Saves a Key object to Memcached.
     *
     * This protected static method takes a Key object and stores its
     * dictionary representation in Memcached using the hashed public key
     * as the key.
     *
     * @param Key $key The Key object to save.
     * @return bool True on success, false on failure.
     *
     * @since 0.0.1
     */
    protected static function save(Key $key) : bool
    {
        return self::$memcached->set(
            $key->hashed_public_key,
            $key->dict(),
        );
    }

    /**
     * Loads API key data from Memcached based on the hashed public key.
     *
     * This protected static method retrieves data associated with the given
     * hashed public key from Memcached. If the key is not found, it returns null.
     * The `$created` timestamp is included for potential future use or compatibility
     * with the parent class's signature, though it's not directly used in this
     * Memcached implementation.
     *
     * @param string $hashed_public_key The hashed public key of the API key to load.
     * @param int $created The creation timestamp of the API key (not directly used in this method).
     * @return array|null The API key data as an associative array, or null if not found.
     *
     * @since 0.0.1
     */
    protected static function load(string $hashed_public_key, int $created)
    {
        return self::$memcached->get($hashed_public_key) ?: NULL;
    }

    /**
     * Performs a basic test of the API key functionality using Memcached.
     *
     * This method defines necessary constants, initializes a Memcached connection,
     * creates API keys, and performs assertions to verify the key generation,
     * token generation, and validation processes when using Memcached for storage.
     * It also tests time-based expiry of the API keys.
     *
     * @param bool $debug Optional. If true, enables debugging output. Defaults to false.
     * @return void
     *
     * @since 0.0.1
     */
    public static function test(bool $debug = false)
    {
        if( ! defined('APP_KEY')){
            /**
             * @ignore
             */
            define('APP_KEY', '0d02e727-d820-4e75-a500-3bb44fd42163');
        }
        self::$debug = $debug;
        self::$memcached = new \Memcached(
            persistent_id: 'test_pool',
        );
        self::$memcached->addServer('127.0.0.1', 11211);
        $key = self::make(
            label: 'x',
            ip: '127.0.0.1',
            ttl: 1,
        );
        assert( ! empty($key));
        $token = $key->token();
        assert( ! empty($token));
        assert(self::check($token));
        assert(self::check($token, ip: '127.0.0.1'));
        assert( ! self::check($token, ip: '127.0.0.2'));
        assert( ! self::check(''));
        assert( ! self::check('123'));
        sleep(2);
        assert( ! self::check($token, ip: '127.0.0.1'));
        assert( ! self::check($token, ip: '127.0.0.2'));
    }
}

/**
 * Class ApiKeyFS: Manages API keys, extending the in-memory storage with file system persistence.
 *
 * This class provides methods for saving, loading, and managing API keys,
 * storing them as JSON files within a designated directory. It inherits
 * functionality from `ApiKeyMemory`.
 *
 * @since 0.0.1
 */
class ApiKeyFS extends ApiKeyMemory
{
    /**
     * Constructs the full path to the API key file.
     *
     * It checks if a constant `API_KEY_PATH` is defined; if so, it uses that
     * as the base directory. Otherwise, it defaults to a `.tmp/api_keys` directory
     * relative to the current working directory. It ensures the directory exists
     * by creating it recursively if necessary.
     *
     * @param string $file The name of the file (which will be the hashed public key).
     * @return string The full path to the API key file.
     *
     * @since 0.0.1
     */
    protected static function path(string $file) : string
    {
        $path = defined('API_KEY_PATH') ? API_KEY_PATH : '.tmp';
        $path .= DIRECTORY_SEPARATOR . 'api_keys' . DIRECTORY_SEPARATOR;
        $file_path = dirname($file);
        if($file_path !== '.') $path .= $file_path;
        @mkdir($path, permissions: 0700, recursive: true);
        $path = str_replace(
            search: str_repeat(DIRECTORY_SEPARATOR, 2),
            replace: DIRECTORY_SEPARATOR,
            subject: $path,
        );
        return $path . DIRECTORY_SEPARATOR . basename($file);
    }

    /**
     * Saves an API key to the file system.
     *
     * The key's data (represented as an associative array from the `dict()` method
     * of the `Key` object) is encoded as JSON and written to a file named after
     * the hashed public key.
     *
     * @param Key $key The `Key` object to be saved.
     * @return bool True if the key was saved successfully, false otherwise.
     *
     * @since 0.0.1
     */
    protected static function save(Key $key) : bool
    {
        $path = static::path($key->file_path());
        assert( ! file_exists($path), $path);
        return file_put_contents(
            $path,
            json_encode($key->dict()),
        ) !== false;
    }

    /**
     * Loads an API key from the file system.
     *
     * Reads the JSON data from the file corresponding to the hashed public key
     * and decodes it into an associative array.
     *
     * @param string $hashed_public_key The hashed public key used to determine the filename.
     * @param int $created pre-existing creation timestamp. If not provided.
     * @return array|null An associative array representing the API key data, or null if the file is empty or does not exist.
     *
     * @since 0.0.1
     */
    protected static function load(string $hashed_public_key, int $created)
    {
        $path = self::path(self::file($created, $hashed_public_key));
        $data = file_get_contents($path);
        return empty($data) ? NULL : json_decode($data, associative: true);
    }

    /**
     * Performs a basic test of the API key functionality.
     *
     * This method defines constants for the API key path and application key,
     * enables debugging if requested, creates a new API key, and then performs
     * basic assertions to check if the key generation and validation work as expected.
     *
     * @param bool $debug Optional. If true, enables debugging output. Defaults to false.
     * @return void
     *
     * @since 0.0.1
     */
    public static function test(bool $debug = false)
    {
        /**
         * @ignore
         */
        define('API_KEY_PATH', 'tmp');
        if( ! defined('APP_KEY')){
            /**
             * @ignore
             */
            define('APP_KEY', '94473B99-23CB-4A4D-A315-C0F9B8C9B39A');
        }
        self::$debug = $debug;
        $key = self::make(
            label: 'x',
            ip: '127.0.0.1',
            ttl: 1,
        );
        assert( ! empty($key));
        $token = $key->token();
        assert( ! empty($token));
        assert(self::check($token));
        assert(self::check($token, ip: '127.0.0.1'));
        assert( ! self::check($token, ip: '127.0.0.2'));
        assert( ! self::check(''));
        assert( ! self::check('123'));
        sleep(2);
        assert( ! self::check($token, ip: '127.0.0.1'));
        assert( ! self::check($token, ip: '127.0.0.2'));
    }
}

/**
 * class ApiKeyDatabase: Manages API keys, extending the in-memory storage with database persistence using `PDO`.
 *
 * This class provides functionality to create, save, and load API keys from a database.
 * It can utilizes any `PDO` database for storage and requires a `PDO` instance to be available.
 * The database schema is automatically created if it doesn't exist.
 * 
 * @since 0.0.1
 */
class ApiKeyDatabase extends ApiKeyMemory
{/**
     * @var ?PDO PDO instance for database interaction.
     * 
     * @since 0.0.1
     */
    public static ?\PDO $pdo = NULL;

    /**
     * @var string The name of the database table used to store API keys. Defaults to 'api_keys'.
     * 
     * @since 0.0.1
     */
    public static string $tableName = 'api_keys';

    /**
     * Defines the database schema for the API key table.
     *
     * This method creates the `api_keys` table if it doesn't already exist.
     * The table includes columns for the unique hashed public key, creation timestamp,
     * optional IP address restriction, an optional label, an optional time-to-live (TTL),
     * and an optional data field.
     *
     * @return void
     * @throws AssertionError If the PDO instance is not initialized.
     * @internal This method is for internal use and should not be called directly.
     * 
     * @since 0.0.1
     */
    protected static function schema()
    {
        assert(!empty(static::$pdo));
        $sql = "CREATE TABLE IF NOT EXISTS " . static::$tableName . " (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hashed_public_key VARCHAR(255) UNIQUE NOT NULL,
            created INTEGER NOT NULL,
            ip VARCHAR(255) NULL,
            label VARCHAR(255) NOT NULL,
            ttl INTEGER NOT NULL,
            data TEXT NOT NULL
        )";
        static::$pdo->exec($sql);
    }

    /**
     * Saves a new API key to the database.
     *
     * This method inserts the provided API key details into the database table.
     * It automatically calls the {@see schema()} method to ensure the table exists.
     *
     * @param Key $key The API key object to be saved.
     * @return bool True on successful insertion, false otherwise.
     * @throws AssertionError If the PDO instance is not initialized.
     * @internal This method is for internal use and should not be called directly.
     * 
     * @since 0.0.1
     */
    protected static function save(Key $key) : bool
    {
        static::schema();
        $stmt = static::$pdo->prepare("INSERT INTO " . static::$tableName . " (
            hashed_public_key
            , created
            , ip
            , label
            , ttl
            , data
        ) VALUES (
            :hashed_public_key
            , :created
            , :ip
            , :label
            , :ttl
            , :data
        )");

        return $stmt->execute([
            ':hashed_public_key' => $key->hashed_public_key,
            ':created' => $key->created,
            ':ip' => $key->ip,
            ':label' => $key->label,
            ':ttl' => $key->ttl,
            ':data' => $key->data,
        ]);
    }

     /**
     * Loads an API key from the database based on its hashed public key.
     *
     * This method retrieves a single API key record from the database that matches
     * the provided hashed public key. It automatically calls the {@see schema()}
     * method to ensure the table exists.
     *
     * @param string $hashed_public_key The hashed public key of the API key to load.
     * @param int $created The creation timestamp of the API key. While included in the
     * original signature, this parameter is not currently used in the
     * query and might be considered for removal or inclusion in future
     * versions for more specific lookups.
     * @return array|null An associative array containing the API key data if found,
     * otherwise null.
     * @throws AssertionError If the PDO instance is not initialized.
     * @internal This method is for internal use and should not be called directly.
     * 
     * @since 0.0.1
     */
    protected static function load(string $hashed_public_key, int $created)
    {
        static::schema();
        $stmt = static::$pdo->prepare(
            " SELECT * FROM " . static::$tableName .
            " WHERE hashed_public_key = :hashed_public_key",
        );
        $stmt->execute([
            ':hashed_public_key' => $hashed_public_key,
        ]);
        return $stmt->fetch(\PDO::FETCH_ASSOC) ?: NULL;
    }

    /**
     * Performs a basic test of the API key functionality.
     *
     * This method defines constants for the API key path and application key,
     * enables debugging if requested, creates a new API key, and then performs
     * basic assertions to check if the key generation and validation work as expected.
     *
     * @param bool $debug Optional. If true, enables debugging output. Defaults to false.
     * @return void
     *
     * @since 0.0.1
     */
    public static function test(bool $debug = false)
    {
        if ($debug) {
            error_reporting(E_ALL);
            ini_set('display_errors', 1);
            echo "Debugging enabled.\n";
        }

        // Initialize PDO connection for testing
        try {
            static::$pdo = new \PDO('sqlite::memory:');
            static::$pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
            if(static::$debug) echo "Connected to in-memory SQLite database.\n";
        } catch (\PDOException $e) {
            die("Failed to connect to the database: " . $e->getMessage());
        }

        if( ! defined('APP_KEY')){
            /**
             * @ignore
             */
            define('APP_KEY', '484d3668-e681-4b7a-a751-468d7dfe9178');
        }
        self::$debug = $debug;
        $key = self::make(
            label: 'x',
            ip: '127.0.0.1',
            ttl: 1,
        );
        assert( ! empty($key));
        $token = $key->token();
        assert( ! empty($token));
        assert(self::check($token));
        assert(self::check($token, ip: '127.0.0.1'));
        assert( ! self::check($token, ip: '127.0.0.2'));
        assert( ! self::check(''));
        assert( ! self::check('123'));
        sleep(2);
        assert( ! self::check($token, ip: '127.0.0.1'));
        assert( ! self::check($token, ip: '127.0.0.2'));
    }
}

/**
 * Class CLI: Provides a command-line interface for generating and checking API keys.
 *
 * This class offers static methods to handle command-line arguments,
 * display help information, and execute specific actions such as
 * generating new API keys, checking the validity of existing keys,
 * and running internal tests. It relies on the `ApiKeyFS` class for
 * the underlying API key storage and validation logic.
 *
 * @since 0.0.1
 */
class CLI
{
    /**
     * @var array $options An associative array to store parsed command-line options.
     * The keys of the array are the option names (without the '--' prefix),
     * and the values are the corresponding option values. Boolean flags
     * will have a value of `true`.
     *
     * @since 0.0.1
     */
    public static $options = [];

    /**
     * Displays the help message for the CLI tool.
     *
     * This function outputs the usage instructions, version information, available
     * commands, and supported options to the console. It also provides examples
     * of how to use the tool.
     *
     * @global array $argv The global array containing command-line arguments.
     *
     * @return void
     *
     * @since 0.0.1
     */
    public static function display_help()
    {
        global $argv;
        echo("
                 _ _  __          
     /\         (_) |/ /          
    /  \   _ __  _| ' / ___ _   _ 
   / /\ \ | '_ \| |  < / _ \ | | |
  / ____ \| |_) | | . \  __/ |_| |
 /_/    \_\ .__/|_|_|\_\___|\__, |
          | |                __/ |
          |_|               |___/ v" . API_KEY_VERSION . PHP_EOL);
        echo("Usage:\n{$argv[0]} <command> [options]\n");
        echo("\n");
        echo("Commands:\n");
        echo("  generate  Generate a new API key and store it.\n");
        echo("  check     Check the validity of an API key.\n");
        echo("  test      Run the tests.\n");
        echo("  version   Show library version.\n");
        echo("  help      Display this help message.\n");
        echo("\n");
        echo("Options:\n");
        echo("  --app-key=<app-key>         Application key (always required).\n");
        echo("  --path=<api-keys-path>      API Keys storage path (always required).\n");
        echo("  --label=<label>             Label for the API key (required for generate).\n");
        echo("  --ip=<ip>                   IP address of the client (optional for generate).\n");
        echo("  --ttl=<ttl>                 The time-to-live default 0 means no expiration (optional for generate).\n");
        echo("  --token=<token>             The API key token to check (required for check).\n");
        echo("  --key-length=<key-length>   The size of key building block (optional: default API_KEY_DEFAULT_LENGTH).\n");
        echo("  --algo=<algo>               The algorithm used for hmac hashing (optional: default sha3-384). See `hash_hmac_algos()` for supported algorithms.\n");
        echo("  --verbose                   Print verbose messages (optional: false).\n");
        echo("\n");
        echo("Example:\n");
        echo("  php {$argv[0]} generate --app-key=abc-def-ghi --path=tmp --label=my-app --ip=192.168.1.100 --ttl=3\n");
        echo("  php {$argv[0]} check --app-key=abc-def-ghi --path=tmp --ip=192.168.1.100 --token=the-api-key-token-here\n");
        echo("  php {$argv[0]} check --app-key=abc-def-ghi --path=tmp --token=the-api-key-token-here\n");
        echo("  php {$argv[0]} help\n");
    }

    /**
     * Parses the command-line arguments and stores them in the `$options` array.
     *
     * This function iterates through the command-line arguments (excluding the
     * script name and the command) and extracts options in the format `--key=value`
     * or boolean flags like `--verbose`. The parsed options are stored as key-value
     * pairs in the static `$options` array. If the `--verbose` option is not
     * present, it defaults to `false`.
     *
     * @global array $argv The global array containing command-line arguments.
     * @global int $argc The number of command-line arguments.
     *
     * @return void
     *
     * @since 0.0.1
     */
    public static function parse()
    {
        global $argv, $argc;
        // Parse command-line options
        for ($i = 2; $i < $argc; $i++) {
            $arg = $argv[$i];
            if (strpos($arg, '--') === 0) {
                $parts = explode('=', substr($arg, 2), 2);
                $key = $parts[0];
                $value = isset($parts[1]) ? $parts[1] : true; // Allow boolean flags
                if( ! is_bool($value)){
                    if(empty(trim($value))) continue;
                }
                self::$options[$key] = $value;
            } else {
                // Handle non-option arguments if needed
            }
        }
        if( ! in_array('verbose', self::$options)) self::$options['verbose'] = false;
    }

    /**
     * Handles the `generate` command to create and store a new API key.
     *
     * This function retrieves the required options (`--app-key`, `--path`, `--label`)
     * from the `$options` array. It then defines the `API_KEY_PATH` and `APP_KEY`
     * constants and calls the `ApiKeyFS::make()` method to generate and store
     * the new API key. Optional parameters like `--ip`, `--ttl`, `--key-length`, and
     * `--algo` are also handled. If the `--verbose` option is enabled, additional
     * information about the generated key and its storage location is printed.
     * In case of any error during the key generation process, an error message
     * is displayed, and the script exits with an error code.
     *
     * @return void
     *
     * @since 0.0.1
     */
    public static function handle_generate()
    {
        foreach([
            'app-key' => "Error: The --app-key option is required for the generate command.",
            'path' => "Error: The --path option is required for the generate command.",
            'label' => "Error: The --label option is required for the generate command.",
        ] as $option => $message){
            if ( ! isset(self::$options[$option])) {
                echo($message . PHP_EOL);
                self::display_help();
                exit(1);
            }
            if (is_bool(self::$options[$option])) {
                echo($message . PHP_EOL);
                self::display_help();
                exit(1);
            }
        }

        $verbose = self::$options['verbose'];
        $app_key = self::$options['app-key'];
        $path = self::$options['path'];
        $label = self::$options['label'];
        $ip = isset(self::$options['ip']) ? self::$options['ip'] : '';
        $ttl = isset(self::$options['ttl']) ? intval(self::$options['ttl']) : 0;
        $key_length = isset(self::$options['key-length']) ? self::$options['key-length'] : API_KEY_DEFAULT_LENGTH;
        $algo = isset(self::$options['algo']) ? self::$options['algo'] : API_KEY_DEFAULT_ALGO;

        $key_length = is_int($key_length) && $key_length >= 1 ? $key_length : API_KEY_DEFAULT_LENGTH;
        $ttl = is_int($ttl) && $ttl >= 1 ? $ttl : 0;

        try {
            /**
             * @ignore
             */
            define('API_KEY_PATH', $path);
            /**
             * @ignore
             */
            define('APP_KEY', $app_key);
            $key = ApiKeyFS::make(
                label: $label,
                ip: $ip,
                ttl: $ttl,
                KEY_LENGTH: $key_length,
                HASH_ALGO: $algo,
            );
            assert( ! empty($key));
            $token = $key->token();
            if($verbose) echo("Generated API Key Token:\n");
            echo($token);
            if($verbose) echo("\n");
            if($verbose) echo("Key stored in: " . API_KEY_PATH . "\n");
        } catch (\Exception $e) {
            echo("Error: " . $e->getMessage() . "\n");
            exit(1);
        }
    }

    /**
     * Handles the `check` command to verify the validity of an API key.
     *
     * This function retrieves the required options (`--app-key`, `--path`, `--token`)
     * from the `$options` array. It then defines the `API_KEY_PATH` and `APP_KEY`
     * constants and calls the `ApiKeyFS::check()` method to validate the provided
     * API key token. Optional parameters like `--key-length` and `--algo` are also
     * handled. The function then prints whether the provided API key token is valid
     * or invalid. In case of any error during the validation process, an error
     * message is displayed, and the script exits with an error code.
     *
     * @return void
     *
     * @since 0.0.1
     */
    public static function handle_check()
    {
        foreach([
            'app-key' => "Error: The --app-key option is required for the check command.",
            'path' => "Error: The --path option is required for the check command.",
            'token' => "Error: The --token option is required for the check command.",
        ] as $option => $message){
            if ( ! isset(self::$options[$option])) {
                echo($message . PHP_EOL);
                self::display_help();
                exit(1);
            }
            if (is_bool(self::$options[$option])) {
                echo($message . PHP_EOL);
                self::display_help();
                exit(1);
            }
        }

        $app_key = self::$options['app-key'];
        $path = self::$options['path'];
        $token = self::$options['token'];
        $ip = isset(self::$options['ip']) ? self::$options['ip'] : '';
        $key_length = isset(self::$options['key-length']) ? self::$options['key-length'] : API_KEY_DEFAULT_LENGTH;
        $algo = isset(self::$options['algo']) ? self::$options['algo'] : API_KEY_DEFAULT_ALGO;

        $key_length = is_int($key_length) && $key_length >= 1 ? $key_length : API_KEY_DEFAULT_LENGTH;

        try {
            /**
             * @ignore
             */
            define('API_KEY_PATH', $path);
            /**
             * @ignore
             */
            define('APP_KEY', $app_key);
            $isValid = ApiKeyFS::check(
                token: $token,
                ip: $ip,
                KEY_LENGTH: $key_length,
                HASH_ALGO: $algo,
            );
            echo("API Key Token is " . ($isValid ? "valid" : "invalid") . ".\n");
        } catch (\Exception $e) {
            echo("Error: " . $e->getMessage() . "\n");
            exit(1);
        }
    }

    /**
     * Handles the `test` command to run various tests.
     *
     * This function calls the `test()` methods of the `Key`, `ApiKeyMemory`,
     * `ApiKeyFS`, and `CLI` classes. The verbosity of the test output can be
     * controlled using the `--verbose` option. After all tests are executed,
     * it prints "ok" to indicate successful completion.
     *
     * @return void
     *
     * @since 0.0.1
     */
    public static function handle_test()
    {
        $verbose = self::$options['verbose'];
        base64::test(debug: $verbose);
        XoRx::test(debug: $verbose);
        Key::test(debug: $verbose);
        ApiKeyMemory::test(debug: $verbose);
        if(function_exists('apcu_add') && function_exists('apcu_fetch'))
            ApiKeyAPCu::test(debug: $verbose);
        if(class_exists('\\Memcached'))
            ApiKeyMemcached::test(debug: $verbose);
        ApiKeyFS::test(debug: $verbose);
        ApiKeyDatabase::test(debug: $verbose);
        CLI::test(debug: $verbose);
        echo('ok' . PHP_EOL);
    }

    /**
     * Runs the CLI application.
     *
     * This is the main entry point for the CLI tool. It retrieves the command
     * from the command-line arguments, parses the options, and then calls the
     * appropriate handler function based on the provided command. If no command
     * is provided or if the command is `help`, it calls the `display_help()`
     * function. Finally, it exits with a success code (0).
     *
     * @global array $argv The global array containing command-line arguments.
     *
     * @return void
     *
     * @since 0.0.1
     */
    public static function run()
    {
        global $argv;
        $command = $argv[1] ?? NULL;
        self::parse();
        switch ($command) {
            case 'generate':
                self::handle_generate();
                break;
            case 'check':
                self::handle_check();
                break;
            case 'test':
                self::handle_test();
                break;
            case 'version':
                echo(API_KEY_VERSION);
                break;
            case 'help':
            default:
                self::display_help();
                break;
        }
        exit(0);
    }

    /**
     * Runs tests specifically for the `CLI` class.
     *
     * This function performs various tests to ensure the correct behavior of the
     * `CLI` class, including handling of missing required options for the `generate`
     * and `check` commands, as well as successful execution of these commands.
     * It uses the `exec()` function to simulate command-line calls and `assert()`
     * to verify the expected output and return codes. The `$debug` parameter can
     * be used to enable verbose output of the test execution.
     *
     * @param bool $debug Optional. If `true`, prints additional debugging information
     * during the test execution. Defaults to `false`.
     *
     * @return void
     *
     * @since 0.0.1
     */
    public static function test(bool $debug = false)
    {
        // bad generate
        foreach([
            'php ApiKey.php generate' => "Error: The --app-key option is required for the generate command.",
            'php ApiKey.php generate --app-key' => "Error: The --app-key option is required for the generate command.",
            'php ApiKey.php generate --app-key=' => "Error: The --app-key option is required for the generate command.",
            'php ApiKey.php generate --app-key=abc-def-ghi' => "Error: The --path option is required for the generate command.",
            'php ApiKey.php generate --app-key=abc-def-ghi --path=tmp' => "Error: The --label option is required for the generate command.",
        ] as $command => $message){
            $output = [];
            $return_var = 0;
            if($debug) echo("Command: $command\n");
            exec($command, $output, $return_var);
            if($debug) var_dump([
                'return_var' => $return_var,
                'message' => $message,
                'output[0]' => $output[0],
                'output' => $output,
            ]);
            assert($return_var === 1);
            assert($output);
            assert(count($output) > 1);
            assert($output[0] === $message);
        }

        // good generate
        $output = [];
        $return_var = 0;
        $command = 'php ApiKey.php generate --app-key=abc-def-ghi --path=tmp --label=my-app --ip=192.168.1.100 --ttl=1';
        if($debug) echo("Command: $command\n");
        exec($command, $output, $return_var);
        if($debug) var_dump(['return_var' => $return_var, 'output' => $output]);
        assert($return_var === 0);
        assert(count($output) === 1);
        $token = $output[0];
        assert( ! empty($token));

        // bad check
        foreach([
            'php ApiKey.php check' => "Error: The --app-key option is required for the check command.",
            'php ApiKey.php check --app-key' => "Error: The --app-key option is required for the check command.",
            'php ApiKey.php check --app-key=' => "Error: The --app-key option is required for the check command.",
            'php ApiKey.php check --app-key=abc-def-ghi' => "Error: The --path option is required for the check command.",
            'php ApiKey.php check --app-key=abc-def-ghi --path=tmp' => "Error: The --token option is required for the check command.",
        ] as $command => $message){
            $output = [];
            $return_var = 0;
            if($debug) echo("Command: $command\n");
            exec($command, $output, $return_var);
            if($debug) var_dump(['return_var' => $return_var, 'output' => $output]);
            assert($return_var === 1);
            if($debug) var_dump($output);
            assert($output);
            assert(count($output) > 1);
            assert($output[0] === $message);
        }

        // good check vaild
        foreach([
            '',
            '--ip=192.168.1.100',
        ] as $ip){
            $output = [];
            $command = "php ApiKey.php check --app-key=abc-def-ghi --path=tmp $ip --token=" . $token;
            $return_var = 0;
            if($debug) echo("Command: $command\n");
            exec($command, $output, $return_var);
            if($debug) var_dump(['return_var' => $return_var, 'output' => $output]);
            assert($return_var === 0);
            if($debug) var_dump($output);
            assert(count($output) === 1);
            assert(in_array('API Key Token is valid.', $output));
        }

        // check invalid
        sleep(2);
        foreach([
            'php ApiKey.php check --app-key=abc-def-ghi --path=tmp --ip=192.168.1.100 --token=' . $token,
            'php ApiKey.php check --app-key=abc-def-ghi --path=tmp --ip=192.168.1.101 --token=' . $token,
            'php ApiKey.php check --app-key=abc-def-ghi --path=tmp --token=xyz',
        ] as $command){
            $output = [];
            $return_var = 0;
            if($debug) echo("Command: $command\n");
            exec($command, $output, $return_var);
            if($debug) var_dump(['return_var' => $return_var, 'output' => $output]);
            assert($return_var === 0);
            if($debug) var_dump($output);
            assert(count($output) === 1);
            assert(in_array('API Key Token is invalid.', $output));
        }
    }
}

if(defined('API_KEY_LIB')) return;
CLI::run();
?>
#!/usr/bin/env php
<?php declare(strict_types=1);

/**
 * @license MIT
 * @author Abdelaziz Elarashed Elshaikh Mohamed
 * @copyright 2025
 * @package ApiKey
 * @link https://github.com/vzool/ApiKey
 */

define('API_KEY_VERSION', '0.0.1');

/**
 * Provides simple XOR-based encryption and decryption functionalities.
 *
 * This class offers static methods for encrypting and decrypting strings using a provided key.
 * It employs a bitwise XOR operation and extends the key if it's shorter than the plaintext
 * by repeatedly hashing it.
 * 
 * REF https://www.codecauldron.dev/2021/02/12/simple-xor-encryption-in-php/
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
     * @param string $algo      The hashing algorithm to use for key extension (default: 'sha3-384').
     * @return string The generated key, guaranteed to be at least as long as the plaintext.
     */
    public static function key(string $plainText, string $key, string $algo = 'sha3-384') : string
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
     * @param string $algo      The hashing algorithm used to extend the key (default: 'sha3-384').
     * @return string The encrypted string in lowercase hexadecimal format.
     */
    public static function encrypt(string $plainText, string $key, string $algo = 'sha3-384') : string
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
     * @param string $algo      The hashing algorithm used to extend the key during encryption (default: 'sha3-384').
     * @return string The original decrypted plaintext string.
     */
    public static function decrypt(string $encryptedText, string $key, string $algo = 'sha3-384') : string
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
     */
    public static function test(bool $debug = false)
    {
        self::$debug = $debug;

        $text = "Salam World!!!";
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

        $text = str_repeat('x', 100);
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

/**
 * Represents a cryptographic key with associated metadata and functionality
 * for generating, validating, and parsing tokens.
 */
class Key
{
    /**
     * The public key associated with this Key object.
     *
     * @var string
     */
    public string $public_key;

    /**
     * A static flag to enable or disable debug output.
     * Defaults to false.
     *
     * @var bool
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
     * @param int $KEY_LENGTH The length of the generated random keys in bytes. Defaults to 33.
     * @param string $HASH_ALGO The hashing algorithm to use for HMAC. Defaults to 'sha3-384'.
     * Must be a supported algorithm by `hash_hmac_algos()`.
     * @param string $hashed_public_key An optional pre-computed hashed public key.
     * @param string $data Optional pre-existing data associated with the key.
     * @throws Exception If `$APP_KEY` is empty or if the `$HASH_ALGO` is not supported.
     */
    public function __construct(
        public string $label,
        public string $ip,
        private string $APP_KEY,
        private int $KEY_LENGTH = 33,
        private string $HASH_ALGO = 'sha3-384',
        public string $hashed_public_key = '',
        public string $data = '',
    ) {
        if( ! $APP_KEY) throw new Exception('APP_KEY is required.');
        if( ! in_array($HASH_ALGO, hash_hmac_algos()))
            throw new Exception('Unsupported hash algorithm(' . $HASH_ALGO . ')');

        if($hashed_public_key || $data) return;

        $this->public_key = $this->random_key();
        $private_key = $this->random_key() . $this->random_key();
        $this->hashed_public_key = self::hmac(
            text: $this->public_key,
            APP_KEY: $this->APP_KEY,
            HASH_ALGO: $this->HASH_ALGO,
        );
        $payload = json_encode([$label, $ip, date('Y-m-d H:i:s')]);
        $length = strlen($payload);
        $encrypted_payload = XoRx::encrypt($payload, $private_key);
        $terminator = hash($HASH_ALGO, $private_key);
        $data = bin2hex(random_bytes(random_int(1, $this->KEY_LENGTH)))
            . $this->hashed_public_key
            . $private_key
            . $length
            . $terminator
            . $encrypted_payload
            . bin2hex(random_bytes(random_int(1, $this->KEY_LENGTH)))
            ;
        $this->data = $data;
        if(self::$debug){
            echo('[KEY]' . PHP_EOL);
            var_dump([
                'hashed_public_key' => $this->hashed_public_key,
                'private_key' => $private_key,
                'length' => $length,
                'terminator' => $terminator,
                'encrypted_payload' => $encrypted_payload,
                'data' => $data,
            ]);
        }
    }

    /**
     * Generates a random key of the specified length.
     *
     * @return string A hexadecimal representation of the random key.
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
     */
    private function private_key()
    {
        if(static::$debug){
            echo('private_key' . PHP_EOL);
            var_dump([
                'assert' => [
                    'strlen' => strlen($this->data),
                    'KEY_LENGTH * 4' => $this->KEY_LENGTH * 4,
                    'result' => strlen($this->data) >= $this->KEY_LENGTH * 4,
                ],
            ]);
        }
        assert(strlen($this->data) >= $this->KEY_LENGTH * 4);
        $data = explode($this->hashed_public_key, $this->data);
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
        $terminator = hash($this->HASH_ALGO, $private_key);
        $terminal = explode($terminator, $this->data);
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
     * @param string $HASH_ALGO The hashing algorithm to use. Defaults to 'sha3-384'.
     * @return string The hexadecimal representation of the HMAC.
     */
    public static function hmac(
        string $text,
        string $APP_KEY,
        string $HASH_ALGO = 'sha3-384',
    ) : string
    {
        if(self::$debug){
            echo('hmac[get_defined_vars]: ' . PHP_EOL);
            var_dump(get_defined_vars());
        }
        return hash_hmac($HASH_ALGO, $text, $APP_KEY, false);
    }

    /**
     * Generates a token by concatenating the public key and the HMAC of the private key.
     *
     * @return string The generated token.
     * @throws AssertionFailedError If `$this->public_key` is empty in non-debug mode.
     */
    public function token() : string
    {
        assert( ! empty($this->public_key));
        list($private_key, $payload) = $this->private_key();
        return $this->public_key . self::hmac(
            text: $private_key,
            APP_KEY: $this->APP_KEY,
            HASH_ALGO: $this->HASH_ALGO,
        );
    }

    /**
     * Parses a token to extract the public key and the shared key (HMAC of the private key).
     *
     * @param string $token The token to parse.
     * @param int $KEY_LENGTH The expected length of the public key in bytes. Defaults to 33.
     * @param string $HASH_ALGO The hashing algorithm that was used to generate the HMAC. Defaults to 'sha3-384'.
     * @return array An array containing the public key (at index 0) and the shared key (at index 1),
     * or an empty array if the token format is invalid or the hash algorithm is unsupported.
     * @throws Exception If the `$HASH_ALGO` is not supported.
     */
    public static function parse(
        string $token,
        int $KEY_LENGTH = 33,
        string $HASH_ALGO = 'sha3-384',
    ) : array
    {
        if( ! in_array($HASH_ALGO, hash_hmac_algos())) throw new Exception('Unsupported hash algorithm(' . $HASH_ALGO . ')');

        $HASH_LENGTH = strlen(hash($HASH_ALGO, ''));
        if(strlen($token) !== $HASH_LENGTH + ($KEY_LENGTH * 2))
            return [];

        $public_key = substr($token, 0, -$HASH_LENGTH);
        $public_key_length = strlen($public_key);
        $shared_key = substr($token, $public_key_length, $HASH_LENGTH); // !!!

        if(static::$debug){
            echo('parse' . PHP_EOL);
            echo('public_key' . PHP_EOL);
            var_dump([
                'substr' => [
                    $token,
                    0,
                    -$HASH_LENGTH,
                ],
                'result' => $public_key,
            ]);
            echo('shared_key' . PHP_EOL);
            var_dump([
                'substr' => [
                    $token,
                    $public_key_length,
                    $HASH_LENGTH,
                ],
                'result' => $shared_key,
            ]);
        }

        return [
            $public_key,
            $shared_key,
        ];
    }

    /**
     * Validates a given token against the current Key object's private key and application key.
     * 
     * @param string $ip The IP address associated with this key. Defaults to an empty string.
     *
     * @param string $token The token to validate.
     * @return bool True if the token is valid, false otherwise.
     */
    public function valid(string $token, string $ip = '') : bool
    {
        $parsed = self::parse(
            token: $token,
            KEY_LENGTH: $this->KEY_LENGTH,
            HASH_ALGO: $this->HASH_ALGO,
        );

        if( ! $parsed) return false;

        list($public_key, $shared_key) = $parsed;
        list($private_key, $payload) = $this->private_key();
        list($label, $stored_ip, $created) = $payload;

        $valid = hash_equals(
            self::hmac(
                text: $private_key,
                APP_KEY: $this->APP_KEY,
                HASH_ALGO: $this->HASH_ALGO,
            ),
            $shared_key,
        );

        if( ! empty($ip) && ! empty($stored_ip)){
            return $valid && $ip === $stored_ip;
        }

        return $valid;
    }

    /**
     * Returns an associative array representing the Key object's label, IP address, and data.
     *
     * @return array An associative array with keys 'label', 'ip', and 'data'.
     */
    public function dict()
    {
        return [
            'label' => $this->label,
            'ip' => $this->ip,
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
     */
    public static function anatomy(string $token, Key $key)
    {
        $parsed = Key::parse(token: $token);
        
        list($public_key, $shared_key) = $parsed ?? [NULL, NULL];

        return [
            'token' => $token,
            'public_key[0]' => $key->public_key,
            'public_key[1]' => $public_key,
            'shared_key' => $shared_key,
            'hashed_public_key' => $key->hashed_public_key,
            'data' => $key->data,
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
     * @param int $KEY_LENGTH The length of the original random keys in bytes. Defaults to 33.
     * @param string $HASH_ALGO The hashing algorithm used for HMAC. Defaults to 'sha3-384'.
     * @return self A new Key object initialized with the provided data.
     */
    public static function create(
        string $hashed_public_key,
        string $data,
        string $APP_KEY,
        string $label = '',
        string $ip = '',
        int $KEY_LENGTH = 33,
        string $HASH_ALGO = 'sha3-384',
    ) : self
    {
        return new self(
            label: $label,
            ip: $ip,
            APP_KEY: $APP_KEY,
            KEY_LENGTH: $KEY_LENGTH,
            HASH_ALGO: $HASH_ALGO,
            hashed_public_key: $hashed_public_key,
            data: $data,
        );
    }

    /**
     * Performs a series of tests to verify the functionality of the Key class.
     *
     * @param bool $debug If true, enables verbose output during the tests. Defaults to false.
     * @return void
     */
    public static function test(bool $debug = false)
    {
       $failed = false;
       try{
            new self('x', '127.0.0.1', '');
        }catch(Exception $ex) { $failed = true; }
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
                if($debug) var_dump($key);
                $token = $key->token();
                if($debug) var_dump($token);
                assert( ! empty($token));
                assert($key->valid($token));
                assert( ! $key->valid($token . 'x'));
                assert( ! $key->valid('x'));
                assert( ! $key->valid(''));
                $key2 = Key::create(
                    hashed_public_key: $key->hashed_public_key,
                    data: $key->data,
                    APP_KEY: $APP_KEY,
                    KEY_LENGTH: $KEY_LENGTH,
                    HASH_ALGO: $algo,
                );
                if($debug) var_dump($key2);
                assert( ! empty($key2));
                $failed = false;
                try{
                    //$key2->token();
                }catch(Exception $ex) { $failed = true; }
                //assert($failed);
                assert($key2->valid($token));
                assert($key2->valid($token, '127.0.0.1'));
                assert( ! $key2->valid($token, '127.0.0.2'));
                assert( ! $key2->valid($token . 'y'));
                assert( ! $key2->valid('y'));
                assert( ! $key2->valid(''));
                assert( ! empty($token));
            }
        }
    }
}

/**
 * Extends the Key class to provide an in-memory storage mechanism for API keys.
 * This class is primarily intended for development or testing environments
 * where persistent storage is not required.
 */
class ApiKeyMemory extends Key
{
    /**
     * @var array $memory
     * A static array that holds the API keys in memory.
     * The keys of this array are the hashed public keys, and the values
     * are arrays representing the key data.
     */
    private static $memory = [];

    /**
     * Saves a Key object's data into the in-memory storage.
     *
     * @param string $hashed_public_key The hashed version of the public key, used as the storage key.
     * @param Key $key The Key object to save.
     * @return bool Returns true if the key was successfully saved.
     */
    protected static function save(string $hashed_public_key, Key $key) : bool
    {
        self::$memory[$hashed_public_key] = $key->dict();
        return true;
    }

    /**
     * Loads a key's data from the in-memory storage based on its hashed public key.
     *
     * @param string $hashed_public_key The hashed version of the public key to look up.
     * @return array|null Returns an array containing the key's data if found, otherwise NULL.
     */
    protected static function load(string $hashed_public_key)
    {
        return self::$memory[$hashed_public_key] ?? NULL;
    }

    /**
     * Generates a new API key, saves it in memory, and returns the token.
     *
     * @param string $label A descriptive label for the API key.
     * @param string $ip The IP address associated with this key (optional, defaults to '').
     * @param string $APP_KEY The application-specific secret key used for signing (defaults to the global APP_KEY constant).
     * @param int $KEY_LENGTH The desired length of the public and private keys (defaults to 33).
     * @param string $HASH_ALGO The hashing algorithm to use (defaults to 'sha3-384').
     * @return string The generated API token.
     */
    public static function make(
        string $label,
        string $ip = '',
        string $APP_KEY = APP_KEY,
        int $KEY_LENGTH = 33,
        string $HASH_ALGO = 'sha3-384',
    ) : string
    {
        if(self::$debug){
            echo('=================================================' . PHP_EOL);
            echo("MAKE(token)" . PHP_EOL);
        }
        $key = new self(
            label: $label . '@' . date('Y-m-d H:i:s'),
            ip: $ip,
            APP_KEY: $APP_KEY,
            KEY_LENGTH: $KEY_LENGTH,
            HASH_ALGO: $HASH_ALGO,
        );
        assert(static::save($key->hashed_public_key, $key));
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
        return $key->token();
    }

    /**
     * Checks if a given API token is valid by retrieving the corresponding key from memory.
     *
     * @param string $token The API token to check.
     * @param string $ip The IP address associated with this key (optional, defaults to '').
     * @param string $APP_KEY The application-specific secret key used for signing (defaults to the global APP_KEY constant).
     * @param int $KEY_LENGTH The expected length of the public and private keys (defaults to 33).
     * @param string $HASH_ALGO The hashing algorithm used (defaults to 'sha3-384').
     * @return bool Returns true if the token is valid, false otherwise.
     */
    public static function check(
        string $token,
        string $ip = '',
        string $APP_KEY = APP_KEY,
        int $KEY_LENGTH = 33,
        string $HASH_ALGO = 'sha3-384',
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

        list($public_key, $shared_key) = $parsed;

        $hashed_public_key = self::hmac(
            text: $public_key,
            APP_KEY: $APP_KEY,
            HASH_ALGO: $HASH_ALGO,
        );
        $key_dict = static::load($hashed_public_key);
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
     */
    public static function test(bool $debug = false)
    {
        $APP_KEY = '65162b0b-784d-4e15-88b4-459d5caadf3f';
        self::$debug = $debug;
        $token = self::make(
            label: 'x',
            APP_KEY: $APP_KEY,
            ip: '127.0.0.1',
        );
        assert( ! empty($token));
        assert(self::check($token, APP_KEY: $APP_KEY));
        assert(self::check($token, APP_KEY: $APP_KEY, ip: '127.0.0.1'));
        assert( ! self::check($token, APP_KEY: $APP_KEY, ip: '127.0.0.2'));
        assert( ! self::check('', APP_KEY: $APP_KEY));
        assert( ! self::check('123', APP_KEY: $APP_KEY));
    }
}

/**
 * Manages API keys, extending the in-memory storage with file system persistence.
 *
 * This class provides methods for saving, loading, and managing API keys,
 * storing them as JSON files within a designated directory. It inherits
 * functionality from `ApiKeyMemory`.
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
     */
    protected static function path(string $file) : string
    {
        $path = defined('API_KEY_PATH') ? API_KEY_PATH : '.tmp';
        $path .= DIRECTORY_SEPARATOR . 'api_keys' . DIRECTORY_SEPARATOR;
        @mkdir($path, permissions: 0700, recursive: true);
        return $path . DIRECTORY_SEPARATOR . $file;
    }

    /**
     * Saves an API key to the file system.
     *
     * The key's data (represented as an associative array from the `dict()` method
     * of the `Key` object) is encoded as JSON and written to a file named after
     * the hashed public key.
     *
     * @param string $hashed_public_key The hashed public key used as the filename.
     * @param Key $key The `Key` object to be saved.
     * @return bool True if the key was saved successfully, false otherwise.
     */
    protected static function save(string $hashed_public_key, Key $key) : bool
    {
        return file_put_contents(
            self::path($hashed_public_key),
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
     * @return array|null An associative array representing the API key data, or null if the file is empty or does not exist.
     */
    protected static function load(string $hashed_public_key)
    {
        $data = file_get_contents(self::path($hashed_public_key));
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
     */
    public static function test(bool $debug = false)
    {
        /**
         * @ignore
         */
        define('API_KEY_PATH', 'tmp');
        /**
         * @ignore
         */
        define('APP_KEY', '94473B99-23CB-4A4D-A315-C0F9B8C9B39A');
        self::$debug = $debug;
        $token = self::make(
            label: 'x',
            ip: '127.0.0.1',
        );
        assert( ! empty($token));
        assert(self::check($token));
        assert(self::check($token, ip: '127.0.0.1'));
        assert( ! self::check($token, ip: '127.0.0.2'));
        assert( ! self::check(''));
        assert( ! self::check('123'));
    }
}

/**
 * Provides a command-line interface for generating and checking API keys.
 *
 * This class offers static methods to handle command-line arguments,
 * display help information, and execute specific actions such as
 * generating new API keys, checking the validity of existing keys,
 * and running internal tests. It relies on the `ApiKeyFS` class for
 * the underlying API key storage and validation logic.
 */
class CLI
{
    /**
     * @var array $options An associative array to store parsed command-line options.
     * The keys of the array are the option names (without the '--' prefix),
     * and the values are the corresponding option values. Boolean flags
     * will have a value of `true`.
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
        echo("  --token=<token>             The API key token to check (required for check).\n");
        echo("  --key-length=<key-length>   The size of key building block (optional: default 33).\n");
        echo("  --algo=<algo>               The algorithm used for hmac hashing (optional: default sha3-384). See `hash_hmac_algos()` for supported algorithms.\n");
        echo("  --verbose                   Print verbose messages (optional: false).\n");
        echo("\n");
        echo("Example:\n");
        echo("  php {$argv[0]} generate --app-key=abc-def-ghi --path=tmp --label=my-app --ip=192.168.1.100\n");
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
     * the new API key. Optional parameters like `--ip`, `--key-length`, and
     * `--algo` are also handled. If the `--verbose` option is enabled, additional
     * information about the generated key and its storage location is printed.
     * In case of any error during the key generation process, an error message
     * is displayed, and the script exits with an error code.
     *
     * @return void
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
        $key_length = isset(self::$options['key-length']) ? self::$options['key-length'] : 33;
        $algo = isset(self::$options['algo']) ? self::$options['algo'] : 'sha3-384';

        $key_length = is_int($key_length) && $key_length >= 1 ? $key_length : 33;

        try {
            /**
             * @ignore
             */
            define('API_KEY_PATH', $path);
            /**
             * @ignore
             */
            define('APP_KEY', $app_key);
            $token = ApiKeyFS::make(
                label: $label,
                ip: $ip,
                KEY_LENGTH: $key_length,
                HASH_ALGO: $algo,
            );
            if($verbose) echo("Generated API Key Token:\n");
            echo($token);
            if($verbose) echo("\n");
            if($verbose) echo("Key stored in: " . API_KEY_PATH . "\n");
        } catch (Exception $e) {
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
        $key_length = isset(self::$options['key-length']) ? self::$options['key-length'] : 33;
        $algo = isset(self::$options['algo']) ? self::$options['algo'] : 'sha3-384';

        $key_length = is_int($key_length) && $key_length >= 1 ? $key_length : 33;

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
        } catch (Exception $e) {
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
     */
    public static function handle_test()
    {
        $verbose = self::$options['verbose'];
        XoRx::test(debug: $verbose);
        Key::test(debug: $verbose);
        ApiKeyMemory::test(debug: $verbose);
        ApiKeyFS::test(debug: $verbose);
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
            if($debug) var_dump(['return_var' => $return_var, 'output' => $output]);
            assert($return_var === 1);
            assert($output);
            assert(count($output) > 1);
            assert($output[0] === $message);
        }

        // good generate
        $output = [];
        $return_var = 0;
        $command = 'php ApiKey.php generate --app-key=abc-def-ghi --path=tmp --label=my-app --ip=192.168.1.100';
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
        foreach([
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
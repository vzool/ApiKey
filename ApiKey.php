<?php

define('KEY_LENGTH', 33);
define('HASH_ALGO', 'sha3-384');
define('HASH_LENGTH', strlen(hash(HASH_ALGO, '')));

class ApiKey
{
    private static $data = [];

    public function __construct(
        public string $label,
        public string $ip,
        public string $stored_key = '',
    ) {}

    private static function private_key(string $stored_key, string $public_key)
    {
        if(strlen($stored_key) > KEY_LENGTH * 4)
        {
            $y = explode(hash(HASH_ALGO, $public_key), $stored_key);
            return substr($y[1], 0, KEY_LENGTH * 2);
        }
    }

    private static function randomKey() : string
    {
        do $key = bin2hex(random_bytes(KEY_LENGTH));
        while (self::keyExists($key));

        return $key;
    }

    private static function calculateSharedKey(string $private_key, ?string $custom_app_key = null) : string
    {
        assert(defined('APP_KEY'));
        $app_key = $custom_app_key ?? APP_KEY;

        if(!$app_key) return 'Your application does not has an app key, search for `APP_KEY`!!!';
        if(!in_array(HASH_ALGO, hash_hmac_algos())) return 'Unsupported hash algorithm(' . HASH_ALGO . ')';

        return hash_hmac(HASH_ALGO, $private_key, $app_key, false);
    }

    private static function keyExists(string $key)
    {
        $hash = hash(HASH_ALGO, $key);
        if(strlen($key) >= KEY_LENGTH * 2)
            return array_reduce(
                array_keys(self::$data),
                function (?array $carry, string $key) use ($hash): ?ApiKey {
                    if ($carry !== null) {
                        return $carry; // First match already found, return it
                    }
                    if (strpos($key, $hash) !== false) {
                        $apiKey = self::$data[$key];
                        if($apiKey){
                            $apiKey->stored_key = $key;
                            return $apiKey;
                        }
                    }
                    return null; // No match yet, continue the reduction
                },
                null // Initial value for the carry
            );
    }

    public static function make(string $label, string $ip = '') : string
    {
        $public_key = self::randomKey();
        $stored_key = uniqid(bin2hex(random_bytes(random_int(1, KEY_LENGTH)))) .
                hash(HASH_ALGO, $public_key) .
                self::randomKey() .
                uniqid(bin2hex(random_bytes(random_int(1, KEY_LENGTH))));
        $apiKey = new ApiKey(
            label: $label . '@' . date('Y-m-d H:i:s'),
            ip: $ip,
        );
        self::$data[$stored_key] = $apiKey;
        $privateKey = self::private_key($stored_key, $public_key);
        return $public_key . self::calculateSharedKey($privateKey);
    }

    public static function check(string $token) : bool
    {
        if(strlen($token) !== HASH_LENGTH + (KEY_LENGTH * 2)) return false;

        $public_key = substr($token, 0, -HASH_LENGTH);
        $shared_key = substr($token, -HASH_LENGTH);
        $apiKey = self::keyExists($public_key);

        if(!$apiKey) return false;
        return hash_equals(self::calculateSharedKey(self::private_key($apiKey->stored_key, $public_key)), $shared_key);
    }
}

// $failed = FALSE;
// try{
//     ApiKey::make('x', '127.0.0.1');
// }catch(Exception $e){
//     $failed = TRUE;
// }
// assert($failed);
define('APP_KEY', '1bd4145f-30cd-46f2-aa7e-598039a34850');
$token = ApiKey::make('x', '127.0.0.1');
assert(ApiKey::check($token));
assert(!ApiKey::check($token. '3'));
assert(!ApiKey::check(''));

?>
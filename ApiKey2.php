<?php declare(strict_types=1);

define('KEY_LENGTH', 33);
define('HASH_ALGO', 'sha3-384');
define('HASH_LENGTH', strlen(hash(HASH_ALGO, '')));

class ApiKey
{
    public static $debug = false;
    private static $memory = [];

    public function __construct(
        public string $label,
        public string $ip,
        public string $data,
    ) {}

    public static function hmac(string $text, $custom_app_key = null) : string
    {
        $app_key = $custom_app_key ?? APP_KEY;

        if(self::$debug)
            print('00000' . PHP_EOL);
        if(!$app_key) return 'Your application does not has an app key, search for `APP_KEY`!!!';
        if(self::$debug)
            print('11111' . PHP_EOL);
        if(!in_array(HASH_ALGO, hash_hmac_algos())) return 'Unsupported hash algorithm(' . HASH_ALGO . ')';
        if(self::$debug)
            print('22222' . PHP_EOL);

        return hash_hmac(HASH_ALGO, $text, $app_key, false);
    }

    private function private_key(string $hashed_public_key)
    {
        if(strlen($this->data) > KEY_LENGTH * 4)
        {
            $y = explode($hashed_public_key, $this->data);
            return substr($y[1], 0, KEY_LENGTH * 2);
        }
    }

    private static function random_key() : string
    {
        return bin2hex(random_bytes(KEY_LENGTH));
    }

    public static function make(string $label, string $ip = '') : string
    {
        $public_key = self::random_key();
        $hashed_public_key = self::hmac($public_key);
        $data = uniqid(bin2hex(random_bytes(random_int(1, KEY_LENGTH)))) .
                $hashed_public_key .
                self::random_key() .
                uniqid(bin2hex(random_bytes(random_int(1, KEY_LENGTH))))
                ;
        $apiKey = new ApiKey(
            label: $label . '@' . date('Y-m-d H:i:s'),
            ip: $ip,
            data: $data,
        );
        self::$memory[$hashed_public_key] = $apiKey; // TODO: save
        if(self::$debug)
            print_r(self::$memory);
        $private_key = $apiKey->private_key($hashed_public_key);
        if(self::$debug)
            var_dump($private_key);
        return  $public_key .
                self::hmac($private_key); // shared_key
    }

    public static function check(string $token) : bool
    {
        if(strlen($token) !== HASH_LENGTH + (KEY_LENGTH * 2)) return false;

        $public_key = substr($token, 0, -HASH_LENGTH);
        $shared_key = substr($token, -HASH_LENGTH);
        
        $hashed_public_key = self::hmac($public_key);
        $apiKey = self::$memory[$hashed_public_key] ?? NULL; // TODO: load

        if(!$apiKey) return false;
        return hash_equals(
            self::hmac($apiKey->private_key($hashed_public_key)),
            $shared_key,
        );
    }
    
    public static function test(bool $debug = false)
    {
        ApiKey::$debug = $debug;
        define('APP_KEY', '1bd4145f-30cd-46f2-aa7e-598039a34850');
        $token = ApiKey::make('x', '127.0.0.1');
        if($debug)
            var_dump($token);
        assert(ApiKey::check($token));
        assert(! ApiKey::check(''));
        assert(! ApiKey::check('123'));
    }
}

ApiKey::test(true);
?>
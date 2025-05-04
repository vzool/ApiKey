<?php declare(strict_types=1);

class Key
{
    private int $KEY_LENGTH;
    private string $HASH_ALGO;
    private int $HASH_LENGTH;
    private string $APP_KEY;

    public string $data;
    public string $public_key;
    public string $hashed_public_key;
    public string $label;
    public string $ip;
    public static bool $debug = false;

    public function __construct(
        string $label,
        string $ip,
        string $APP_KEY,
        int $KEY_LENGTH = 33,
        string $HASH_ALGO = 'sha3-384',
        string $hashed_public_key = '',
        string $data = '',
    ) {
        if(!$APP_KEY) throw new Exception('APP_KEY is required.');
        if(!in_array($HASH_ALGO, hash_hmac_algos())) throw new Exception('Unsupported hash algorithm(' . $HASH_ALGO . ')');

        $this->label = $label;
        $this->ip = $ip;
        $this->APP_KEY = $APP_KEY;
        $this->KEY_LENGTH = $KEY_LENGTH;
        $this->HASH_ALGO = $HASH_ALGO;
        $this->HASH_LENGTH = strlen(hash($HASH_ALGO, ''));
        $this->hashed_public_key = $hashed_public_key;
        $this->data = $data;

        if($hashed_public_key || $data) return;

        $this->public_key = $this->random_key();
        $this->hashed_public_key = self::hmac(
            text: $this->public_key,
            APP_KEY: $this->APP_KEY,
            HASH_ALGO: $this->HASH_ALGO,
        );
        $this->data = uniqid(bin2hex(random_bytes(random_int(1, $this->KEY_LENGTH)))) .
                $this->hashed_public_key .
                $this->random_key() .
                uniqid(bin2hex(random_bytes(random_int(1, $this->KEY_LENGTH))))
                ;
    }

    private function random_key() : string
    {
        return bin2hex(random_bytes($this->KEY_LENGTH));
    }

    private function private_key()
    {
        if(strlen($this->data) > $this->KEY_LENGTH * 4)
        {
            $y = explode($this->hashed_public_key, $this->data);
            return substr($y[1], 0, $this->KEY_LENGTH * 2);
        }
    }

    public static function hmac(
        string $text,
        string $APP_KEY,
        string $HASH_ALGO = 'sha3-384',
    ) : string
    {
    if(self::$debug){
            echo('get_defined_vars: ' . PHP_EOL);
            var_dump(get_defined_vars());
        }
        return hash_hmac($HASH_ALGO, $text, $APP_KEY, false);
    }

    public function token() : string
    {
        assert( ! empty($this->public_key));
        return $this->public_key . self::hmac(
            text: $this->private_key(),
            APP_KEY: $this->APP_KEY,
            HASH_ALGO: $this->HASH_ALGO,
        );
    }

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
        $shared_key = substr($token, -$HASH_LENGTH);

        return [
            $public_key,
            $shared_key,
        ];
    }

    public function valid(string $token) : bool
    {
        $parsed = self::parse(
            token: $token,
            KEY_LENGTH: $this->KEY_LENGTH,
            HASH_ALGO: $this->HASH_ALGO,
        );

        if(! $parsed) return false;

        list($public_key, $shared_key) = $parsed;

        return hash_equals(
            self::hmac(
                text: $this->private_key(),
                APP_KEY: $this->APP_KEY,
                HASH_ALGO: $this->HASH_ALGO,
            ),
            $shared_key,
        );
    }

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
                assert(! empty($token));
                assert($key->valid($token));
                assert(! $key->valid($token . 'x'));
                assert(! $key->valid('x'));
                assert(! $key->valid(''));
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
                assert( ! $key2->valid($token . 'y'));
                assert( ! $key2->valid('y'));
                assert( ! $key2->valid(''));
                assert( ! empty($token));
            }
        }
    }
}

class ApiKeyMemory extends Key
{
    private static $memory = [];

    private static function save(string $hashed_public_key, string $data) : bool
    {
        self::$memory[$hashed_public_key] = $data;
        return true;
    }

    private static function load(string $hashed_public_key)
    {
        return self::$memory[$hashed_public_key] ?? NULL;
    }

    public static function make(
        string $label,
        string $APP_KEY,
        string $ip = '',
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
        assert(self::save($key->hashed_public_key, $key->data));
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

    public static function check(
        string $token,
        string $APP_KEY,
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
        $data = self::load($hashed_public_key);
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
            hashed_public_key: $hashed_public_key,
            data: $data,
            APP_KEY: $APP_KEY,
            KEY_LENGTH: $KEY_LENGTH,
            HASH_ALGO: $HASH_ALGO,
        );

        if(!$key) return false;
        return $key->valid($token);
    }

    public static function test(bool $debug = false)
    {
        $APP_KEY = '65162b0b-784d-4e15-88b4-459d5caadf3f';
        self::$debug = $debug;
        $token = self::make(
            label: 'x',
            APP_KEY: $APP_KEY,
            ip: '127.0.0.1',
        );
        assert(! empty($token));
        assert(self::check($token, APP_KEY: $APP_KEY));
        assert( ! self::check('', APP_KEY: $APP_KEY));
        assert( ! self::check('123', APP_KEY: $APP_KEY));
    }
}
?>
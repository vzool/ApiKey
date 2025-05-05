#!/usr/bin/env php
<?php declare(strict_types=1);

define('API_KEY_VERSION', '0.0.1');

class Key
{
    public string $public_key;
    public static bool $debug = false;

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

        $this->label = $label;
        $this->ip = $ip;
        $this->APP_KEY = $APP_KEY;
        $this->KEY_LENGTH = $KEY_LENGTH;
        $this->HASH_ALGO = $HASH_ALGO;
        $this->hashed_public_key = $hashed_public_key;
        $this->data = $data;

        if($hashed_public_key || $data) return;

        $this->public_key = $this->random_key();
        $this->hashed_public_key = self::hmac(
            text: $this->public_key,
            APP_KEY: $this->APP_KEY,
            HASH_ALGO: $this->HASH_ALGO,
        );
        $data = uniqid(bin2hex(random_bytes(random_int(1, $this->KEY_LENGTH))))
            . $this->hashed_public_key
            . $this->random_key()
            . uniqid(bin2hex(random_bytes(random_int(1, $this->KEY_LENGTH))))
            ;
        $this->data = $data;
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
        $shared_key = substr($token, -$HASH_LENGTH, $HASH_LENGTH); // !!!

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

        if( ! $parsed) return false;

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

    public function dict()
    {
        return [
            'label' => $this->label,
            'ip' => $this->ip,
            'data' => $this->data,
        ];
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

    protected static function save(string $hashed_public_key, Key $key) : bool
    {
        self::$memory[$hashed_public_key] = $key->dict();
        return true;
    }

    protected static function load(string $hashed_public_key)
    {
        return self::$memory[$hashed_public_key] ?? NULL;
    }

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

    public static function check(
        string $token,
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
        assert( ! empty($token));
        assert(self::check($token, APP_KEY: $APP_KEY));
        assert( ! self::check('', APP_KEY: $APP_KEY));
        assert( ! self::check('123', APP_KEY: $APP_KEY));
    }
}

class ApiKeyFS extends ApiKeyMemory
{
    protected static function path(string $file) : string
    {
        $path = defined('API_KEY_PATH') ? API_KEY_PATH : '.tmp';
        $path .= DIRECTORY_SEPARATOR . 'api_keys' . DIRECTORY_SEPARATOR;
        @mkdir($path, permissions: 0700, recursive: true);
        return $path . DIRECTORY_SEPARATOR . $file;
    }

    protected static function save(string $hashed_public_key, Key $key) : bool
    {
        return file_put_contents(
            self::path($hashed_public_key),
            json_encode($key->dict()),
        ) !== false;
    }

    protected static function load(string $hashed_public_key)
    {
        $data = file_get_contents(self::path($hashed_public_key));
        return empty($data) ? NULL : json_decode($data, associative: true);
    }

    public static function test(bool $debug = false)
    {
        define('API_KEY_PATH', 'tmp');
        define('APP_KEY', '94473B99-23CB-4A4D-A315-C0F9B8C9B39A');
        self::$debug = $debug;
        $token = self::make(
            label: 'x',
            ip: '127.0.0.1',
        );
        assert( ! empty($token));
        assert(self::check($token));
        assert( ! self::check(''));
        assert( ! self::check('123'));
    }
}

if(defined('API_KEY_LIB')) return;

class CLI
{
    public static $options = [];

    public static function display_help()
    {
        global $argv;
        echo "Usage: {$argv[0]} <command> [options]\n";
        echo "Version: " . API_KEY_VERSION . "\n";
        echo "\n";
        echo "Commands:\n";
        echo "  generate  Generate a new API key and store it.\n";
        echo "  check     Check the validity of an API key.\n";
        echo "  test      Run the tests.\n";
        echo "  help      Display this help message.\n";
        echo "\n";
        echo "Options:\n";
        echo "  --app-key=<app-key>     Application key (always required).\n";
        echo "  --path=<api-keys-path>  API Keys storage path (always required).\n";
        echo "  --label=<label>         Label for the API key (required for generate).\n";
        echo "  --ip=<ip>               IP address of the client (optional for generate).\n";
        echo "  --token=<token>         The API key token to check (required for check).\n";
        echo "\n";
        echo "Example:\n";
        echo "  php {$argv[0]} generate --app-key=abc-def-ghi --path=tmp --label=my-app --ip=192.168.1.100\n";
        echo "  php {$argv[0]} check --app-key=abc-def-ghi --path=tmp --token=the-api-key-token-here\n";
        echo "  php {$argv[0]} help\n";
    }

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
                if(! is_bool($value)){
                    if(empty(trim($value))) continue;
                }
                self::$options[$key] = $value;
            } else {
                // Handle non-option arguments if needed
            }
        }
    }

    public static function handle_generate()
    {
        foreach([
            'app-key' => "Error: The --app-key option is required for the generate command.",
            'path' => "Error: The --path option is required for the generate command.",
            'label' => "Error: The --label option is required for the generate command.",
        ] as $option => $message){
            if (!isset(self::$options[$option])) {
                echo $message . PHP_EOL;
                self::display_help();
                exit(1);
            }
            if (is_bool(self::$options[$option])) {
                echo $message . PHP_EOL;
                self::display_help();
                exit(1);
            }
        }

        $app_key = self::$options['app-key'];
        $path = self::$options['path'];
        $label = self::$options['label'];
        $ip = isset(self::$options['ip']) ? self::$options['ip'] : '';

        try {
            define('API_KEY_PATH', $path);
            define('APP_KEY', $app_key);
            $token = ApiKeyFS::make(
                label: $label,
                ip: $ip,
            );
            // echo "Generated API Key Token:\n";
            echo $token;
            // echo "\n";
            // echo "Key stored in: " . API_KEY_PATH . "\n";
        } catch (Exception $e) {
            echo "Error: " . $e->getMessage() . "\n";
            exit(1);
        }
    }

    public static function handle_check()
    {
        foreach([
            'app-key' => "Error: The --app-key option is required for the check command.",
            'path' => "Error: The --path option is required for the check command.",
            'token' => "Error: The --token option is required for the check command.",
        ] as $option => $message){
            if (!isset(self::$options[$option])) {
                echo $message . PHP_EOL;
                self::display_help();
                exit(1);
            }
            if (is_bool(self::$options[$option])) {
                echo $message . PHP_EOL;
                self::display_help();
                exit(1);
            }
        }

        $app_key = self::$options['app-key'];
        $path = self::$options['path'];
        $token = self::$options['token'];

        try {
            define('API_KEY_PATH', $path);
            define('APP_KEY', $app_key);
            $isValid = ApiKeyFS::check($token);
            echo "API Key Token is " . ($isValid ? "valid" : "invalid") . ".\n";
        } catch (Exception $e) {
            echo "Error: " . $e->getMessage() . "\n";
            exit(1);
        }
    }

    public static function handle_test()
    {
        Key::test(true);
        ApiKeyMemory::test(true);
        ApiKeyFS::test(true);
        CLI::test(true);
        echo('ok' . PHP_EOL);
    }

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
            case 'help':
            default:
                self::display_help();
                break;
        }
        exit(0);
    }

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
            if($debug) echo "Command: $command\n";
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
        if($debug) echo "Command: $command\n";
        exec($command, $output, $return_var);
        if($debug) var_dump(['return_var' => $return_var, 'output' => $output]);
        assert($return_var === 0);
        assert(count($output) === 1);
        $token = $output[0];

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
            if($debug) echo "Command: $command\n";
            exec($command, $output, $return_var);
            if($debug) var_dump(['return_var' => $return_var, 'output' => $output]);
            assert($return_var === 1);
            if($debug) var_dump($output);
            assert($output);
            assert(count($output) > 1);
            assert($output[0] === $message);
        }

        // good check vaild
        $output = [];
        $command = 'php ApiKey.php check --app-key=abc-def-ghi --path=tmp --token=' . $token;
        $return_var = 0;
        if($debug) echo "Command: $command\n";
        exec($command, $output, $return_var);
        if($debug) var_dump(['return_var' => $return_var, 'output' => $output]);
        assert($return_var === 0);
        if($debug) var_dump($output);
        assert(count($output) === 1);
        assert(in_array('API Key Token is valid.', $output));

        // check invalid
        $output = [];
        $return_var = 0;
        $command = 'php ApiKey.php check --app-key=abc-def-ghi --path=tmp --token=xyz';
        if($debug) echo "Command: $command\n";
        exec($command, $output, $return_var);
        if($debug) var_dump(['return_var' => $return_var, 'output' => $output]);
        assert($return_var === 0);
        if($debug) var_dump($output);
        assert(count($output) === 1);
        assert(in_array('API Key Token is invalid.', $output));
    }
}

CLI::run();
?>
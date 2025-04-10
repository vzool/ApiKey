<?php
use Illuminate\Database\Eloquent\Model;

define('KEY_LENGTH', 33);
define('HASH_ALGO', 'sha3-384');
define('HASH_LENGTH', strlen(hash(HASH_ALGO, '')));

class ApiKey extends Model
{
    protected $table = 'sys_api';
    public $timestamps = false;
    protected $fillable = [
        'apikey',
        'ip',
        'label',
    ];

    private function private_key(string $public_key)
    {
        if(strlen($this->apikey) > KEY_LENGTH * 4)
        {
            $y = explode(hash(HASH_ALGO, $public_key), $this->apikey);
            return substr($y[1], 0, KEY_LENGTH * 2);
        }
    }

    private static function randomKey() : string
    {
        do $key = bin2hex(random_bytes(KEY_LENGTH));
        while (self::keyExists($key));

        return $key;
    }

    private static function calculateSharedKey(string $private_key, string $custom_app_key = null) : string
    {
        $app_key = $custom_app_key ?? APP_KEY;

        if(!$app_key) return 'Your application does not has an app key, search for `APP_KEY`!!!';
        if(!in_array(HASH_ALGO, hash_hmac_algos())) return 'Unsupported hash algorithm(' . HASH_ALGO . ')';

        return hash_hmac(HASH_ALGO, $private_key, $app_key, false);
    }

    private static function keyExists(string $key)
    {
        $hash = hash(HASH_ALGO, $key);
        if(strlen($key) >= KEY_LENGTH * 2)
            return self::whereLike('apikey', "%$key%")->orWhereLike('apikey', "%$hash%")->limit(1)->first();
    }

    public static function make(string $label, string $ip = '') : string
    {
        $public_key = self::randomKey();
        $apiKey = new ApiKey([
            'label' => $label . '@' . date('Y-m-d H:i:s'),
            'ip' => $ip,
            'apikey' => uniqid(bin2hex(random_bytes(random_int(1, KEY_LENGTH)))) .
                        hash(HASH_ALGO, $public_key) .
                        self::randomKey() .
                        uniqid(bin2hex(random_bytes(random_int(1, KEY_LENGTH)))),
        ]);

        $apiKey->save();

        return $public_key . self::calculateSharedKey($apiKey->private_key($public_key));
    }

    public static function check(string $token) : bool
    {
        if(strlen($token) !== HASH_LENGTH + (KEY_LENGTH * 2)) return false;

        $public_key = substr($token, 0, -HASH_LENGTH);
        $shared_key = substr($token, -HASH_LENGTH);
        $apiKey = self::keyExists($public_key);

        if(!$apiKey) return false;
        return hash_equals(self::calculateSharedKey($apiKey->private_key($public_key)), $shared_key);
    }
}
?>
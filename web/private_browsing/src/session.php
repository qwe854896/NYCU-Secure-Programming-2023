<?php
$redis = new Redis();
$redis->connect('redis', 6379);
class SessionManager
{
    function __construct($redis, $sessid, $fallback, $encode = 'serialize', $decode = 'unserialize')
    {
        $this->redis = $redis;
        $this->sessid = $sessid;
        $this->encode = $encode;
        $this->decode = $decode;
        $this->fallback = $fallback;
        $this->val = null;
    }

    function get()
    {
        if ($this->val !== null) {
            return $this->val;
        }
        if ($this->redis->exists($this->sessid)) {
            $this->val = ($this->decode)($this->redis->get($this->sessid));
        } else {
            $this->val = ($this->fallback)();
        }
        return $this->val;
    }

    function __destruct()
    {
        global $redis;
        if ($this->val !== null) {
            $redis->set($this->sessid, ($this->encode)($this->val));
        }
    }

    function __call($name, $arguments)
    {
        return $this->get()->{$name}(...$arguments);
    }

    static function load_from_cookie($name, $fallback)
    {
        global $redis;
        if (isset($_COOKIE[$name])) {
            $sessid = $_COOKIE[$name];
        } else {
            $sessid = bin2hex(random_bytes(10));
            setcookie($name, $sessid);
        }
        return new SessionManager($redis, $sessid, $fallback);
    }
}

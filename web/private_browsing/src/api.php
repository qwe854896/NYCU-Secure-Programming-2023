<?php
require_once 'session.php';
class BrowsingSession
{
    function __construct()
    {
        $this->history = [];
    }
    function push($url)
    {
        $this->history[] = $url;
    }
    function get_history()
    {
        return $this->history;
    }
    function clear_history()
    {
        $this->history = [];
    }
    static function new()
    {
        return new BrowsingSession();
    }
}
$session = SessionManager::load_from_cookie('sess_id', ['BrowsingSession', 'new']);
if (!isset($_GET['action'])) {
    die();
}
$action = $_GET['action'];
if ($action === 'view' && isset($_GET['url'])) {
    header("Content-Security-Policy: script-src 'none'");
    $url = $_GET['url'];
    $session->push($url);
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_exec($ch);
    curl_close($ch);
} else if ($action === 'get_history') {
    header('Content-Type: application/json');
    echo json_encode($session->get_history());
} else if ($action === 'clear_history') {
    $session->clear_history();
    echo 'OK';
}


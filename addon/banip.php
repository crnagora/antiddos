#!/usr/bin/php
<?php
/*
 * Title: BanIP plugin.
 * Version: 1.0.0 (8/Nov/2015)
 * Author: Denis.
 * License: GPL.
 * Site: https://montenegro-it.com 
 * Email: contact@montenegro-it.com
 */

@set_time_limit(0);
@error_reporting(E_NONE);
@ini_set('display_errors', 0);
$xml_string = file_get_contents("php://stdin");
$doc = simplexml_load_string($xml_string);
$func = $doc->params->func;
$sok = $doc->params->sok;
$elid = $doc->params->elid;
$user = $doc["user"];
$level = $doc["level"];
define("PLUGIN_PATH", "/usr/local/ispmgr/var/.plugin_banip/");
include_once (PLUGIN_PATH . "function.php");
switch ($func) {

    case "banip.block";
        if ($sok == "ok") {
            $list_ip = explode(", ", $elid);
            BanIp::ban_ip($list_ip, $doc->params->time, $doc->params->subnet);
            $doc->addChild("ok", "ok");
            break;
        }
        $doc->addChild("elid", $elid);
        $time = array(99999999 => 'unlimited', 5 => 5, 10 => 10, 15 => 15, 30 => 30, 60 => 60, 180 => 180, 1440 => 1400);
        $slist = $doc->addChild('slist');
        $slist->addAttribute('name', 'time');
        foreach ($time AS $key => $row) {
            $val = $slist->addChild('val', $row);
            $val->addAttribute('key', $key);
        }
        break;
    case "banip.list";

        $rows = BanIp::get_ban();
        foreach ($rows AS $ip) {
            $data = BanIp::get_countryhostname($ip);
            $param = $doc->addChild('elem');
            $val = $param->addChild('ip', $ip);
            $val = $param->addChild('hostname', $data['hostname']);
            $val = $param->addChild('country', $data['country']);
            $key = $param->addChild('time', BanIp::get_timeban($ip));
        }

        break;
    case "banip.run";
        $rows = BanIp::get_listip();
        foreach ($rows AS $ip => $count) {
            $data = BanIp::get_countryhostname($ip);
            $param = $doc->addChild('elem');
            $val = $param->addChild('ip', $ip);
            $val = $param->addChild('hostname', $data['hostname']);
            $val = $param->addChild('country', $data['country']);
            $key = $param->addChild('count', $count);
        }
        break;

    case "banip.delete";
        $list_ip = explode(", ", $elid);
        BanIp::clear_ban($list_ip);
        $doc->addChild("ok", "ok");
        break;
}
echo $doc->asXML();

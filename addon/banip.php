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
$xml_string = file_get_contents("php://stdin");
$doc = simplexml_load_string($xml_string);
$func = $doc->params->func;
$sok = $doc->params->sok;
$elid = $doc->params->elid;
$user = $doc["user"];
$level = $doc["level"];
define("PLUGIN_PATH", "/usr/local/ispmgr/var/.plugin_banip/");

class BanIp {

    static public function create_task($ip_array, $unban = 0) {
        if ($unban) {
            $flag = "D";
        } else {
            $flag = "I";
        }
        foreach ($ip_array AS $ip) {
            $data = "iptables -" . $flag . " INPUT -s " . $ip . " -j DROP";
            $file = str_replace("/", "_", $ip);
            file_put_contents(PLUGIN_PATH . $flag . "ban." . $file, $data);
            if ($unban == 1) {
                //для удаления флага, если задание не успело отработать
                @unlink(PLUGIN_PATH . "Iban." . $file);
            }
        }
    }

    static public function get_listip() {
        $data = array();
        ob_start();
        exec("netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr", $data);
        $return = ob_get_contents();
        ob_end_clean();
        if ($return == 0) {
            $iplist = array();
            foreach ($data AS $row) {
                $string = explode(" ", trim($row));
                if (isset($string[1]) && filter_var($string[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $iplist[$string[1]] = $string[0];
                }
            }
            return $iplist;
        } else {
            return false;
        }
    }

    static public function store_cache($ip) {
        $list['hostname'] = htmlspecialchars(gethostbyaddr($ip));
        //используется собственный сервис определения географии
        $geo = json_decode(file_get_contents('https://ip2geo.link/json/en/' . $ip));
        $list['country'] = $geo->country;
        if (!$list['country']) {
            $list['country'] = "-";
        }
        $data = $list['hostname'] . ";" . $list['country'];
        file_put_contents(PLUGIN_PATH . "cache." . $ip, $data);
        return $list;
    }

    static public function get_rootip() {
        $data = array();
        exec('/usr/local/ispmgr/sbin/mgrctl -m ispmgr session -o json', $data);
        $rows = json_decode(implode("", $data))->elem;
        $root_ip = array();
        foreach ($rows AS $row) {
            if ($row->name == "root") {
                $root_ip[] = $row->ip;
            }
        }
        return array_unique($root_ip);
    }

    static public function get_serverip() {
        $data = array();
        ob_start();
        exec('ifconfig |grep -v lo | awk \'/flags/ {printf "Interface "$1" "} /inet/ {printf $2" "} /status/ {printf $2"\n"}\'|grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"', $data);
        $return = ob_get_contents();
        ob_end_clean();
        if ($return == 0) {
            return array_unique($data);
        } else {
            return false;
        }
    }

    //убираем из списка на блокировку ip адреса сервера и рута
    static function clean_ip($ip_array) {
        $ip_root = self::get_rootip();
        $ip_server = self::get_serverip();
        $block_ip = array_diff($ip_array, $ip_root);
        return array_diff($block_ip, $ip_server);
    }

    static function clean_subnet($subnet_array) {
        $subnet_root = array();
        $subnet_server = array();

        $ip_root = self::get_rootip();
        $ip_server = self::get_serverip();

        foreach ($ip_root AS $row) {
            $pos = strrpos($row, '.');
            $subnet_root[] = substr($row, 0, $pos + 1) . "0/24";
        }
        $subnet_root_uniq = array_unique($subnet_root);

        foreach ($ip_server AS $row) {
            $pos = strrpos($row, '.');
            $subnet_server[] = substr($row, 0, $pos + 1) . "0/24";
        }
        $subnet_server_uniq = array_unique($subnet_server);

        $block_ip = array_diff($subnet_array, $subnet_root_uniq);
        return array_diff($block_ip, $subnet_server_uniq);
    }

    static public function get_countryhostname($ip) {
        if (is_file(PLUGIN_PATH . "cache." . $ip)) {
            $file = file_get_contents(PLUGIN_PATH . "cache." . $ip);
            $data = explode(";", $file);
            $list['hostname'] = $data[0];
            $list['country'] = $data[1];
            return $list;
        } else {
            return self::store_cache($ip);
        }
    }

    static public function ban_ip($ip_array, $time, $subnet) {
        //удаляем из массива адреса текущих сессий рута и адреса сервера
        $ip_list = self::clean_ip($ip_array);
        $ip = array();
        if ($subnet) {
            foreach ($ip_list AS $row) {
                $pos = strrpos($row, '.');
                $ip[] = substr($row, 0, $pos + 1) . "0/24";
            }
            //удаляем подсети, если рут или сервер попадает в диапазон
            $ip_list = self::clean_subnet(array_unique($ip));
        }
        self::create_task($ip_list);
    }

}

switch ($func) {

    case "banip.block";
        if ($sok == "ok") {
            //блокируем
            //$doc->addChild("ok", "ok");
            
            //BanIp::ban_ip($ip_array, $time, $subnet);
           
            $doc->addChild("debug", json_encode($elid));
            break;
        }
        //$doc->addChild("debug", json_encode($doc));
        // $doc->addChild("hidden",  json_encode($doc));
        $time = array(5, 10, 15, 30, 60, 180, 1440,'unlimited');
        $slist = $doc->addChild('slist');
        $slist->addAttribute('name', 'time');
        foreach ($time AS $row) {
            $val = $slist->addChild('val', $row);
        }
        break;
    case "banip.stat";



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

    case "banip.run2";
        if ($sok == "ok") {
            $doc->addChild("ok", "ok");
            break;
        }
        break;
}
echo $doc->asXML();

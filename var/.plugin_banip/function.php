<?php

/*
 * Title: BanIP plugin.
 * Version: 1.0.1 (9/Nov/2015)
 * Author: Denis.
 * License: GPL.
 * Site: https://montenegro-it.com 
 * Email: contact@montenegro-it.com
 */

class BanIp {

    static public function cron_run() {
        $file = file(PLUGIN_PATH . "base.txt");
        $ip_array = array();
        foreach ($file AS $row) {
            $data = explode(";", trim($row));
            if ($data[1] < time()) {
                $ip_array[] = $data[0];
            }
        }
        self::clear_ban($ip_array);
        $data = self::get_cronparam();
        if ($data) {
            self::start_automat($data);
        }
    }

    static public function get_cronparam() {
        if (is_file(PLUGIN_PATH . "setting.txt")) {
            $data = json_decode(file_get_contents(PLUGIN_PATH . "setting.txt"));
            if (property_exists($data->cron, 0)) {
                return $data;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    static public function send_subscribe($email, $array_ip, $array_connect, $from) {
        $subject = "New Ban from " . php_uname('n');
        $message = $subject . "\n\n";
        if (!$array_ip) {
            return;
        }
        foreach ($array_ip AS $key => $item) {
            $data = self::get_countryhostname($item);
            $message.="ip:" . $item . ", hostname:" . $data['hostname'] . ", country:" . $data['country'] . ", connect:" . $array_connect[$key] . "\n";
        }

        foreach ($email AS $row) {
            unset($headers);
            $headers = array();
            $headers[] = "MIME-Version: 1.0";
            $headers[] = "Content-type: text/plain; charset=utf-8";
            $headers[] = "From: BanIp Plugin <" . $from . ">";
            $headers[] = "Reply-To: BanIp Plugin <" . $from . ">";
            $headers[] = "Subject: {$subject}";
            mail($row, $subject, $message, implode("\r\n", $headers));
        }
    }

    static public function start_automat($data) {
        $list_ip = self::get_listip();
        $block_ip = array();
        $count_connect = array();
        foreach ($list_ip AS $item => $key) {
            $new[] = $item;
        }
        $count = $data->count;
        //удаляем из массива белый список 
        $uniq_ip = array_diff($new, $data->ip);
        // для подстраховки убираем еще раз список интерфейсов, на случай, если задание давно не обновлялось, а ип добавились
        $safe_ip = array_unique(array_diff($uniq_ip, self::get_serverip()));
        foreach ($safe_ip AS $row) {
            if ($count < $list_ip[$row]) {
                $block_ip[] = $row;
                $count_connect[] = $list_ip[$row];
            }
        }
        if ($data->email && $safe_ip) {
            self::send_subscribe($data->email, $block_ip, $count_connect, $data->from->{0});
        }
        $subnet = 0;
        if (property_exists($data->subnet, 0)) {
            $subnet = "on";
        }
        self::ban_ip($block_ip, $data->time, $subnet);
    }

    static public function create_task($ip_array, $time, $unban = 0) {
        if ($unban == 1) {
            $flag = "D";
        } else {
            $flag = "I";
        }
        ob_start();
        foreach ($ip_array AS $ip) {
            exec("iptables -" . $flag . " INPUT -s " . $ip . " -j DROP");
            $file = str_replace("/", "_", $ip);
            if ($unban == 1) {
                @unlink(PLUGIN_PATH . "base_.txt");
                exec("cat " . PLUGIN_PATH . "base.txt | grep -v " . $ip . ">" . PLUGIN_PATH . "base_.txt");
                exec("mv " . PLUGIN_PATH . "base_.txt " . PLUGIN_PATH . "base.txt");
            } else {
                $endtime = time() + ($time * 60);
                file_put_contents(PLUGIN_PATH . "base.txt", $ip . ";" . $endtime . "\n", FILE_APPEND);
            }
        }
        ob_end_clean();
    }

    static public function clear_ban($ip_array) {
        self::create_task($ip_array, 1, 1);
    }

    //получение полного списка блокировок
    static public function get_ban() {
        $data = array();
        exec("iptables -L -n -4 |grep DROP|awk '{print $4}'", $data);
        return $data;
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
        if (!$list['hostname']) {
            $list['hostname'] = "-";
        }
        //используется собственный сервис определения географии
        $geo = json_decode(file_get_contents('https://ip2geo.link/json/en/' . $ip));
        $list['country'] = $geo->country;
        if (!$list['country']) {
            $list['country'] = "-";
        }
        $data = $list['hostname'] . ";" . $list['country'];
        $file = str_replace("/", "_", $ip);
        file_put_contents(PLUGIN_PATH . "cache." . $file, $data);
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

    static public function get_timeban($ip) {
        exec("cat " . PLUGIN_PATH . "base.txt|grep " . $ip . "|sed \"s/" . $ip . ";//\"", $data);
        $minutes = intval(($data[0] - time()) / 60);
        if ($minutes < 0) {
            $minutes = "&#8734;";
        }
        return $minutes;
    }

    static public function get_countryhostname($ip) {
        $file_name = str_replace("/", "_", $ip);
        if (is_file(PLUGIN_PATH . "cache." . $file_name)) {
            $file = file_get_contents(PLUGIN_PATH . "cache." . $file_name);
            $data = explode(";", $file);
            $list['hostname'] = $data[0];
            $list['country'] = $data[1];
            return $list;
        } else {
            return self::store_cache($ip);
        }
    }

    static public function save_setting($ip, $email, $time, $count, $subnet, $cron, $from) {
        $tmp_ip = explode(",", $ip);
        $tmp_email = explode(",", $email);
        $ip_array = array();
        $email_array = array();
        foreach ($tmp_ip AS $row) {
            if (filter_var(trim($row), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ip_array[] = trim($row);
            }
        }
        foreach ($tmp_email AS $row) {
            if (filter_var(trim($row), FILTER_VALIDATE_EMAIL)) {
                $email_array[] = trim($row);
            }
        }
        if (!filter_var($from, FILTER_VALIDATE_EMAIL)) {
            $from = "root@" . php_uname('n');
        }
        $data['ip'] = $ip_array;
        $data['from'] = $from;
        $data['email'] = $email_array;
        $data['time'] = intval($time);
        $data['count'] = intval($count);
        $data['subnet'] = $subnet;
        $data['cron'] = $cron;
        file_put_contents(PLUGIN_PATH . "setting.txt", json_encode($data));
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
        self::create_task($ip_list, $time, 0);
    }

}

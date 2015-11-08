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
    
    static public function create_ban($ip){
          $ban="iptables -I INPUT -s ".$ip." -j DROP";
    }
    static public function delete_ban($ip){
          $ban="iptables -D INPUT -s ".$ip." -j DROP";
    }

    static public function get_listip() {
        $data = "";
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
        $geo = json_decode(file_get_contents('https://ip2geo.link/json/en/' . $ip));
        $list['country'] = $geo->country;
        if (!$list['country']) {
            $list['country'] = "-";
        }
        $data = $list['hostname'] . ";" . $list['country'];
        file_put_contents(PLUGIN_PATH . "cache." . $ip, $data);
        return $list;
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

}

switch ($func) {
    /*
      case "changepasswd.run";
      $mysqli = ChangePassword::connect_db();
      if ($mysqli->connect_errno) {
      $doc->addChild("changepasswd", "SQL ERROR: " . $mysqli->connect_error);
      break;
      }
      if (!$elid[0]) {
      $id = $doc->params->user_id[0];
      } else {
      $id = $elid[0];
      }
      $user_data = ChangePassword::get_userdata($id);
      $project_data = ChangePassword::get_projectdata($user_data->account);
      if ($sok == "ok") {
      if ($user_data->email) {
      ChangePassword::send_mail($user_data->email, $user_data->name, $user_data->lang, $doc->params->user_password[0], $project_data->name, $project_data->domain, $user_data->realname, $project_data->notifyemail);
      ChangePassword::update_password($doc->params->user_hash[0], $id);
      }
      $doc->addChild("ok", "ok");
      break;
      }
      $password = ChangePassword::generate_password();
      $salt = ChangePassword::generate_password();
      $hash = crypt($password, '$1$' . $salt . '$');
      $doc->addChild("changepasswd", "login: " . $user_data->name . "<br />email: " . $user_data->email . "<br />passwd: " . $password . "<input type=\"hidden\" name=\"user_id\"  value=\"" . $elid . "\"><input type=\"hidden\" name=\"user_hash\"  value=\"" . $hash . "\"><input type=\"hidden\" name=\"user_password\"  value=\"" . $password . "\">");
      break; */

    case "banip.block";
        if ($sok == "ok") {
            //$doc->addChild("ok", "ok");
            $doc->addChild("debug",  json_encode($doc));
            break;
        }
        $doc->addChild("debug",  json_encode($doc));
       // $doc->addChild("hidden",  json_encode($doc));
        $time = array(5, 10, 15, 30, 60, 180, 1440);
        $slist = $doc->addChild('slist');
        $slist->addAttribute('name', 'time');
        foreach ($time AS $row) {
            $val = $slist->addChild('val', $row);
        }
       // $doc->addChild("changepasswd", "login: " . $user_data->name . "<br />email: " . $user_data->email . "<br />passwd: " . $password . "<input type=\"hidden\" name=\"user_id\"  value=\"" . $elid . "\"><input type=\"hidden\" name=\"user_hash\"  value=\"" . $hash . "\"><input type=\"hidden\" name=\"user_password\"  value=\"" . $password . "\">");
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

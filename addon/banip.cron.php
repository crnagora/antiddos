#!/usr/bin/php
<?php
/*
 * Title: BanIP plugin.
 * Version: 1.0.2 (16/Feb/2016)
 * Author: Denis.
 * License: GPL.
 * Site: https://montenegro-it.com 
 * Email: contact@montenegro-it.com
 */
@set_time_limit(0);
@error_reporting(E_NONE);
@ini_set('display_errors', 0);
define("PLUGIN_PATH", "/usr/local/ispmgr/var/.plugin_banip/");
include_once (PLUGIN_PATH . "function.php");
BanIp::cron_run();

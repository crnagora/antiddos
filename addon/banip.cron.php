#!/usr/bin/php
<?php
/*
 * Title: BanIP plugin.
 * Version: 1.0.1 (9/Nov/2015)
 * Author: Denis.
 * License: GPL.
 * Site: https://montenegro-it.com 
 * Email: contact@montenegro-it.com
 */
@set_time_limit(0);
@error_reporting(E_NONE);
@ini_set('display_errors', 0);
define("PLUGIN_PATH", "/usr/local/ispmgr/var/.plugin_banip/");
include_once (PLUGIN_PATH."function.php");
BanIp::cron_run();
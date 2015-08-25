<?php

/**
 * Razor Authenticating Resource Server
 * A simple php resource server using REST protocols and JSON data. Uses authentication via user/access api utilising Authorization header for token handshaking
 * Includes many features like data cleansing, flood control (via IP and UA banning) and transparancy of DB type via custom PDO class
 * All authentication is via Authorization header (fallback to cookie 'token' on root) with synchronization of tokens (resends incoming token back out)
 *
 * Copywrite 2014 to Present Day - Paul Smith (aka smiffy6969, razorcms)
 *
 * @author Paul Smith
 * @site ulsmith.net
 * @created Feb 2014
 */

// auto defines
define("RARS_BASE_PATH", str_replace(array("index.php"), "", $_SERVER["SCRIPT_FILENAME"]));
$port = ($_SERVER["SERVER_PORT"] == "80" || $_SERVER["SERVER_PORT"] == "443" ? "" : ":{$_SERVER["SERVER_PORT"]}");
define("RARS_BASE_URL", (isset($_SERVER['https']) && !empty($_SERVER['https']) ? "https://" : "http://").$_SERVER["SERVER_NAME"].$port.str_replace(array("index.php"), "", $_SERVER["SCRIPT_NAME"]));

// security defines
define("RARS_ACCESS_ATTEMPTS", 5); // how many attempts are allowed before lockout, which will appear on the next attempt, (from 1 to 99) [this can be made longer by altering attemps col type]
define("RARS_ACCESS_LOCKOUT", 600); // how many seconds to lockout for after above failures detected
define("RARS_ACCESS_TIMEOUT", 86400); // the amount of time the login will stay alive
define("RARS_ACCESS_BAN_ATTEMPS", 250); // flood control, the amount of atempts an IP can have without a successful login, before being banned completely from logging in, 0 to turn off.
// define("RARS_CLEAN_DATA_ALLOWED_TAGS", "<b><i><h1><h2><h3><h4><h5><h6><p><strong><em><table><thead><tbody><tfooter><tr><th><td><ul><ol><li><a><br><div><header><footer><span><img>"); // will add extra checking to data coming in, checking strings and removing any not listed, comment out to turn off.

// permission defines
// 6 to 10 - access to admin dash
define("SUPER_ADMIN", 10);
define("ADMIN", 9);
define("MANAGER", 8);
// 1 to 5 - no access to admin dash, user levels only
define("USER_1", 1);
define("USER_2", 2);
define("USER_3", 3);
define("USER_4", 4);
define("USER_5", 5);

// PDO SETUP
define('RARS_PDO', ''); // e.g. mysql:host=localhost;dbname=YOUR_DB_NAME
define('RARS_PDO_USER', ''); // e.g. root if running locally
define('RARS_PDO_PASSWORD', ''); // leave empty if running locally in development

// CONFIG FOR SYSTEM
define('RARS_SYSTEM_MODE', 'development'); // 'development' or 'production'
define('RARS_SYSTEM_REGISTRATION_ALLOWED', true); // allow user registrations via registration form
define('RARS_SYSTEM_REGISTRATION_ACTIVATION', true); // allow users to activate new accounts via email link
define('RARS_SYSTEM_BAN', 200); // how many registrations/resets in an hour before banning, 0 to turn off
define('RARS_SYSTEM_FLOOD', 1); // how many registrations/resets in a minute before locking, 0 to turn off
define('RARS_SYSTEM_ACTIVATION_EXPIRE', 1200); // how many seconds before activation expires and they have to resend via registration page (ten minute = 600)
define('RARS_SYSTEM_EMAIL_ADDRESS', ''); // The email address used by the system when notifying system admin
define('RARS_SYSTEM_EMAIL_ADDRESS_NAME', ''); // The name for the user at this email address used by the system when notifying system admin
define('RARS_SYSTEM_PASSWORD_RESET_TIME', 600); // The lockout time for password reset requests
define('RARS_SYSTEM_EMAIL_REGISTRATION', '<html><head><title>**server_name** - Account Registered</title></head><body><h1>Thankyou for Registering your **server_name** Account</h1><p>This email address has registered for an account. If this was not you that did this, please ignore this email and the account will be removed in due course.</p><p>Before you can login to your account, it will need to be activated by administration.</p><p>**server_name**</p></body></html>');
define('RARS_SYSTEM_EMAIL_EMAIL_ACTIVATE', '<html><head><title>**server_name** - Activate Account</title></head><body><h1>Please Activate your **server_name** Account</h1><p>This email address has registered for an account. If this was not you that did this, please ignore this email and the account will be removed in due course.</p><p>In order to login to your account, you will first need to activate it.</p><p>You can activate your account by using the following link, if you have trouble clicking this, try to copy and paste it into the address bar of your web browser directly.</p><a href="**activation_link**">**activation_link**</a><p>**server_name**</p></body></html>');
define('RARS_SYSTEM_EMAIL_MANUAL_ACTIVATE', '<html><head><title>**server_name** - Activate Account</title></head><body><h1>A New User Account Needs Activating on **server_name**</h1><p>**user_email** has registered for an account. This account needs activating manually as email activation is turned off for users in system configuration.</p><p>**server_name**</p></body></html>');
define('RARS_SYSTEM_EMAIL_PASSWORD_REMINDER', '<html><head><title>**server_name** - Password Reset</title></head><body><h1>Reset your **server_name** Account Password</h1><p>This email address (**user_email**) has requested a password reset for the account on **server_name**. If this was not you that requested this, please ignore this email and the password reset will expire in 1 hour.</p><p>If you did request this, then you can reset your password using the link below. If you have trouble clicking this this, try to copy and paste it into the address bar of your web browser directly.</p><a href="**forgot_password_link**">**forgot_password_link**</a></body></html>');

// CONFIG FOR PHP MAILER
define('PHP_MAILER_MAIN_BACKUP_SERVERS', '');  // Specify main and backup SMTP servers seperating with a ;
define('PHP_MAILER_ENABLE_SMTP_AUTHENTICATION', true);  // Specify main and backup SMTP servers
define('PHP_MAILER_NAME', '');  // The name of the mailer as shown by the 'from' name
define('PHP_MAILER_USERNAME', '');  // SMTP username
define('PHP_MAILER_PASSWORD', '');  // SMTP password
define('PHP_MAILER_ENCRYPTION', '');  // Enable TLS encryption, `ssl` also accepted
define('PHP_MAILER_PORT', 587);  // TCP port to connect to

// include error handler
include_once(RARS_BASE_PATH.'library/rars/rars_file_tools.php');
include_once(RARS_BASE_PATH.'library/rars/rars_error_handler.php');
include_once(RARS_BASE_PATH."library/rars/rars_pdo.php");
include_once(RARS_BASE_PATH.'library/rars/rars_api.php');
include_once(RARS_BASE_PATH.'library/phpmailer/class.phpmailer.php');
include_once(RARS_BASE_PATH.'library/phpmailer/class.smtp.php');

// Load error handler
$error = new RarsErrorHandler();
set_error_handler(array($error, 'handle_error'));
set_exception_handler(array($error, 'handle_error'));

// grab method
$method = preg_replace("/[^a-z]/", '', strtolower($_SERVER["REQUEST_METHOD"]));

// check for path data to REST classes and grab them
if (!isset($_GET["path"])) RarsAPI::response(null , null, $code = 404);
$path_parts = explode("/", $_GET["path"]);

$filename = "";
$classname = "";
$found = false;
$c = 0;
foreach ($path_parts as $pp)
{
	$c++;
	$filename.= "/".preg_replace("/[^a-z0-9_-]/", '', strtolower($pp));
	$classname.= ucfirst(preg_replace("/[^a-z0-9_]/", '', strtolower($pp)));
	if (is_file(RARS_BASE_PATH."api{$filename}.php"))
	{
		$found = true;
		break;
	}
}

if (!$found) RarsAPI::response(null , null, $code = 404);

// grab any data or id's data
if ($method == "delete" || $method == "get")
{
	$data = (count($path_parts) == $c + 1 ? RarsAPI::clean_data($path_parts[$c]) : (count($path_parts) == $c + 2 ? RarsAPI::clean_data($path_parts[$c + 1]) : null));
}
else $data = RarsAPI::clean_data((!empty($_POST) ? $_POST : json_decode(file_get_contents('php://input'))));

// load resource or throw error
include(RARS_BASE_PATH."api{$filename}.php");
$resource = new $classname();
if (!method_exists($resource, $method)) RarsAPI::response(null, null, $code = 405);
$response = $resource->$method($data);

/* EOF */

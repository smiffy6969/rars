<?php if (!defined("RARS_BASE_PATH")) die("No direct script access to this content");

/**
 * razorCMS FBCMS
 *
 * Copywrite 2014 to Present Day - Paul Smith (aka smiffy6969, razorcms)
 *
 * @author Paul Smith
 * @site ulsmith.net
 * @created Feb 2014
 */

// RarsAPI class
class RarsAPI
{
	private $backtrace = null;
	// public $user = null;
	public $rars_db = null;

	function __construct()
	{
		$this->rars_db = new RarsPDO();
	}

	public static function clean_data($data)
	{
		if (is_object($data) || is_array($data))
		{
			$data_array = array();
			foreach ($data as $key => $value)
			{
				$clean_key = preg_replace("/[|`<>?;'\"]/", '', (string) $key);
				$data_array[$clean_key] = RarsAPI::clean_data($value);
			}
			return $data_array;
		}
		elseif (is_string($data))
		{
			// we do not have to do much checking here, the db class protects itself against harmfull chars
			if (defined("RARS_CLEAN_DATA_ALLOWED_TAGS")) return strip_tags($data, RARS_CLEAN_DATA_ALLOWED_TAGS);
			else return $data;
		}
		elseif (is_bool($data) || is_int($data) || is_float($data)) return $data;
		else return null;
	}

	// clean output data of slashes
	public static function clean_output($data)
	{
		if (is_object($data) || is_array($data))
		{
			$data_array = array();
			foreach ($data as $key => $value)
			{
				$clean_key = preg_replace("/[|`<>?;'\"]/", '', (string) $key);
				$data_array[$clean_key] = RarsAPI::clean_output($value);
			}
			return $data_array;
		}
		elseif (is_string($data)) return stripcslashes($data);
		elseif (is_bool($data) || is_int($data) || is_float($data)) return $data;
		else return null;
	}

	// function to obscure passwords //
	public static function create_hash($inText, $saltHash=NULL, $mode='sha1'){
		// check if hash function available, else fallback to sha1 //
		$hashOK = false;
		if(function_exists('hash')) {
		$hashOK = true;
		}
		// hash the text //
		if($hashOK) {
			$textHash = hash($mode, $inText);
		} else {
			$textHash = sha1($inText);
		}
		// set where salt will appear in hash //
		$saltStart = strlen($inText);
		// if no salt given create random one //
		if($saltHash == NULL) {
			if($hashOK) {
				$saltHash = hash($mode, uniqid(rand(), true));
			} else {
				$saltHash = sha1(uniqid(rand(), true));
			}
		}
		// add salt into text hash at pass length position and hash it //
		if($saltStart > 0 && $saltStart < strlen($saltHash)) {
			$textHashStart = substr($textHash,0,$saltStart);
			$textHashEnd = substr($textHash,$saltStart,strlen($saltHash));
			if($hashOK) {
				$outHash = hash($mode, $textHashEnd.$saltHash.$textHashStart);
			} else {
				$outHash = sha1($textHashEnd.$saltHash.$textHashStart);
			}
		} elseif($saltStart > (strlen($saltHash)-1)) {
			if($hashOK) {
				$outHash = hash($mode, $textHash.$saltHash);
			} else {
				$outHash = sha1($textHash.$saltHash);
			}
		} else {
			if($hashOK) {
				$outHash = hash($mode, $saltHash.$textHash);
			} else {
				$outHash = sha1($saltHash.$textHash);
			}
		}
		// put salt at front of hash //
		$output = $saltHash.$outHash;
		return $output;
	}

	public function email($to, $to_name, $subject, $message, $alt_message = null)
	{
		// config the mailer object
		$mail = new PHPMailer;
		$mail->isSMTP();
		$mail->Host = PHP_MAILER_MAIN_BACKUP_SERVERS;
		$mail->SMTPAuth = PHP_MAILER_ENABLE_SMTP_AUTHENTICATION;
		$mail->Username = PHP_MAILER_USERNAME;
		$mail->Password = PHP_MAILER_PASSWORD;
		$mail->SMTPSecure = PHP_MAILER_ENCRYPTION;
		$mail->Port = PHP_MAILER_PORT;

		// build email
		$mail->From = PHP_MAILER_USERNAME;
		$mail->FromName = PHP_MAILER_NAME;
		$mail->addAddress($to, $to_name);
		$mail->isHTML(true);
		$mail->Subject = $subject;
		$mail->Body    = $message;
		if (!empty($alt_message)) $mail->AltBody = $alt_message;
		$result = $mail->send();

		if (!$result) RarsErrorHandler::log_error(array('error' => 'Email send error', 'string' => $mail->ErrorInfo));
		return $result;
	}

	public static function response($data, $type = null, $code = null)
	{
		switch ($code)
		{
			// 2XX Success
			case 201:
				header("HTTP/1.0 201 Created");
			break;
			case 202:
				header("HTTP/1.0 202 Accepted");
			break;
			case 204:
				header("HTTP/1.0 204 No Content");
			break;
			case 205:
				header("HTTP/1.0 205 Reset Content");
			break;
			case 206:
				header("HTTP/1.0 206 Partial Content");
			break;

			// 4XX Client Error
			case 400:
				$data = array("error" => "HTTP/1.0 400 Bad Request", "response" => $data);
				header($data["error"]);
			break;
			case 401:
				$data = array("error" => "HTTP/1.0 401 Unauthorized", "response" => $data);
				header($data["error"]);
			break;
			case 402:
				$data = array("error" => "HTTP/1.0 402 Payment Required", "response" => $data);
				header($data["error"]);
			break;
			case 403:
				$data = array("error" => "HTTP/1.0 403 Forbidden", "response" => $data);
				header($data["error"]);
			break;
			case 404:
				$data = array("error" => "HTTP/1.0 404 Not Found", "response" => $data);
				header($data["error"]);
			break;
			case 405:
				$data = array("error" => "HTTP/1.0 405 Method Not Allowed", "response" => $data);
				header($data["error"]);
			break;
			case 406:
				$data = array("error" => "HTTP/1.0 406 Not Acceptable", "response" => $data);
				header($data["error"]);
			break;
			case 407:
				$data = array("error" => "HTTP/1.0 407 Proxy Authentication Required", "response" => $data);
				header($data["error"]);
			break;
			case 408:
				$data = array("error" => "HTTP/1.0 408 Request Timeout", "response" => $data);
				header($data["error"]);
			break;
			case 409:
				$data = array("error" => "HTTP/1.0 409 Conflict", "response" => $data);
				header($data["error"]);
			break;

			//5XX Server Error
			case 500:
				$data = array("error" => "HTTP/1.0 500 Internal Server Error", "response" => $data);
				header($data["error"]);
			break;
			case 501:
				$data = array("error" => "HTTP/1.0 501 Not Implemented", "response" => $data);
				header($data["error"]);
			break;
		}

		$token = (isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : (isset($_COOKIE['token']) ? $_COOKIE['token'] : null )));
		if ($token) header("Authorization:{$token}"); // return any tokens sent in

		if ($type == null || !method_exists("RarsAPI", $type)) RarsAPI::raw($data);
		else RarsAPI::$type($data);
	}

	private static function raw($data)
	{
		$data = RarsAPI::clean_output($data);

		header("Cache-Control: no-cache, no-store, must-revalidate");
		echo (isset($data["error"]) ? $data["error"].(empty($data["response"]) ? "" : " with response: ".$data["response"]) : var_export($data, true));
		exit();
	}

	private static function json($data)
	{
		$data = RarsAPI::clean_output($data);

		header("Content-type: application/json");
		header("Cache-Control: no-cache, no-store, must-revalidate");
		echo json_encode($data);
		exit();
	}

	private static function xml($data)
	{
		$data = RarsAPI::clean_output($data);

		// build sitemap index
		$output = '<?xml version="1.0" encoding="UTF-8"?>';
		$output.= $data;

		header('Content-Type: application/xml; charset=utf-8');
		header("Cache-Control: no-cache, no-store, must-revalidate");
		echo $output;
		exit();
	}
}
/* EOF */

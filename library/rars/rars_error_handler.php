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

class RarsErrorHandler {
	/**
	 * Handle Error
	 * Handles all errors and exceptions
	 *
	 * @param string $error_type Type of error
	 * @param string $error_string Actual error string
	 * @param string $error_file File error happened in
	 * @param string $error_line Line error happened on
	 * @return bool True on pass
	 */
	public function handle_error($error_type = "", $error_string = "", $error_file = "", $error_line = "")
	{
		$error_group = 'log'; // changeing log type to chrome php
		$type = '';

		if (is_int($error_type))
		{
			switch ($error_type)
			{
				case E_ERROR: // 1 //
					$error_group = 'error';
					$type = 'E_ERROR';
				break;
				case E_WARNING: // 2 //
					$error_group = 'warn';
					$type = 'E_WARNING';
				break;
				case E_PARSE: // 4 //
					$type = 'E_PARSE';
				break;
				case E_NOTICE: // 8 //
					$type = 'E_NOTICE';
				break;
				case E_CORE_ERROR: // 16 //
					$error_group = 'error';
					$type = 'E_CORE_ERROR';
				break;
				case E_CORE_WARNING: // 32 //
					$error_group = 'warn';
					$type = 'E_CORE_WARNING';
				break;
				case E_CORE_ERROR: // 64 //
					$error_group = 'error';
					$type = 'E_COMPILE_ERROR';
				break;
				case E_CORE_WARNING: // 128 //
					$error_group = 'warn';
					$type = 'E_COMPILE_WARNING';
				break;
				case E_USER_ERROR: // 256 //
					$error_group = 'error';
					$type = 'E_USER_ERROR';
				break;
				case E_USER_WARNING: // 512 //
					$error_group = 'warn';
					$type = 'E_USER_WARNING';
				break;
				case E_USER_NOTICE: // 1024 //
					$type = 'E_USER_NOTICE';
				break;
				case E_STRICT: // 2048 //
					$type = 'E_STRICT';
				break;
				case E_RECOVERABLE_ERROR: // 4096 //
					$error_group = 'error';
					$type = 'E_RECOVERABLE_ERROR';
				break;
				case E_DEPRECATED: // 8192 //
					$type = 'E_DEPRECATED';
				break;
				case E_USER_DEPRECATED: // 16384 //
					$type = 'E_USER_DEPRECATED';
				break;
			}
		}

		$error['error'] = $type;
		$error['type'] = $error_type;
		$error['file'] = $error_file;
		$error['line'] = $error_line;
		$error['string'] = $error_string;
		$error['group'] = $error_group;

		// log error
		self::log_error($error);

		// log error to chromephp
		self::chrome_php($error, false);

		// display error on screen
		self::display_error($error);

		if (class_exists("RarsAPI")) RarsAPI::response(null, null, 500);
		else return true;
	}


	/**
	 * Log Error
	 * Log the error to log file
	 *
	 * @param array $error Error data array
	 * @param string $log_book The log book to write to
	 * @return bool False on fail
	 */
	public static function log_error($error, $log_book = 'rars-error-log')
	{
		if (empty($error)) return false;

		// get file contents
		$log = array();
		if (is_file(RARS_BASE_PATH."storage/log/{$log_book}.php"))
		{
			$log = RarsFileTools::read_file_contents(RARS_BASE_PATH."storage/log/{$log_book}.php", 'array');
		}

		// set date time
		$date_time = @date('d m Y - h:i:s', time());

		$entry = "<?php /* [{$date_time}] [{$error['error']}]";
		$entry.= (isset($error['type']) ? " [type: {$error['type']}]" : "");
		$entry.= (isset($error['file']) ? " [file: {$error['file']}]" : "");
		$entry.= (isset($error['line']) ? " [line: {$error['line']}]" : "");
		$entry.= " [message: {$error['string']}] */ ?>\n\r";
		$log[] = $entry;

		if (count($log) > 100)
		{
			array_shift($log);
		}

		$log_string = implode('',$log);
		if (!is_dir(RARS_BASE_PATH.'storage/log')) mkdir(RARS_BASE_PATH.'storage/log');
		RarsFileTools::write_file_contents(RARS_BASE_PATH."storage/log/{$log_book}.php", $log_string);
	}


	/**
	 * Chrome PHP
	 * Allows errors to be logged to chromePHP, also allows debugging to chromePHP directly
	 *
	 * @param array $error Error data array
	 * @param bool $debug Optional debug option set to true, set false to output directly to chromePHP
	 */
	public static function chrome_php($error, $debug = true)
	{
		include_once(RARS_BASE_PATH.'library/chromephp/chromephp.php');

		// set date time
		$date_time = @date('d m Y - h:i:s', time());

		// log error to chromephp
		if ($debug === false)
		{
			if (RARS_SYSTEM_MODE == "development")
			{
				$message = "rars error handler >> [{$date_time}] [{$error['error']}] [type: {$error['type']}] [file: {$error['file']}] [line: {$error['line']}] [message: {$error['string']}]";
				ChromePhp::$error['group']($message);
			}
			return;
		}

		// log debug data to chromephp
		ChromePhp::log("RARS DEBUG");
		ChromePhp::log($error);
	}


	/**
	 * Display Error
	 * Shows the error on screen
	 *
	 * @param array $error Error data array
	 * @return bool False on fail
	 */
	public static function display_error($error)
	{
		if (empty($error) || RARS_SYSTEM_MODE == "production") return false;

		// set date time
		$date_time = @date('d m Y - h:i:s', time());

		echo "rars error handler >> [{$date_time}] [{$error['error']}] [type: {$error['type']}] [file: {$error['file']}] [line: {$error['line']}] [message: {$error['string']}]";
	}
}

/* EOF */

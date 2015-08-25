<?php if (!defined("RARS_BASE_PATH")) die("No direct script access to this content");

/**
 * Razor Authenticating Resource Server
 * Copywrite 2014 to Present Day - Paul Smith (aka smiffy6969, razorcms)
 *
 * @author Paul Smith
 * @site ulsmith.net
 * @created Feb 2014
 *
 * Requires the following tables and columns (rename at your peril, just ensure you change in code below, ctrl-d is your friend)
 *
 * Table: banned
 * Column: id (int PK AI)
 * Column: ip_address (string 20)
 * Column: user_agent (string 255)
 * Column: created (timestamp CURRENT_TIMESTAMP)
 *
 * Table: user
 * Column: id (int PK AI)
 * Column: active (bool or tinyint(1))
 * Column: name (string 255, does first and last name together to stop issues with name conventions around world)
 * Column: email_address (string 255)
 * Column: password (string 255)
 * Column: access_level (int 2)
 * Column: last_logged_in (timestamp yyyy-mm-dd hh:mm:ss)
 * Column: last_accessed (timestamp yyyy-mm-dd hh:mm:ss)
 * Column: failed_attempts (int)
 * Column: lock_until (timestamp yyyy-mm-dd hh:mm:ss)
 * Column: ip_address (string 20)
 * Column: created (timestamp CURRENT_TIMESTAMP)
 * Column: activate_token (string 255)
 * Column: reminder_token (string 255)
 * Column: reminder_time (timestamp)
 */

class UserReset extends RarsAPI
{
	function __construct()
	{
		// REQUIRED IN EXTENDED CLASS TO LOAD DEFAULTS
		parent::__construct();
	}

	/**
	 * REST POST - Send a password reset email to the user so they can reset their password using the link supplied
	 * @param $data The login data via rest request containing 'username', note username contains the email_address
	 * @return Message + Email response.
	 */
	public function post($data)
	{
		// no email
		if (empty($data['username'])) $this->response('User not found', 'json', 404);

		// try find user
		$user = $this->rars_db->get_first('user', '*', array('email_address' => $data['username']));
		if (empty($user)) $this->response('User not found', 'json', 404);
		if ($user['reminder_time'] > time() - RARS_SYSTEM_PASSWORD_RESET_TIME) $this->response('Only one password request allowed per hour', 'json', 401);

		/* Match found, attempts good, carry on */

		// now we will store token and send it via email
		$user_agent = $_SERVER['HTTP_USER_AGENT'];
		$ip_address = $_SERVER['REMOTE_ADDR'];
		$pass_hash = $user['password'];
		$reminder_time = date('Y-m-d H:i:s', time());
		$reminder_token = sha1($reminder_time.$user_agent.$ip_address.$pass_hash);

		// set new reminder
		$row = array('reminder_token' => $reminder_token, 'reminder_time' => $reminder_time);
		$this->rars_db->edit_data('user', $row, array('id' => $user['id']));

		// email user pasword reset email
		$reminder_link = RARS_BASE_URL."../#password-reset?token={$reminder_token}_{$user['id']}";

		// email text replacement
		$search = array(
			'**server_name**',
			'**user_email**',
			'**forgot_password_link**'
		);

		$replace = array(
			$_SERVER['SERVER_NAME'],
			$user['email_address'],
			$reminder_link
		);

		$message = str_replace($search, $replace, RARS_SYSTEM_EMAIL_PASSWORD_REMINDER);
		$result = $this->email($user['email_address'], $user['name'], "{$_SERVER['SERVER_NAME']} Account Password Reset", $message);
		if (!$result) throw new Exception('Could not send email, please contact administrator');
		$this->response('Password reset created, please check your email', 'json');
	}

	/**
	 * REST PUT - Update the password from a password reset, requires reset token
	 * @param $data The login data via rest request containing 'username', note username contains the email_address
	 * @return Message + Email response.
	 */
	public function put($data)
	{
		if (!isset($data['password'], $data['token'], $data['email'], $data['human']) || empty($data['password']) || empty($data['token'])) $this->response('User not found', 'json', 404);
		if (!empty($data['human'])) $this->response("Only humans can register", "json", 406);

		// check if already banned
		if (RARS_SYSTEM_BAN > 0)
		{
			// find banned rows
			$banned = $this->rars_db->get_first('banned', '*', array('ip_address' => $_SERVER["REMOTE_ADDR"], 'user_agent' => $_SERVER["HTTP_USER_AGENT"]));
			if (!empty($banned)) $this->response('Password reset failed: ip banned', 'json', 401);
		}

		// extract id
		$parts = explode('_', $data['token']);
		if (count($parts) != 2) $this->response('Token invalid', 'json', 404);
		$id = $parts[1];
		$token = $parts[0];

		// get user and validate
		$user = $this->rars_db->get_first('user', '*', array('id' => $id));
		if (empty($user) || $user['email_address'] != $data['email']) $this->response('User not found', 'json', 404);
		if ($user['reminder_token'] !== $token || strtotime($user["reminder_time"]) + RARS_SYSTEM_PASSWORD_RESET_TIME < time()) $this->response('Could not update password', 'json', 401);

		/* All OK, user found, validated and within time, allow update of password. Also we do not need to implement banning here as tokens only valid for an hour */

		// if this is your account, alter name and email
		$row = array("password" => $this->create_hash($data['password']), "reminder_token" => "");
		$this->rars_db->edit_data('user', $row, array('id' => $id));
		$this->response('Password reset, please log in with new password', 'json');
	}
}

/* EOF */

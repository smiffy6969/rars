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
 * Column: id (int PK AI NN)
 * Column: ip_address (string 20 NN)
 * Column: user_agent (string 255 NN)
 * Column: created (timestamp NN default = CURRENT_TIMESTAMP)
 *
 * Table: user
 * Column: id (int PK AI NN)
 * Column: active (tinyint(1) NN default = 0)
 * Column: name (string 255 NN, does first and last name together to stop issues with name conventions around world)
 * Column: email_address (string 255 NN)
 * Column: password (string 255 NN)
 * Column: access_level (tinyint(1) NN default 0)
 * Column: last_logged_in (timestamp yyyy-mm-dd hh:mm:ss)
 * Column: last_accessed (timestamp yyyy-mm-dd hh:mm:ss)
 * Column: failed_attempts (int NN default 0)
 * Column: lock_until (timestamp yyyy-mm-dd hh:mm:ss)
 * Column: ip_address (string 20 NN)
 * Column: activate_token (string 255)
 * Column: created (timestamp NN default = CURRENT_TIMESTAMP)
 * Column: activate_token (string 255)
 * Column: reminder_token (string 255)
 * Column: reminder_time (timestamp)
 */

class UserProfile extends RarsAPI
{
	private $user = null;

	function __construct()
	{
		// REQUIRED IN EXTENDED CLASS TO LOAD DEFAULTS
		parent::__construct();

		include_once(RARS_BASE_PATH.'api/user/access.php');
		$access = new UserAccess();
		$this->user = $access->check();
	}

	/**
	 * REST POST - Change a users profile details, this requires a table called 'user' and 'banned' in your db with various fields as per header
	 * @param $data The data to update the users profile with
	 * @return message as complete or error
	 */
	public function post($data)
	{
		// check we have a logged in user
		if ((int) $this->user['access_level'] < 1) $this->response('You do not have permission to perform that action', 'json', 401);
		if (empty($data)) $this->response('Invalid data', 'json', 400);
		if ($this->user["id"] != $data["id"]) $this->response('You do not have permission to alter that account', 'json', 401);

		// check password
		$user_password_check = $this->rars_db->get_first('user', '*', array('id' => $this->user['id']));
		if (!$user_password_check) $this->response('Permission denied', 'json', 401);
		if (RarsAPI::create_hash($data['password'], substr($user_password_check['password'], 0, (strlen($user_password_check['password']) / 2)), 'sha1') !== $user_password_check['password']) $this->response('Permission denied, password incorrect', 'json', 401);

		// check if we are doing a deletion
		if (isset($data['delete']) && $data['delete'] == 1)
		{
			$this->rars_db->delete_data('user', array('id' => $this->user['id']));
			$this->response('Account deleted, logging you out...', 'json', 202); // reset content as deleted
		}

		// check email is unique if changed
		if ($data["email_address"] != $this->user["email_address"])
		{
			$user_email_check = $this->rars_db->get_first('user', '*', array('email_address' => $data["email_address"]));
			if (!empty($user)) $this->response('Email address already registered', 'json', 409);
		}

		// if this is your account, alter name and email
		$row = array(
			"name" => $data["name"],
			"email_address" => $data["email_address"]
		);

		if (isset($data["new_password"]) && !empty($data["new_password"])) $row["password"] = $this->create_hash($data["new_password"]);

		$this->rars_db->edit_data('user', $row, array('id' => $this->user['id']));
		if (isset($row["password"])) $this->response('User account updated, logging you out...', 'json', 202);
		else $this->response('User account updated', 'json');
	}
}

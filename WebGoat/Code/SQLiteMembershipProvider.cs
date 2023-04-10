using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Data;
using Mono.Data.Sqlite;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Security;

namespace TechInfoSystems.Data.SQLite
{
	public sealed class SQLiteMembershipProvider : MembershipProvider
	{
		#region Private Fields

		private const string _httpTransactionId = "SQLiteTran";
		private const int NEW_PASSWORD_LENGTH = 8;
		private const string APP_TB_NAME = "[aspnet_Applications]";
		private const string USER_TB_NAME = "[aspnet_Users]";
		private const string USERS_IN_ROLES_TB_NAME = "[aspnet_UsersInRoles]";
		private const string PROFILE_TB_NAME = "[aspnet_Profile]";
		private const int MAX_APPLICATION_NAME_LENGTH = 256;
		private const int MAX_USERNAME_LENGTH = 256;
		private const int MAX_PASSWORD_LENGTH = 128;
		private const int MAX_PASSWORD_ANSWER_LENGTH = 128;
		private const int MAX_EMAIL_LENGTH = 256;
		private const int MAX_PASSWORD_QUESTION_LENGTH = 256;
		private static string _connectionString;
		private static string _applicationName;
		private static string _applicationId;
		private static bool _enablePasswordReset;
		private static bool _enablePasswordRetrieval;
		private static bool _requiresQuestionAndAnswer;
		private static bool _requiresUniqueEmail;
		private static int _maxInvalidPasswordAttempts;
		private static int _passwordAttemptWindow;
		private static MembershipPasswordFormat _passwordFormat;
		private static int _minRequiredNonAlphanumericCharacters;
		private static int _minRequiredPasswordLength;
		private static string _passwordStrengthRegularExpression;
		private static readonly DateTime _minDate = DateTime.ParseExact ("01/01/1753", "d", CultureInfo.InvariantCulture);

		#endregion

		#region Public Properties

		public override string ApplicationName {
			get { return _applicationName; }
			set {
				if (value.Length > MAX_APPLICATION_NAME_LENGTH)
					throw new ProviderException (String.Format ("SQLiteMembershipProvider error: applicationName must be less than or equal to {0} characters.", MAX_APPLICATION_NAME_LENGTH));

				_applicationName = value;
				_applicationId = GetApplicationId (_applicationName);
			}
		}

		public override bool EnablePasswordReset {
			get { return _enablePasswordReset; }
		}

		public override bool EnablePasswordRetrieval {
			get { return _enablePasswordRetrieval; }
		}

		public override bool RequiresQuestionAndAnswer {
			get { return _requiresQuestionAndAnswer; }
		}

		public override bool RequiresUniqueEmail {
			get { return _requiresUniqueEmail; }
		}

		public override int MaxInvalidPasswordAttempts {
			get { return _maxInvalidPasswordAttempts; }
		}

		public override int PasswordAttemptWindow {
			get { return _passwordAttemptWindow; }
		}

		public override MembershipPasswordFormat PasswordFormat {
			get { return _passwordFormat; }
		}

		public override int MinRequiredNonAlphanumericCharacters {
			get { return _minRequiredNonAlphanumericCharacters; }
		}

		public override int MinRequiredPasswordLength {
			get { return _minRequiredPasswordLength; }
		}

		public override string PasswordStrengthRegularExpression {
			get { return _passwordStrengthRegularExpression; }
		}

		#endregion

		#region Public Methods

		public override void Initialize (string name, NameValueCollection config)
		{
			if (config == null)
				throw new ArgumentNullException ("config");

			if (string.IsNullOrEmpty (name))
				name = "SQLiteMembershipProvider";

			if (String.IsNullOrEmpty (config ["description"])) {
				config.Remove ("description");
				config.Add ("description", "SQLite Membership provider");
			}

			base.Initialize (name, config);

			_maxInvalidPasswordAttempts = Convert.ToInt32 (GetConfigValue (config ["maxInvalidPasswordAttempts"], "50"));
			_passwordAttemptWindow = Convert.ToInt32 (GetConfigValue (config ["passwordAttemptWindow"], "10"));
			_minRequiredNonAlphanumericCharacters = Convert.ToInt32 (GetConfigValue (config ["minRequiredNonalphanumericCharacters"], "1"));
			_minRequiredPasswordLength = Convert.ToInt32 (GetConfigValue (config ["minRequiredPasswordLength"], "7"));
			_passwordStrengthRegularExpression = Convert.ToString (GetConfigValue (config ["passwordStrengthRegularExpression"], ""));
			_enablePasswordReset = Convert.ToBoolean (GetConfigValue (config ["enablePasswordReset"], "true"));
			_enablePasswordRetrieval = Convert.ToBoolean (GetConfigValue (config ["enablePasswordRetrieval"], "false"));
			_requiresQuestionAndAnswer = Convert.ToBoolean (GetConfigValue (config ["requiresQuestionAndAnswer"], "false"));
			_requiresUniqueEmail = Convert.ToBoolean (GetConfigValue (config ["requiresUniqueEmail"], "false"));

			ValidatePwdStrengthRegularExpression ();

			if (_minRequiredNonAlphanumericCharacters > _minRequiredPasswordLength) {
				throw new System.Web.HttpException ("SQLiteMembershipProvider configuration error: minRequiredNonalphanumericCharacters can not be greater than minRequiredPasswordLength. Check the web configuration file (web.config).");
			}

			string temp_format = config ["passwordFormat"];
			if (temp_format == null) {
				temp_format = "Hashed";
			}

			switch (temp_format) {
			case "Clear":
				_passwordFormat = MembershipPasswordFormat.Clear;
				break;
			case "Hashed":
				_passwordFormat = MembershipPasswordFormat.Hashed;
				break;
			case "Encrypted":
				_passwordFormat = MembershipPasswordFormat.Encrypted;
				break;
			default:
				throw new ProviderException ("Password format not supported.");
			}

			if ((PasswordFormat == MembershipPasswordFormat.Hashed) && EnablePasswordRetrieval) {
				throw new ProviderException ("SQLiteMembershipProvider configuration error: enablePasswordRetrieval can not be set to true when passwordFormat is set to \"Hashed\". Check the web configuration file (web.config).");
			}

			ConnectionStringSettings ConnectionStringSettings = ConfigurationManager.ConnectionStrings [config ["connectionStringName"]];

			if (ConnectionStringSettings == null || ConnectionStringSettings.ConnectionString == null || ConnectionStringSettings.ConnectionString.Trim ().Length == 0) {
				throw new ProviderException ("Connection string is empty for SQLiteMembershipProvider. Check the web configuration file (web.config).");
			}

			_connectionString = ConnectionStringSettings.ConnectionString;

			if (config ["applicationName"] == null || config ["applicationName"].Trim () == "") {
				this.ApplicationName = System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath;
			} else {
				this.ApplicationName = config ["applicationName"];
			}

			config.Remove ("connectionStringName");
			config.Remove ("enablePasswordRetrieval");
			config.Remove ("enablePasswordReset");
			config.Remove ("requiresQuestionAndAnswer");
			config.Remove ("applicationName");
			config.Remove ("requiresUniqueEmail");
			config.Remove ("maxInvalidPasswordAttempts");
			config.Remove ("passwordAttemptWindow");
			config.Remove ("commandTimeout");
			config.Remove ("passwordFormat");
			config.Remove ("name");
			config.Remove ("minRequiredPasswordLength");
			config.Remove ("minRequiredNonalphanumericCharacters");
			config.Remove ("passwordStrengthRegularExpression");

			if (config.Count > 0) {
				string key = config.GetKey (0);
				if (!string.IsNullOrEmpty (key)) {
					throw new ProviderException (String.Concat ("SQLiteMembershipProvider configuration error: Unrecognized attribute: ", key));
				}
			}

			VerifyApplication ();
		}

		public override bool ChangePassword (string username, string oldPassword, string newPassword)
		{
			SecUtility.CheckParameter (ref username, true, true, true, MAX_USERNAME_LENGTH, "username");
			SecUtility.CheckParameter (ref oldPassword, true, true, false, MAX_PASSWORD_LENGTH, "oldPassword");
			SecUtility.CheckParameter (ref newPassword, true, true, false, MAX_PASSWORD_LENGTH, "newPassword");

			string salt;
			MembershipPasswordFormat passwordFormat;
			if (!CheckPassword (username, oldPassword, true, out salt, out passwordFormat))
				return false;

			if (newPassword.Length < this.MinRequiredPasswordLength) {
				throw new ArgumentException (String.Format (CultureInfo.CurrentCulture, "The password must be at least {0} characters.", this.MinRequiredPasswordLength));
			}

			int numNonAlphaNumericChars = 0;
			for (int i = 0; i < newPassword.Length; i++) {
				if (!char.IsLetterOrDigit (newPassword, i)) {
					numNonAlphaNumericChars++;
				}
			}
			if (numNonAlphaNumericChars < this.MinRequiredNonAlphanumericCharacters) {
				throw new ArgumentException (String.Format (CultureInfo.CurrentCulture, "There must be at least {0} non alpha numeric characters.", this.MinRequiredNonAlphanumericCharacters));
			}
			if ((this.PasswordStrengthRegularExpression.Length > 0) && !Regex.IsMatch (newPassword, this.PasswordStrengthRegularExpression)) {
				throw new ArgumentException ("The password does not match the regular expression in the config file.");
			}

			string encodedPwd = EncodePassword (newPassword, passwordFormat, salt);
			if (encodedPwd.Length > MAX_PASSWORD_LENGTH) {
				throw new ArgumentException (String.Format (CultureInfo.CurrentCulture, "The password is too long: it must not exceed {0} chars after encrypting.", MAX_PASSWORD_LENGTH));
			}

			ValidatePasswordEventArgs args = new ValidatePasswordEventArgs (username, newPassword, false);

			OnValidatingPassword (args);

			if (args.Cancel) {
				if (args.FailureInformation != null)
					throw args.FailureInformation;
				else
					throw new MembershipPasswordException ("Change password canceled due to new password validation failure.");
			}

			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "UPDATE " + USER_TB_NAME +
														" SET Password = $Password, LastPasswordChangedDate = $LastPasswordChangedDate " +
														" WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue ("$Password", encodedPwd);
					cmd.Parameters.AddWithValue ("$LastPasswordChangedDate", DateTime.UtcNow);
					cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					return (cmd.ExecuteNonQuery () > 0);
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override bool ChangePasswordQuestionAndAnswer (string username, string password, string newPasswordQuestion, string newPasswordAnswer)
		{
			SecUtility.CheckParameter (ref username, true, true, true, MAX_USERNAME_LENGTH, "username");
			SecUtility.CheckParameter (ref password, true, true, false, MAX_PASSWORD_LENGTH, "password");

			string salt, encodedPasswordAnswer;
			MembershipPasswordFormat passwordFormat;
			if (!CheckPassword (username, password, true, out salt, out passwordFormat))
				return false;

			SecUtility.CheckParameter (ref newPasswordQuestion, this.RequiresQuestionAndAnswer, this.RequiresQuestionAndAnswer, false, MAX_PASSWORD_QUESTION_LENGTH, "newPasswordQuestion");
			if (newPasswordAnswer != null) {
				newPasswordAnswer = newPasswordAnswer.Trim ();
			}

			SecUtility.CheckParameter (ref newPasswordAnswer, this.RequiresQuestionAndAnswer, this.RequiresQuestionAndAnswer, false, MAX_PASSWORD_ANSWER_LENGTH, "newPasswordAnswer");
			if (!string.IsNullOrEmpty (newPasswordAnswer)) {
				encodedPasswordAnswer = EncodePassword (newPasswordAnswer.ToLower (CultureInfo.InvariantCulture), passwordFormat, salt);
			} else {
				encodedPasswordAnswer = newPasswordAnswer;
			}
			SecUtility.CheckParameter (ref encodedPasswordAnswer, this.RequiresQuestionAndAnswer, this.RequiresQuestionAndAnswer, false, MAX_PASSWORD_ANSWER_LENGTH, "newPasswordAnswer");


			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "UPDATE " + USER_TB_NAME +
														" SET PasswordQuestion = $Question, PasswordAnswer = $Answer" +
														" WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";
					cmd.Parameters.AddWithValue ("$Question", newPasswordQuestion);
					cmd.Parameters.AddWithValue ("$Answer", encodedPasswordAnswer);
					cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					return (cmd.ExecuteNonQuery () > 0);
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override MembershipUser CreateUser (string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
		{
			#region Validation

			if (!SecUtility.ValidateParameter (ref password, true, true, false, MAX_PASSWORD_LENGTH)) {
				status = MembershipCreateStatus.InvalidPassword;
				return null;
			}

			string salt = GenerateSalt ();
			string encodedPassword = EncodePassword (password, PasswordFormat, salt);
			if (encodedPassword.Length > MAX_PASSWORD_LENGTH) {
				status = MembershipCreateStatus.InvalidPassword;
				return null;
			}

			if (passwordAnswer != null) {
				passwordAnswer = passwordAnswer.Trim ();
			}

			string encodedPasswordAnswer;
			if (!string.IsNullOrEmpty (passwordAnswer)) {
				if (passwordAnswer.Length > MAX_PASSWORD_ANSWER_LENGTH) {
					status = MembershipCreateStatus.InvalidAnswer;
					return null;
				}
				encodedPasswordAnswer = EncodePassword (passwordAnswer.ToLower (CultureInfo.InvariantCulture), PasswordFormat, salt);
			} else {
				encodedPasswordAnswer = passwordAnswer;
			}

			if (!SecUtility.ValidateParameter (ref encodedPasswordAnswer, RequiresQuestionAndAnswer, true, false, MAX_PASSWORD_ANSWER_LENGTH)) {
				status = MembershipCreateStatus.InvalidAnswer;
				return null;
			}

			if (!SecUtility.ValidateParameter (ref username, true, true, true, MAX_USERNAME_LENGTH)) {
				status = MembershipCreateStatus.InvalidUserName;
				return null;
			}

			if (!SecUtility.ValidateParameter (ref email, this.RequiresUniqueEmail, this.RequiresUniqueEmail, false, MAX_EMAIL_LENGTH)) {
				status = MembershipCreateStatus.InvalidEmail;
				return null;
			}

			if (!SecUtility.ValidateParameter (ref passwordQuestion, this.RequiresQuestionAndAnswer, true, false, MAX_PASSWORD_QUESTION_LENGTH)) {
				status = MembershipCreateStatus.InvalidQuestion;
				return null;
			}

			if ((providerUserKey != null) && !(providerUserKey is Guid)) {
				status = MembershipCreateStatus.InvalidProviderUserKey;
				return null;
			}

			if (password.Length < this.MinRequiredPasswordLength) {
				status = MembershipCreateStatus.InvalidPassword;
				return null;
			}

			int numNonAlphaNumericChars = 0;
			for (int i = 0; i < password.Length; i++) {
				if (!char.IsLetterOrDigit (password, i)) {
					numNonAlphaNumericChars++;
				}
			}

			if (numNonAlphaNumericChars < this.MinRequiredNonAlphanumericCharacters) {
				status = MembershipCreateStatus.InvalidPassword;
				return null;
			}

			if ((this.PasswordStrengthRegularExpression.Length > 0) && !Regex.IsMatch (password, this.PasswordStrengthRegularExpression)) {
				status = MembershipCreateStatus.InvalidPassword;
				return null;
			}

			#endregion

			ValidatePasswordEventArgs args = new ValidatePasswordEventArgs (username, password, true);

			OnValidatingPassword (args);

			if (args.Cancel) {
				status = MembershipCreateStatus.InvalidPassword;
				return null;
			}

			if (RequiresUniqueEmail && !String.IsNullOrEmpty (GetUserNameByEmail (email))) {
				status = MembershipCreateStatus.DuplicateEmail;
				return null;
			}

			MembershipUser u = GetUser (username, false);

			if (u == null) {
				DateTime createDate = DateTime.UtcNow;

				if (providerUserKey == null) {
					providerUserKey = Guid.NewGuid ();
				} else {
					if (!(providerUserKey is Guid)) {
						status = MembershipCreateStatus.InvalidProviderUserKey;
						return null;
					}
				}

				SqliteConnection cn = GetDBConnectionForMembership ();
				try {
					using (SqliteCommand cmd = cn.CreateCommand()) {
						cmd.CommandText = "INSERT INTO " + USER_TB_NAME +
									" (UserId, Username, LoweredUsername, ApplicationId, Email, LoweredEmail, Comment, Password, " +
									" PasswordFormat, PasswordSalt, PasswordQuestion, PasswordAnswer, IsApproved, IsAnonymous, " +
									" LastActivityDate, LastLoginDate, LastPasswordChangedDate, CreateDate, " +
									" IsLockedOut, LastLockoutDate, FailedPasswordAttemptCount, FailedPasswordAttemptWindowStart, " +
									" FailedPasswordAnswerAttemptCount, FailedPasswordAnswerAttemptWindowStart) " +
									" Values ($UserId, $Username, $LoweredUsername, $ApplicationId, $Email, $LoweredEmail, $Comment, $Password, " +
									" $PasswordFormat, $PasswordSalt, $PasswordQuestion, $PasswordAnswer, $IsApproved, $IsAnonymous, " +
									" $LastActivityDate, $LastLoginDate, $LastPasswordChangedDate, $CreateDate, " +
									" $IsLockedOut, $LastLockoutDate, $FailedPasswordAttemptCount, $FailedPasswordAttemptWindowStart, " +
									" $FailedPasswordAnswerAttemptCount, $FailedPasswordAnswerAttemptWindowStart)";

						DateTime nullDate = _minDate;

						cmd.Parameters.AddWithValue ("$UserId", providerUserKey.ToString ());
						cmd.Parameters.AddWithValue ("$Username", username);
						cmd.Parameters.AddWithValue ("$LoweredUsername", username.ToLowerInvariant ());
						cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);
						cmd.Parameters.AddWithValue ("$Email", email);
						cmd.Parameters.AddWithValue ("$LoweredEmail", (email != null ? email.ToLowerInvariant () : null));
						cmd.Parameters.AddWithValue ("$Comment", null);
						cmd.Parameters.AddWithValue ("$Password", encodedPassword);
						cmd.Parameters.AddWithValue ("$PasswordFormat", PasswordFormat.ToString ());
						cmd.Parameters.AddWithValue ("$PasswordSalt", salt);
						cmd.Parameters.AddWithValue ("$PasswordQuestion", passwordQuestion);
						cmd.Parameters.AddWithValue ("$PasswordAnswer", encodedPasswordAnswer);
						cmd.Parameters.AddWithValue ("$IsApproved", isApproved);
						cmd.Parameters.AddWithValue ("$IsAnonymous", false);
						cmd.Parameters.AddWithValue ("$LastActivityDate", createDate);
						cmd.Parameters.AddWithValue ("$LastLoginDate", createDate);
						cmd.Parameters.AddWithValue ("$LastPasswordChangedDate", createDate);
						cmd.Parameters.AddWithValue ("$CreateDate", createDate);
						cmd.Parameters.AddWithValue ("$IsLockedOut", false);
						cmd.Parameters.AddWithValue ("$LastLockoutDate", nullDate);
						cmd.Parameters.AddWithValue ("$FailedPasswordAttemptCount", 0);
						cmd.Parameters.AddWithValue ("$FailedPasswordAttemptWindowStart", nullDate);
						cmd.Parameters.AddWithValue ("$FailedPasswordAnswerAttemptCount", 0);
						cmd.Parameters.AddWithValue ("$FailedPasswordAnswerAttemptWindowStart", nullDate);

						if (cn.State == ConnectionState.Closed)
							cn.Open ();

						if (cmd.ExecuteNonQuery () > 0) {
							status = MembershipCreateStatus.Success;
						} else {
							status = MembershipCreateStatus.UserRejected;
						}
					}
				} catch {
					status = MembershipCreateStatus.ProviderError;

					throw;
				} finally {
					if (!IsTransactionInProgress ())
						cn.Dispose ();
				}

				return GetUser (username, false);
			} else {
				status = MembershipCreateStatus.DuplicateUserName;
			}

			return null;
		}

		public override bool DeleteUser (string username, bool deleteAllRelatedData)
		{
			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					string userId = null;
					if (deleteAllRelatedData) {
						cmd.CommandText = "SELECT UserId FROM " + USER_TB_NAME + " WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

						cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
						cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

						userId = cmd.ExecuteScalar () as string;
					}

					cmd.CommandText = "DELETE FROM " + USER_TB_NAME + " WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					int rowsAffected = cmd.ExecuteNonQuery ();

					if (deleteAllRelatedData && (!String.IsNullOrEmpty ((userId)))) {
						cmd.CommandText = "DELETE FROM " + USERS_IN_ROLES_TB_NAME + " WHERE UserId = $UserId";
						cmd.Parameters.Clear ();
						cmd.Parameters.AddWithValue ("$UserId", userId);
						cmd.ExecuteNonQuery ();

						cmd.CommandText = "DELETE FROM " + PROFILE_TB_NAME + " WHERE UserId = $UserId";
						cmd.Parameters.Clear ();
						cmd.Parameters.AddWithValue ("$UserId", userId);
						cmd.ExecuteNonQuery ();
					}

					return (rowsAffected > 0);
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override MembershipUserCollection GetAllUsers (int pageIndex, int pageSize, out int totalRecords)
		{
			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT Count(*) FROM " + USER_TB_NAME + " WHERE ApplicationId = $ApplicationId AND IsAnonymous='0'";
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					totalRecords = Convert.ToInt32 (cmd.ExecuteScalar ());

					MembershipUserCollection users = new MembershipUserCollection ();

					if (totalRecords <= 0) {
						return users;
					}

					cmd.CommandText = "SELECT UserId, Username, Email, PasswordQuestion," +
									 " Comment, IsApproved, IsLockedOut, CreateDate, LastLoginDate," +
									 " LastActivityDate, LastPasswordChangedDate, LastLockoutDate " +
									 " FROM " + USER_TB_NAME +
									 " WHERE ApplicationId = $ApplicationId AND IsAnonymous='0' " +
									 " ORDER BY Username Asc";

					using (SqliteDataReader reader = cmd.ExecuteReader()) {
						int counter = 0;
						int startIndex = pageSize * pageIndex;
						int endIndex = startIndex + pageSize - 1;

						while (reader.Read()) {
							if (counter >= startIndex) {
								MembershipUser u = GetUserFromReader (reader);
								users.Add (u);
							}

							if (counter >= endIndex) {
								cmd.Cancel ();
							}

							counter++;
						}

						return users;
					}
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override int GetNumberOfUsersOnline ()
		{
			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT Count(*) FROM " + USER_TB_NAME +
												" WHERE LastActivityDate > $LastActivityDate AND ApplicationId = $ApplicationId";

					TimeSpan onlineSpan = new TimeSpan (0, Membership.UserIsOnlineTimeWindow, 0);
					DateTime compareTime = DateTime.UtcNow.Subtract (onlineSpan);

					cmd.Parameters.AddWithValue ("$LastActivityDate", compareTime);
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					return Convert.ToInt32 (cmd.ExecuteScalar ());
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override string GetPassword (string username, string answer)
		{
			if (!EnablePasswordRetrieval) {
				throw new ProviderException ("Password retrieval not enabled.");
			}

			if (PasswordFormat == MembershipPasswordFormat.Hashed) {
				throw new ProviderException ("Cannot retrieve hashed passwords.");
			}

			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT Password, PasswordFormat, PasswordSalt, PasswordAnswer, IsLockedOut FROM "
						+ USER_TB_NAME + " WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					using (SqliteDataReader dr = cmd.ExecuteReader((CommandBehavior.SingleRow))) {
						string password, passwordAnswer, passwordSalt;
						MembershipPasswordFormat passwordFormat;

						if (dr.HasRows) {
							dr.Read ();

							if (dr.GetBoolean (4))
								throw new MembershipPasswordException ("The supplied user is locked out.");

							password = dr.GetString (0);
							passwordFormat = (MembershipPasswordFormat)Enum.Parse (typeof(MembershipPasswordFormat), dr.GetString (1));
							passwordSalt = dr.GetString (2);
							passwordAnswer = (dr.GetValue (3) == DBNull.Value ? String.Empty : dr.GetString (3));
						} else {
							throw new MembershipPasswordException ("The supplied user name is not found.");
						}

						if (RequiresQuestionAndAnswer && !ComparePasswords (answer, passwordAnswer, passwordSalt, passwordFormat)) {
							UpdateFailureCount (username, "passwordAnswer", false);

							throw new MembershipPasswordException ("Incorrect password answer.");
						}

						if (passwordFormat == MembershipPasswordFormat.Encrypted) {
							password = UnEncodePassword (password, passwordFormat);
						}

						return password;
					}
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override MembershipUser GetUser (string username, bool userIsOnline)
		{
			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT UserId, Username, Email, PasswordQuestion,"
						+ " Comment, IsApproved, IsLockedOut, CreateDate, LastLoginDate,"
						+ " LastActivityDate, LastPasswordChangedDate, LastLockoutDate"
						+ " FROM " + USER_TB_NAME + " WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					MembershipUser user = null;

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					using (SqliteDataReader dr = cmd.ExecuteReader()) {
						if (dr.HasRows) {
							dr.Read ();
							user = GetUserFromReader (dr);
						}
					}

					if (userIsOnline) {
						cmd.CommandText = "UPDATE " + USER_TB_NAME
							+ " SET LastActivityDate = $LastActivityDate"
							+ " WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

						cmd.Parameters.AddWithValue ("$LastActivityDate", DateTime.UtcNow);

						cmd.ExecuteNonQuery ();
					}

					return user;
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override MembershipUser GetUser (object providerUserKey, bool userIsOnline)
		{
			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT UserId, Username, Email, PasswordQuestion,"
						+ " Comment, IsApproved, IsLockedOut, CreateDate, LastLoginDate,"
						+ " LastActivityDate, LastPasswordChangedDate, LastLockoutDate"
						+ " FROM " + USER_TB_NAME + " WHERE UserId = $UserId";

					cmd.Parameters.AddWithValue ("$UserId", providerUserKey.ToString ());

					MembershipUser user = null;

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					using (SqliteDataReader dr = cmd.ExecuteReader()) {
						if (dr.HasRows) {
							dr.Read ();
							user = GetUserFromReader (dr);
						}
					}

					if (userIsOnline) {
						cmd.CommandText = "UPDATE " + USER_TB_NAME
							+ " SET LastActivityDate = $LastActivityDate"
							+ " WHERE UserId = $UserId";

						cmd.Parameters.AddWithValue ("$LastActivityDate", DateTime.UtcNow);
						cmd.ExecuteNonQuery ();
					}

					return user;
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override bool UnlockUser (string username)
		{
			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "UPDATE " + USER_TB_NAME
						+ " SET IsLockedOut = '0', FailedPasswordAttemptCount = 0,"
						+ " FailedPasswordAttemptWindowStart = $MinDate, FailedPasswordAnswerAttemptCount = 0,"
						+ " FailedPasswordAnswerAttemptWindowStart = $MinDate"
						+ " WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue ("$MinDate", _minDate);
					cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					return (cmd.ExecuteNonQuery () > 0);
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override string GetUserNameByEmail (string email)
		{
			if (email == null)
				return null;

			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT Username" +
						" FROM " + USER_TB_NAME + " WHERE LoweredEmail = $Email AND ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue ("$Email", email.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					return (cmd.ExecuteScalar () as string);
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override string ResetPassword (string username, string passwordAnswer)
		{
			string salt;
			MembershipPasswordFormat passwordFormat;
			string passwordFromDb;
			int status;
			int failedPwdAttemptCount;
			int failedPwdAnswerAttemptCount;
			bool isApproved;
			DateTime lastLoginDate;
			DateTime lastActivityDate;
			if (!this.EnablePasswordReset) {
				throw new NotSupportedException ("This provider is not configured to allow password resets. To enable password reset, set enablePasswordReset to \"true\" in the configuration file.");
			}
			SecUtility.CheckParameter (ref username, true, true, true, 0x100, "username");

			GetPasswordWithFormat (username, out status, out passwordFromDb, out passwordFormat, out salt, out failedPwdAttemptCount, out failedPwdAnswerAttemptCount, out isApproved, out lastLoginDate, out lastActivityDate);

			if (status != 0) {
				if (IsStatusDueToBadPassword (status)) {
					throw new MembershipPasswordException (GetExceptionText (status));
				}
				throw new ProviderException (GetExceptionText (status));
			}

			string encodedPwdAnswer;
			if (passwordAnswer != null) {
				passwordAnswer = passwordAnswer.Trim ();
			}
			if (!string.IsNullOrEmpty (passwordAnswer)) {
				encodedPwdAnswer = EncodePassword (passwordAnswer.ToLower (CultureInfo.InvariantCulture), passwordFormat, salt);
			} else {
				encodedPwdAnswer = passwordAnswer;
			}
			SecUtility.CheckParameter (ref encodedPwdAnswer, this.RequiresQuestionAndAnswer, this.RequiresQuestionAndAnswer, false, MAX_PASSWORD_ANSWER_LENGTH, "passwordAnswer");

			string newPassword = Membership.GeneratePassword (NEW_PASSWORD_LENGTH, MinRequiredNonAlphanumericCharacters);

			ValidatePasswordEventArgs e = new ValidatePasswordEventArgs (username, newPassword, false);
			this.OnValidatingPassword (e);
			if (e.Cancel) {
				if (e.FailureInformation != null) {
					throw e.FailureInformation;
				}
				throw new ProviderException ("The custom password validation failed.");
			}

			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT PasswordAnswer, IsLockedOut FROM " + USER_TB_NAME
						+ " WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					using (SqliteDataReader dr = cmd.ExecuteReader(CommandBehavior.SingleRow)) {
						string passwordAnswerFromDb;
						if (dr.HasRows) {
							dr.Read ();

							if (Convert.ToBoolean (dr.GetValue (1)))
								throw new MembershipPasswordException ("The supplied user is locked out.");

							passwordAnswerFromDb = dr.GetValue (0) as string;
						} else {
							throw new MembershipPasswordException ("The supplied user name is not found.");
						}

						if (RequiresQuestionAndAnswer && !ComparePasswords (passwordAnswer, passwordAnswerFromDb, salt, passwordFormat)) {
							UpdateFailureCount (username, "passwordAnswer", false);

							throw new MembershipPasswordException ("Incorrect password answer.");
						}
					}

					cmd.CommandText = "UPDATE " + USER_TB_NAME
						+ " SET Password = $Password, LastPasswordChangedDate = $LastPasswordChangedDate,"
						+ " FailedPasswordAttemptCount = 0, FailedPasswordAttemptWindowStart = $MinDate,"
						+ " FailedPasswordAnswerAttemptCount = 0, FailedPasswordAnswerAttemptWindowStart = $MinDate"
						+ " WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId AND IsLockedOut = 0";

					cmd.Parameters.Clear ();
					cmd.Parameters.AddWithValue ("$Password", EncodePassword (newPassword, passwordFormat, salt));
					cmd.Parameters.AddWithValue ("$LastPasswordChangedDate", DateTime.UtcNow);
					cmd.Parameters.AddWithValue ("$MinDate", _minDate);
					cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cmd.ExecuteNonQuery () > 0) {
						return newPassword;
					} else {
						throw new MembershipPasswordException ("User not found, or user is locked out. Password not reset.");
					}
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override void UpdateUser (MembershipUser user)
		{
			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "UPDATE " + USER_TB_NAME +
							" SET Email = $Email, LoweredEmail = $LoweredEmail, Comment = $Comment," +
							" IsApproved = $IsApproved" +
							" WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue ("$Email", user.Email);
					cmd.Parameters.AddWithValue ("$LoweredEmail", user.Email.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$Comment", user.Comment);
					cmd.Parameters.AddWithValue ("$IsApproved", user.IsApproved);
					cmd.Parameters.AddWithValue ("$Username", user.UserName.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					cmd.ExecuteNonQuery ();
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override bool ValidateUser (string username, string password)
		{
			if (!SecUtility.ValidateParameter (ref username, true, true, true, MAX_USERNAME_LENGTH) || !SecUtility.ValidateParameter (ref password, true, true, false, MAX_PASSWORD_LENGTH)) {
				return false;
			}

			string salt;
			MembershipPasswordFormat passwordFormat;
			bool isAuthenticated = CheckPassword (username, password, true, out salt, out passwordFormat);

			if (isAuthenticated) {
				SqliteConnection cn = GetDBConnectionForMembership ();
				try {
					using (SqliteCommand cmd = cn.CreateCommand()) {
						cmd.CommandText = "UPDATE " + USER_TB_NAME
						+ " SET LastActivityDate = $UtcNow, LastLoginDate = $UtcNow"
						+ " WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

						cmd.Parameters.AddWithValue ("$UtcNow", DateTime.UtcNow);
						cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
						cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

						if (cn.State == ConnectionState.Closed)
							cn.Open ();

						cmd.ExecuteNonQuery ();
					}
				} finally {
					if (!IsTransactionInProgress ())
						cn.Dispose ();
				}
			}

			return isAuthenticated;
		}

		public override MembershipUserCollection FindUsersByName (string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
		{
			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT Count(*) FROM " + USER_TB_NAME +
								"WHERE LoweredUsername LIKE $UsernameSearch AND ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue ("$UsernameSearch", usernameToMatch.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					totalRecords = Convert.ToInt32 (cmd.ExecuteScalar ());

					MembershipUserCollection users = new MembershipUserCollection ();

					if (totalRecords <= 0) {
						return users;
					}

					cmd.CommandText = "SELECT UserId, Username, Email, PasswordQuestion,"
						+ " Comment, IsApproved, IsLockedOut, CreateDate, LastLoginDate,"
						+ " LastActivityDate, LastPasswordChangedDate, LastLockoutDate "
						+ " FROM " + USER_TB_NAME
						+ " WHERE LoweredUsername LIKE $UsernameSearch AND ApplicationId = $ApplicationId "
						+ " ORDER BY Username Asc";

					using (SqliteDataReader dr = cmd.ExecuteReader()) {
						int counter = 0;
						int startIndex = pageSize * pageIndex;
						int endIndex = startIndex + pageSize - 1;

						while (dr.Read()) {
							if (counter >= startIndex) {
								MembershipUser u = GetUserFromReader (dr);
								users.Add (u);
							}

							if (counter >= endIndex) {
								cmd.Cancel ();
							}

							counter++;
						}
					}

					return users;
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override MembershipUserCollection FindUsersByEmail (string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
		{
			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT Count(*) FROM " + USER_TB_NAME
						+ " WHERE LoweredEmail LIKE $EmailSearch AND ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue ("$EmailSearch", emailToMatch.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					totalRecords = Convert.ToInt32 (cmd.ExecuteScalar ());

					MembershipUserCollection users = new MembershipUserCollection ();

					if (totalRecords <= 0) {
						return users;
					}

					cmd.CommandText = "SELECT UserId, Username, Email, PasswordQuestion,"
						+ " Comment, IsApproved, IsLockedOut, CreateDate, LastLoginDate,"
						+ " LastActivityDate, LastPasswordChangedDate, LastLockoutDate"
						+ " FROM " + USER_TB_NAME
						+ " WHERE LoweredEmail LIKE $EmailSearch AND ApplicationId = $ApplicationId"
						+ " ORDER BY Username Asc";

					using (SqliteDataReader dr = cmd.ExecuteReader()) {
						int counter = 0;
						int startIndex = pageSize * pageIndex;
						int endIndex = startIndex + pageSize - 1;

						while (dr.Read()) {
							if (counter >= startIndex) {
								MembershipUser u = GetUserFromReader (dr);
								users.Add (u);
							}

							if (counter >= endIndex) {
								cmd.Cancel ();
							}

							counter++;
						}
					}

					return users;
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		#endregion

		#region Private Methods

		private static void ValidatePwdStrengthRegularExpression ()
		{
			if (_passwordStrengthRegularExpression == null)
				_passwordStrengthRegularExpression = String.Empty;

			_passwordStrengthRegularExpression = _passwordStrengthRegularExpression.Trim ();
			if (_passwordStrengthRegularExpression.Length > 0) {
				try {
					new Regex (_passwordStrengthRegularExpression);
				} catch (ArgumentException ex) {
					throw new ProviderException (ex.Message, ex);
				}
			}
		}

		private static void VerifyApplication ()
		{
			if (!String.IsNullOrEmpty (_applicationId))
				return;

			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "INSERT INTO " + APP_TB_NAME + " (ApplicationId, ApplicationName, Description) VALUES ($ApplicationId, $ApplicationName, $Description)";

					_applicationId = Guid.NewGuid ().ToString ();
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);
					cmd.Parameters.AddWithValue ("ApplicationName", _applicationName);
					cmd.Parameters.AddWithValue ("Description", String.Empty);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					cmd.ExecuteNonQuery ();
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		private static string GetApplicationId (string appName)
		{
			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT ApplicationId FROM aspnet_Applications WHERE ApplicationName = $AppName";
					cmd.Parameters.AddWithValue ("$AppName", appName);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					return cmd.ExecuteScalar () as string;
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		private static string GetConfigValue (string configValue, string defaultValue)
		{
			if (String.IsNullOrEmpty (configValue))
				return defaultValue;

			return configValue;
		}

		private MembershipUser GetUserFromReader (IDataRecord reader)
		{
			if (reader.GetString (1) == "")
				return null;
			object providerUserKey = null;
			string strGooid = Guid.NewGuid ().ToString ();

			if (reader.GetValue (0).ToString ().Length > 0)
				providerUserKey = new Guid (reader.GetValue (0).ToString ());
			else
				providerUserKey = new Guid (strGooid);

			string username = reader.GetString (1);

			string email = (reader.GetValue (2) == DBNull.Value ? String.Empty : reader.GetString (2));

			string passwordQuestion = (reader.GetValue (3) == DBNull.Value ? String.Empty : reader.GetString (3));

			string comment = (reader.GetValue (4) == DBNull.Value ? String.Empty : reader.GetString (4));

			bool isApproved = reader.GetBoolean (5);

			bool isLockedOut = reader.GetBoolean (6);

			DateTime creationDate = reader.GetDateTime (7);

			DateTime lastLoginDate = reader.GetDateTime (8);

			DateTime lastActivityDate = reader.GetDateTime (9);

			DateTime lastPasswordChangedDate = reader.GetDateTime (10);

			DateTime lastLockedOutDate = reader.GetDateTime (11);

			MembershipUser user = new MembershipUser (this.Name,
																						username,
																						providerUserKey,
																						email,
																						passwordQuestion,
																						comment,
																						isApproved,
																						isLockedOut,
																						creationDate,
																						lastLoginDate,
																						lastActivityDate,
																						lastPasswordChangedDate,
																						lastLockedOutDate);

			return user;
		}

		private void UpdateFailureCount (string username, string failureType, bool isAuthenticated)
		{
			if (!((failureType == "password") || (failureType == "passwordAnswer"))) {
				throw new ArgumentException ("Invalid value for failureType parameter. Must be 'password' or 'passwordAnswer'.", "failureType");
			}

			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT FailedPasswordAttemptCount, FailedPasswordAttemptWindowStart, "
						+ "  FailedPasswordAnswerAttemptCount, FailedPasswordAnswerAttemptWindowStart, IsLockedOut "
						+ "  FROM " + USER_TB_NAME
						+ "  WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					int failedPasswordAttemptCount = 0;
					int failedPasswordAnswerAttemptCount = 0;
					DateTime failedPasswordAttemptWindowStart = _minDate;
					DateTime failedPasswordAnswerAttemptWindowStart = _minDate;
					bool isLockedOut = false;

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					using (SqliteDataReader dr = cmd.ExecuteReader(CommandBehavior.SingleRow)) {
						if (dr.HasRows) {
							dr.Read ();

							failedPasswordAttemptCount = dr.GetInt32 (0);
							failedPasswordAttemptWindowStart = dr.GetDateTime (1);
							failedPasswordAnswerAttemptCount = dr.GetInt32 (2);
							failedPasswordAnswerAttemptWindowStart = dr.GetDateTime (3);
							isLockedOut = dr.GetBoolean (4);
						}
					}

					if (isLockedOut)
						return;

					if (isAuthenticated) {
						if ((failedPasswordAttemptCount > 0) || (failedPasswordAnswerAttemptCount > 0)) {
							cmd.CommandText = "UPDATE " + USER_TB_NAME
								+ " SET FailedPasswordAttemptCount = 0, FailedPasswordAttemptWindowStart = $MinDate, "
								+ " FailedPasswordAnswerAttemptCount = 0, FailedPasswordAnswerAttemptWindowStart = $MinDate, IsLockedOut = '0' "
								+ " WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

							cmd.Parameters.Clear ();
							cmd.Parameters.AddWithValue ("$MinDate", _minDate);
							cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
							cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

							cmd.ExecuteNonQuery ();
						}

						return;
					}

					DateTime windowStart = _minDate;
					int failureCount = 0;
					if (failureType == "password") {
						windowStart = failedPasswordAttemptWindowStart;
						failureCount = failedPasswordAttemptCount;
					} else if (failureType == "passwordAnswer") {
						windowStart = failedPasswordAnswerAttemptWindowStart;
						failureCount = failedPasswordAnswerAttemptCount;
					}

					DateTime windowEnd = windowStart.AddMinutes (PasswordAttemptWindow);

					if (failureCount == 0 || DateTime.UtcNow > windowEnd) {

						if (failureType == "password")
							cmd.CommandText = "UPDATE " + USER_TB_NAME
								+ "  SET FailedPasswordAttemptCount = $Count, "
								+ "      FailedPasswordAttemptWindowStart = $WindowStart "
								+ "  WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

						if (failureType == "passwordAnswer")
							cmd.CommandText = "UPDATE " + USER_TB_NAME
								+ "  SET FailedPasswordAnswerAttemptCount = $Count, "
								+ "      FailedPasswordAnswerAttemptWindowStart = $WindowStart "
								+ "  WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

						cmd.Parameters.Clear ();
						cmd.Parameters.AddWithValue ("$Count", 1);
						cmd.Parameters.AddWithValue ("$WindowStart", DateTime.UtcNow);
						cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
						cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

						if (cmd.ExecuteNonQuery () < 0)
							throw new ProviderException ("Unable to update failure count and window start.");
					} else {
						if (failureCount++ >= MaxInvalidPasswordAttempts) {
							cmd.CommandText = "UPDATE " + USER_TB_NAME
								+ "  SET IsLockedOut = '1', LastLockoutDate = $LastLockoutDate, FailedPasswordAttemptCount = $Count "
								+ "  WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

							cmd.Parameters.Clear ();
							cmd.Parameters.AddWithValue ("$LastLockoutDate", DateTime.UtcNow);
							cmd.Parameters.AddWithValue ("$Count", failureCount);
							cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
							cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

							if (cmd.ExecuteNonQuery () < 0)
								throw new ProviderException ("Unable to lock out user.");
						} else {

							if (failureType == "password")
								cmd.CommandText = "UPDATE " + USER_TB_NAME
									+ "  SET FailedPasswordAttemptCount = $Count"
									+ "  WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

							if (failureType == "passwordAnswer")
								cmd.CommandText = "UPDATE " + USER_TB_NAME
									+ "  SET FailedPasswordAnswerAttemptCount = $Count"
									+ "  WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

							cmd.Parameters.Clear ();
							cmd.Parameters.AddWithValue ("$Count", failureCount);
							cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
							cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

							if (cmd.ExecuteNonQuery () < 0)
								throw new ProviderException ("Unable to update failure count.");
						}
					}
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		private bool ComparePasswords (string password, string dbpassword, string salt, MembershipPasswordFormat passwordFormat)
		{
			string pass1 = password;
			string pass2 = dbpassword;

			switch (passwordFormat) {
			case MembershipPasswordFormat.Encrypted:
				pass2 = UnEncodePassword (dbpassword, passwordFormat);
				break;
			case MembershipPasswordFormat.Hashed:
				pass1 = EncodePassword (password, passwordFormat, salt);
				break;
			default:
				break;
			}

			if (pass1 == pass2) {
				return true;
			}

			return false;
		}

		private bool CheckPassword (string username, string password, bool failIfNotApproved, out string salt, out MembershipPasswordFormat passwordFormat)
		{
			string encodedPwdFromDatabase;
			int status;
			int failedPwdAttemptCount;
			int failedPwdAnswerAttemptCount;
			bool isApproved;
			DateTime lastLoginDate;
			DateTime lastActivityDate;
			GetPasswordWithFormat (username, out status, out encodedPwdFromDatabase, out passwordFormat, out salt, out failedPwdAttemptCount, out failedPwdAnswerAttemptCount, out isApproved, out lastLoginDate, out lastActivityDate);
			if (status != 0) {
				return false;
			}
			if (!isApproved && failIfNotApproved) {
				return false;
			}
			string encodedPwdFromUser = EncodePassword (password, passwordFormat, salt);
			bool isAuthenticated = encodedPwdFromDatabase.Equals (encodedPwdFromUser);
			if ((isAuthenticated && (failedPwdAttemptCount == 0)) && (failedPwdAnswerAttemptCount == 0)) {
				return true;
			}

			UpdateFailureCount (username, "password", isAuthenticated);

			return isAuthenticated;
		}

		private static void GetPasswordWithFormat (string username, out int status, out string password, out MembershipPasswordFormat passwordFormat, out string passwordSalt, out int failedPasswordAttemptCount, out int failedPasswordAnswerAttemptCount, out bool isApproved, out DateTime lastLoginDate, out DateTime lastActivityDate)
		{
			SqliteConnection cn = GetDBConnectionForMembership ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT Password, PasswordFormat, PasswordSalt, FailedPasswordAttemptCount,"
						+ " FailedPasswordAnswerAttemptCount, IsApproved, IsLockedOut, LastLoginDate, LastActivityDate"
						+ " FROM " + USER_TB_NAME + " WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					using (SqliteDataReader dr = cmd.ExecuteReader(CommandBehavior.SingleRow)) {
						if (dr.HasRows) {
							dr.Read ();

							password = dr.GetString (0);
							passwordFormat = (MembershipPasswordFormat)Enum.Parse (typeof(MembershipPasswordFormat), dr.GetString (1));
							passwordSalt = dr.GetString (2);
							failedPasswordAttemptCount = dr.GetInt32 (3);
							failedPasswordAnswerAttemptCount = dr.GetInt32 (4);
							isApproved = dr.GetBoolean (5);
							status = dr.GetBoolean (6) ? 99 : 0;
							lastLoginDate = dr.GetDateTime (7);
							lastActivityDate = dr.GetDateTime (8);
						} else {
							status = 1;
							password = null;
							passwordFormat = MembershipPasswordFormat.Clear;
							passwordSalt = null;
							failedPasswordAttemptCount = 0;
							failedPasswordAnswerAttemptCount = 0;
							isApproved = false;
							lastLoginDate = DateTime.UtcNow;
							lastActivityDate = DateTime.UtcNow;
						}
					}
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		private string EncodePassword (string password, MembershipPasswordFormat passwordFormat, string salt)
		{
			if (String.IsNullOrEmpty (password))
				return password;

			byte[] bytes = Encoding.Unicode.GetBytes (password);
			byte[] src = Convert.FromBase64String (salt);
			byte[] dst = new byte[src.Length + bytes.Length];
			byte[] inArray;

			Buffer.BlockCopy (src, 0, dst, 0, src.Length);
			Buffer.BlockCopy (bytes, 0, dst, src.Length, bytes.Length);

			switch (passwordFormat) {
			case MembershipPasswordFormat.Clear:
				return password;
			case MembershipPasswordFormat.Encrypted:
				inArray = EncryptPassword (dst);
				break;
			case MembershipPasswordFormat.Hashed:
				HashAlgorithm algorithm = HashAlgorithm.Create (Membership.HashAlgorithmType);
				if (algorithm == null) {
					throw new ProviderException (String.Concat ("SQLiteMembershipProvider configuration error: HashAlgorithm.Create() does not recognize the hash algorithm ", Membership.HashAlgorithmType, "."));
				}
				inArray = algorithm.ComputeHash (dst);

				break;
			default:
				throw new ProviderException ("Unsupported password format.");
			}

			return Convert.ToBase64String (inArray);
		}

		private string UnEncodePassword (string encodedPassword, MembershipPasswordFormat passwordFormat)
		{
			string password = encodedPassword;

			switch (passwordFormat) {
			case MembershipPasswordFormat.Clear:
				break;
			case MembershipPasswordFormat.Encrypted:
				byte[] bytes = base.DecryptPassword (Convert.FromBase64String (password));
				if (bytes == null) {
					password = null;
				} else {
					password = Encoding.Unicode.GetString (bytes, 0x10, bytes.Length - 0x10);
				}
				break;
			case MembershipPasswordFormat.Hashed:
				throw new ProviderException ("Cannot unencode a hashed password.");
			default:
				throw new ProviderException ("Unsupported password format.");
			}

			return password;
		}

		private static byte[] HexToByte (string hexString)
		{
			byte[] returnBytes = new byte[hexString.Length / 2];
			for (int i = 0; i < returnBytes.Length; i++)
				returnBytes [i] = Convert.ToByte (hexString.Substring (i * 2, 2), 16);
			return returnBytes;
		}

		private static string GenerateSalt ()
		{
			byte[] data = new byte[0x10];
			new RNGCryptoServiceProvider ().GetBytes (data);
			return Convert.ToBase64String (data);
		}

		private static bool IsStatusDueToBadPassword (int status)
		{
			return (((status >= 2) && (status <= 6)) || (status == 99));
		}

		private static string GetExceptionText (int status)
		{
			string exceptionText;
			switch (status) {
			case 0:
				return string.Empty;

			case 1:
				exceptionText = "The user was not found.";
				break;

			case 2:
				exceptionText = "The password supplied is wrong.";
				break;

			case 3:
				exceptionText = "The password-answer supplied is wrong.";
				break;

			case 4:
				exceptionText = "The password supplied is invalid.  Passwords must conform to the password strength requirements configured for the default provider.";
				break;

			case 5:
				exceptionText = "The password-question supplied is invalid.  Note that the current provider configuration requires a valid password question and answer.  As a result, a CreateUser overload that accepts question and answer parameters must also be used.";
				break;

			case 6:
				exceptionText = "The password-answer supplied is invalid.";
				break;

			case 7:
				exceptionText = "The E-mail supplied is invalid.";
				break;

			case 99:
				exceptionText = "The user account has been locked out.";
				break;

			default:
				exceptionText = "The Provider encountered an unknown error.";
				break;
			}
			return exceptionText;
		}

		[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate")]
		private static SqliteConnection GetDBConnectionForMembership ()
		{
			if (System.Web.HttpContext.Current != null) {
				SqliteTransaction tran = (SqliteTransaction)System.Web.HttpContext.Current.Items [_httpTransactionId];
				if ((tran != null) && (String.Equals (tran.Connection.ConnectionString, _connectionString)))
					return tran.Connection;
			}

			return new SqliteConnection (_connectionString);
		}

		private static bool IsTransactionInProgress ()
		{
			if (System.Web.HttpContext.Current == null)
				return false;

			SqliteTransaction tran = (SqliteTransaction)System.Web.HttpContext.Current.Items [_httpTransactionId];

			if ((tran != null) && (String.Equals (tran.Connection.ConnectionString, _connectionString)))
				return true;
			else
				return false;
		}

		#endregion
	}

	internal class SecUtility
	{
		internal static void CheckParameter (ref string param, bool checkForNull, bool checkIfEmpty, bool checkForCommas, int maxSize, string paramName)
		{
			if (param == null) {
				if (checkForNull) {
					throw new ArgumentNullException (paramName);
				}
			} else {
				param = param.Trim ();
				if (checkIfEmpty && (param.Length < 1)) {
					throw new ArgumentException (String.Format ("The parameter '{0}' must not be empty.", paramName), paramName);
				}
				if ((maxSize > 0) && (param.Length > maxSize)) {
					throw new ArgumentException (String.Format ("The parameter '{0}' is too long: it must not exceed {1} chars in length.", paramName, maxSize.ToString (CultureInfo.InvariantCulture)), paramName);
				}
				if (checkForCommas && param.Contains (",")) {
					throw new ArgumentException (String.Format ("The parameter '{0}' must not contain commas.", paramName), paramName);
				}
			}
		}

		internal static bool ValidateParameter (ref string param, bool checkForNull, bool checkIfEmpty, bool checkForCommas, int maxSize)
		{
			if (param == null) {
				return !checkForNull;
			}
			param = param.Trim ();
			return (((!checkIfEmpty || (param.Length >= 1)) && ((maxSize <= 0) || (param.Length <= maxSize))) && (!checkForCommas || !param.Contains (",")));
		}

	}

}

using System;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Configuration;
using System.Configuration.Provider;
using System.Data;
using Mono.Data.Sqlite;
using System.Globalization;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Web.Profile;
using System.Xml.Serialization;

namespace TechInfoSystems.Data.SQLite
{
	public sealed class SQLiteProfileProvider : ProfileProvider
	{
		#region Private Fields

		private static string _connectionString;
		private const string HTTP_TRANSACTION_ID = "SQLiteTran";
		private const string USER_TB_NAME = "[aspnet_Users]";
		private const string PROFILE_TB_NAME = "[aspnet_Profile]";
		private const string APP_TB_NAME = "[aspnet_Applications]";
		private const int MAX_APPLICATION_NAME_LENGTH = 256;
		private static string _applicationId;
		private static string _applicationName;
		private static string _membershipApplicationId;
		private static string _membershipApplicationName;

		#endregion

		#region Public Properties

		public override string ApplicationName {
			get { return _applicationName; }
			set {
				if (value.Length > MAX_APPLICATION_NAME_LENGTH)
					throw new ProviderException (String.Format ("SQLiteProfileProvider error: applicationName must be less than or equal to {0} characters.", MAX_APPLICATION_NAME_LENGTH));

				_applicationName = value;
				_applicationId = GetApplicationId (_applicationName);
			}
		}

		public static string MembershipApplicationName {
			get { return _membershipApplicationName; }
			set {
				if (value.Length > MAX_APPLICATION_NAME_LENGTH)
					throw new ProviderException (String.Format ("SQLiteProfileProvider error: membershipApplicationName must be less than or equal to {0} characters.", MAX_APPLICATION_NAME_LENGTH));

				_membershipApplicationName = value;
				_membershipApplicationId = GetApplicationId (_membershipApplicationName);
			}
		}

		#endregion

		#region Public Methods

		public override void Initialize (string name, NameValueCollection config)
		{
			if (config == null)
				throw new ArgumentNullException ("config");

			if (string.IsNullOrEmpty (name))
				name = "SQLiteProfileProvider";


			if (string.IsNullOrEmpty (config ["description"])) {
				config.Remove ("description");
				config.Add ("description", "SQLite Profile Provider");
			}

			base.Initialize (name, config);

			ConnectionStringSettings connectionStringSettings = ConfigurationManager.ConnectionStrings [config ["connectionStringName"]];

			if (connectionStringSettings == null || String.IsNullOrEmpty (connectionStringSettings.ConnectionString)) {
				throw new ProviderException ("Connection String is empty for SQLiteProfileProvider. Check the web configuration file (web.config).");
			}
			_connectionString = connectionStringSettings.ConnectionString;

			if (config ["applicationName"] == null || config ["applicationName"].Trim () == "") {
				ApplicationName = System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath;
			} else {
				ApplicationName = config ["applicationName"];
			}

			if (config ["membershipApplicationName"] == null || config ["membershipApplicationName"].Trim () == "") {
				MembershipApplicationName = _applicationName;
			} else {
				MembershipApplicationName = config ["membershipApplicationName"];
			}

			config.Remove ("connectionStringName");
			config.Remove ("applicationName");
			config.Remove ("membershipApplicationName");

			if (config.Count > 0) {
				string attribUnrecognized = config.GetKey (0);
				if (!String.IsNullOrEmpty (attribUnrecognized))
					throw new ProviderException ("Unrecognized attribute: " + attribUnrecognized);
			}

			VerifyApplication ();
		}

		public override SettingsPropertyValueCollection GetPropertyValues (SettingsContext sc, SettingsPropertyCollection properties)
		{
			SettingsPropertyValueCollection svc = new SettingsPropertyValueCollection ();
			if (properties.Count < 1)
				return svc;

			string username = (string)sc ["UserName"];
			foreach (SettingsProperty prop in properties) {
				if (prop.SerializeAs == SettingsSerializeAs.ProviderSpecific) {
					if (prop.PropertyType.IsPrimitive || prop.PropertyType == typeof(string))
						prop.SerializeAs = SettingsSerializeAs.String;
					else
						prop.SerializeAs = SettingsSerializeAs.Xml;
				}
				svc.Add (new SettingsPropertyValue (prop));
			}

			if (!String.IsNullOrEmpty (username)) {
				GetPropertyValuesFromDatabase (username, svc);
			}
			return svc;
		}

		public override void SetPropertyValues (SettingsContext sc, SettingsPropertyValueCollection properties)
		{
			string username = (string)sc ["UserName"];
			bool userIsAuthenticated = (bool)sc ["IsAuthenticated"];
			if (string.IsNullOrEmpty (username) || properties.Count < 1)
				return;

			string names = String.Empty;
			string values = String.Empty;
			byte[] buf = null;

			PrepareDataForSaving (ref names, ref values, ref buf, true, properties, userIsAuthenticated);

			if (names.Length == 0)
				return;

			SqliteTransaction tran = null;
			SqliteConnection cn = GetDbConnectionForProfile ();
			try {
				if (cn.State == ConnectionState.Closed)
					cn.Open ();

				if (!IsTransactionInProgress ())
					tran = cn.BeginTransaction ();

				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT UserId FROM " + USER_TB_NAME + " WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId;";

					cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _membershipApplicationId);

					string userId = cmd.ExecuteScalar () as string;

					if ((userId == null) && (userIsAuthenticated))
						return;

					if (userId == null) {
						userId = Guid.NewGuid ().ToString ();

						CreateAnonymousUser (username, cn, tran, userId);
					}

					cmd.CommandText = "SELECT COUNT(*) FROM " + PROFILE_TB_NAME + " WHERE UserId = $UserId";
					cmd.Parameters.Clear ();
					cmd.Parameters.AddWithValue ("$UserId", userId);

					if (Convert.ToInt64 (cmd.ExecuteScalar ()) > 0) {
						cmd.CommandText = "UPDATE " + PROFILE_TB_NAME + " SET PropertyNames = $PropertyNames, PropertyValuesString = $PropertyValuesString, PropertyValuesBinary = $PropertyValuesBinary, LastUpdatedDate = $LastUpdatedDate WHERE UserId = $UserId";
					} else {
						cmd.CommandText = "INSERT INTO " + PROFILE_TB_NAME + " (UserId, PropertyNames, PropertyValuesString, PropertyValuesBinary, LastUpdatedDate) VALUES ($UserId, $PropertyNames, $PropertyValuesString, $PropertyValuesBinary, $LastUpdatedDate)";
					}
					cmd.Parameters.Clear ();
					cmd.Parameters.AddWithValue ("$UserId", userId);
					cmd.Parameters.AddWithValue ("$PropertyNames", names);
					cmd.Parameters.AddWithValue ("$PropertyValuesString", values);
					cmd.Parameters.AddWithValue ("$PropertyValuesBinary", buf);
					cmd.Parameters.AddWithValue ("$LastUpdatedDate", DateTime.UtcNow);

					cmd.ExecuteNonQuery ();

					cmd.CommandText = "UPDATE " + USER_TB_NAME + " SET LastActivityDate = $LastActivityDate WHERE UserId = $UserId";
					cmd.Parameters.Clear ();
					cmd.Parameters.AddWithValue ("$LastActivityDate", DateTime.UtcNow);
					cmd.Parameters.AddWithValue ("$UserId", userId);
					cmd.ExecuteNonQuery ();

					if (tran != null)
						tran.Commit ();
				}
			} catch {
				if (tran != null) {
					try {
						tran.Rollback ();
					} catch (SqliteException) {
					}
				}

				throw;
			} finally {
				if (tran != null)
					tran.Dispose ();

				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override int DeleteProfiles (ProfileInfoCollection profiles)
		{
			if (profiles == null)
				throw new ArgumentNullException ("profiles");

			if (profiles.Count < 1)
				throw new ArgumentException ("Profiles collection is empty", "profiles");

			int numDeleted = 0;
			SqliteTransaction tran = null;
			SqliteConnection cn = GetDbConnectionForProfile ();
			try {
				if (cn.State == ConnectionState.Closed)
					cn.Open ();

				if (!IsTransactionInProgress ())
					tran = cn.BeginTransaction ();

				foreach (ProfileInfo profile in profiles) {
					if (DeleteProfile (cn, tran, profile.UserName.Trim ()))
						numDeleted++;
				}

				if (tran != null)
					tran.Commit ();
			} catch {
				if (tran != null) {
					try {
						tran.Rollback ();
					} catch (SqliteException) {
					}
				}

				throw;
			} finally {
				if (tran != null)
					tran.Dispose ();

				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}

			return numDeleted;
		}

		public override int DeleteProfiles (string[] usernames)
		{
			int numDeleted = 0;
			SqliteTransaction tran = null;
			SqliteConnection cn = GetDbConnectionForProfile ();
			try {
				if (cn.State == ConnectionState.Closed)
					cn.Open ();

				if (!IsTransactionInProgress ())
					tran = cn.BeginTransaction ();

				foreach (string username in usernames) {
					if (DeleteProfile (cn, tran, username))
						numDeleted++;
				}

				if (tran != null)
					tran.Commit ();
			} catch {
				if (tran != null) {
					try {
						tran.Rollback ();
					} catch (SqliteException) {
					}
				}

				throw;
			} finally {
				if (tran != null)
					tran.Dispose ();

				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}

			return numDeleted;
		}

		public override int DeleteInactiveProfiles (ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate)
		{
			SqliteConnection cn = GetDbConnectionForProfile ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "DELETE FROM " + PROFILE_TB_NAME + " WHERE UserId IN (SELECT UserId FROM " + USER_TB_NAME
														+ " WHERE ApplicationId = $ApplicationId AND LastActivityDate <= $LastActivityDate"
														+ GetClauseForAuthenticationOptions (authenticationOption) + ")";

					cmd.Parameters.AddWithValue ("$ApplicationId", _membershipApplicationId);
					cmd.Parameters.AddWithValue ("$LastActivityDate", userInactiveSinceDate);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					return cmd.ExecuteNonQuery ();
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override int GetNumberOfInactiveProfiles (ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate)
		{
			SqliteConnection cn = GetDbConnectionForProfile ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT COUNT(*) FROM " + USER_TB_NAME + " u, " + PROFILE_TB_NAME + " p " +
														"WHERE u.ApplicationId = $ApplicationId AND u.LastActivityDate <= $LastActivityDate AND u.UserId = p.UserId" + GetClauseForAuthenticationOptions (authenticationOption);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					cmd.Parameters.AddWithValue ("$ApplicationId", _membershipApplicationId);
					cmd.Parameters.AddWithValue ("$LastActivityDate", userInactiveSinceDate);

					return cmd.ExecuteNonQuery ();
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override ProfileInfoCollection GetAllProfiles (ProfileAuthenticationOption authenticationOption, int pageIndex, int pageSize, out int totalRecords)
		{
			string sqlQuery = "SELECT u.UserName, u.IsAnonymous, u.LastActivityDate, p.LastUpdatedDate, length(p.PropertyNames) + length(p.PropertyValuesString) FROM "
												+ USER_TB_NAME + " u, " + PROFILE_TB_NAME + " p WHERE u.ApplicationId = $ApplicationId AND u.UserId = p.UserId "
												+ GetClauseForAuthenticationOptions (authenticationOption);

			SqliteParameter prm = new SqliteParameter ("$ApplicationId", DbType.String, 36);
			prm.Value = _membershipApplicationId;

			SqliteParameter[] args = new SqliteParameter[1];
			args [0] = prm;
			return GetProfilesForQuery (sqlQuery, args, pageIndex, pageSize, out totalRecords);
		}

		public override ProfileInfoCollection GetAllInactiveProfiles (ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
		{
			string sqlQuery = "SELECT u.UserName, u.IsAnonymous, u.LastActivityDate, p.LastUpdatedDate, length(p.PropertyNames) + length(p.PropertyValuesString) FROM "
												+ USER_TB_NAME + " u, " + PROFILE_TB_NAME + " p WHERE u.ApplicationId = $ApplicationId AND u.UserId = p.UserId AND u.LastActivityDate <= $LastActivityDate"
												+ GetClauseForAuthenticationOptions (authenticationOption);

			SqliteParameter prm1 = new SqliteParameter ("$ApplicationId", DbType.String, 256);
			prm1.Value = _membershipApplicationId;
			SqliteParameter prm2 = new SqliteParameter ("$LastActivityDate", DbType.DateTime);
			prm2.Value = userInactiveSinceDate;

			SqliteParameter[] args = new SqliteParameter[2];
			args [0] = prm1;
			args [1] = prm2;

			return GetProfilesForQuery (sqlQuery, args, pageIndex, pageSize, out totalRecords);
		}

		public override ProfileInfoCollection FindProfilesByUserName (ProfileAuthenticationOption authenticationOption, string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
		{
			string sqlQuery = "SELECT u.UserName, u.IsAnonymous, u.LastActivityDate, p.LastUpdatedDate, length(p.PropertyNames) + length(p.PropertyValuesString) FROM "
												+ USER_TB_NAME + " u, " + PROFILE_TB_NAME + " p WHERE u.ApplicationId = $ApplicationId AND u.UserId = p.UserId AND u.LoweredUserName LIKE $UserName"
												+ GetClauseForAuthenticationOptions (authenticationOption);

			SqliteParameter prm1 = new SqliteParameter ("$ApplicationId", DbType.String, 256);
			prm1.Value = _membershipApplicationId;
			SqliteParameter prm2 = new SqliteParameter ("$UserName", DbType.String, 256);
			prm2.Value = usernameToMatch.ToLowerInvariant ();

			SqliteParameter[] args = new SqliteParameter[2];
			args [0] = prm1;
			args [1] = prm2;

			return GetProfilesForQuery (sqlQuery, args, pageIndex, pageSize, out totalRecords);
		}

		public override ProfileInfoCollection FindInactiveProfilesByUserName (ProfileAuthenticationOption authenticationOption, string usernameToMatch, DateTime userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
		{
			string sqlQuery = "SELECT u.UserName, u.IsAnonymous, u.LastActivityDate, p.LastUpdatedDate, length(p.PropertyNames) + length(p.PropertyValuesString) FROM "
												+ USER_TB_NAME + " u, " + PROFILE_TB_NAME + " p WHERE u.ApplicationId = $ApplicationId AND u.UserId = p.UserId AND u.UserName LIKE $UserName AND u.LastActivityDate <= $LastActivityDate"
												+ GetClauseForAuthenticationOptions (authenticationOption);

			SqliteParameter prm1 = new SqliteParameter ("$ApplicationId", DbType.String, 256);
			prm1.Value = _membershipApplicationId;
			SqliteParameter prm2 = new SqliteParameter ("$UserName", DbType.String, 256);
			prm2.Value = usernameToMatch.ToLowerInvariant ();
			SqliteParameter prm3 = new SqliteParameter ("$LastActivityDate", DbType.DateTime);
			prm3.Value = userInactiveSinceDate;

			SqliteParameter[] args = new SqliteParameter[3];
			args [0] = prm1;
			args [1] = prm2;
			args [2] = prm3;

			return GetProfilesForQuery (sqlQuery, args, pageIndex, pageSize, out totalRecords);
		}

		#endregion

		#region Private Methods

		private static void CreateAnonymousUser (string username, SqliteConnection cn, SqliteTransaction tran, string userId)
		{
			using (SqliteCommand cmd = cn.CreateCommand()) {
				cmd.CommandText = "INSERT INTO " + USER_TB_NAME
													+ " (UserId, Username, LoweredUsername, ApplicationId, Email, LoweredEmail, Comment, Password,"
													+ " PasswordFormat, PasswordSalt, PasswordQuestion,"
													+ " PasswordAnswer, IsApproved, IsAnonymous,"
													+ " CreateDate, LastPasswordChangedDate, LastActivityDate,"
													+ " LastLoginDate, IsLockedOut, LastLockoutDate,"
													+ " FailedPasswordAttemptCount, FailedPasswordAttemptWindowStart,"
													+ " FailedPasswordAnswerAttemptCount, FailedPasswordAnswerAttemptWindowStart)"
													+ " Values($UserId, $Username, $LoweredUsername, $ApplicationId, $Email, $LoweredEmail, $Comment, $Password,"
													+ " $PasswordFormat, $PasswordSalt, $PasswordQuestion, $PasswordAnswer, $IsApproved, $IsAnonymous, $CreateDate, $LastPasswordChangedDate,"
													+ " $LastActivityDate, $LastLoginDate, $IsLockedOut, $LastLockoutDate,"
													+ " $FailedPasswordAttemptCount, $FailedPasswordAttemptWindowStart,"
													+ " $FailedPasswordAnswerAttemptCount, $FailedPasswordAnswerAttemptWindowStart)";

				cmd.Transaction = tran;

				DateTime nullDate = DateTime.MinValue;
				DateTime nowDate = DateTime.UtcNow;

				cmd.Parameters.Add ("$UserId", DbType.String).Value = userId;
				cmd.Parameters.Add ("$Username", DbType.String, 256).Value = username;
				cmd.Parameters.Add ("$LoweredUsername", DbType.String, 256).Value = username.ToLowerInvariant ();
				cmd.Parameters.Add ("$ApplicationId", DbType.String, 256).Value = _membershipApplicationId;
				cmd.Parameters.Add ("$Email", DbType.String, 256).Value = String.Empty;
				cmd.Parameters.Add ("$LoweredEmail", DbType.String, 256).Value = String.Empty;
				cmd.Parameters.Add ("$Comment", DbType.String, 3000).Value = null;
				cmd.Parameters.Add ("$Password", DbType.String, 128).Value = Guid.NewGuid ().ToString ();
				cmd.Parameters.Add ("$PasswordFormat", DbType.String, 128).Value = System.Web.Security.Membership.Provider.PasswordFormat.ToString ();
				cmd.Parameters.Add ("$PasswordSalt", DbType.String, 128).Value = String.Empty;
				cmd.Parameters.Add ("$PasswordQuestion", DbType.String, 256).Value = null;
				cmd.Parameters.Add ("$PasswordAnswer", DbType.String, 128).Value = null;
				cmd.Parameters.Add ("$IsApproved", DbType.Boolean).Value = true;
				cmd.Parameters.Add ("$IsAnonymous", DbType.Boolean).Value = true;
				cmd.Parameters.Add ("$CreateDate", DbType.DateTime).Value = nowDate;
				cmd.Parameters.Add ("$LastPasswordChangedDate", DbType.DateTime).Value = nullDate;
				cmd.Parameters.Add ("$LastActivityDate", DbType.DateTime).Value = nowDate;
				cmd.Parameters.Add ("$LastLoginDate", DbType.DateTime).Value = nullDate;
				cmd.Parameters.Add ("$IsLockedOut", DbType.Boolean).Value = false;
				cmd.Parameters.Add ("$LastLockoutDate", DbType.DateTime).Value = nullDate;
				cmd.Parameters.Add ("$FailedPasswordAttemptCount", DbType.Int32).Value = 0;
				cmd.Parameters.Add ("$FailedPasswordAttemptWindowStart", DbType.DateTime).Value = nullDate;
				cmd.Parameters.Add ("$FailedPasswordAnswerAttemptCount", DbType.Int32).Value = 0;
				cmd.Parameters.Add ("$FailedPasswordAnswerAttemptWindowStart", DbType.DateTime).Value = nullDate;

				if (cn.State != ConnectionState.Open)
					cn.Open ();

				cmd.ExecuteNonQuery ();
			}
		}

		private static void ParseDataFromDb (string[] names, string values, byte[] buf, SettingsPropertyValueCollection properties)
		{
			if (names == null || values == null || buf == null || properties == null)
				return;

			for (int iter = 0; iter < names.Length / 4; iter++) {
				string name = names [iter * 4];
				SettingsPropertyValue pp = properties [name];

				if (pp == null)
					continue;

				int startPos = Int32.Parse (names [iter * 4 + 2], CultureInfo.InvariantCulture);
				int length = Int32.Parse (names [iter * 4 + 3], CultureInfo.InvariantCulture);

				if (length == -1 && !pp.Property.PropertyType.IsValueType) {
					pp.PropertyValue = null;
					pp.IsDirty = false;
					pp.Deserialized = true;
				}
				if (names [iter * 4 + 1] == "S" && startPos >= 0 && length > 0 && values.Length >= startPos + length) {
					pp.PropertyValue = Deserialize (pp, values.Substring (startPos, length));
				}

				if (names [iter * 4 + 1] == "B" && startPos >= 0 && length > 0 && buf.Length >= startPos + length) {
					byte[] buf2 = new byte[length];

					Buffer.BlockCopy (buf, startPos, buf2, 0, length);
					pp.PropertyValue = Deserialize (pp, buf2);
				}
			}
		}

		private static void GetPropertyValuesFromDatabase (string username, SettingsPropertyValueCollection svc)
		{
			string[] names = null;
			string values = null;
			byte[] buffer = null;

			SqliteConnection cn = GetDbConnectionForProfile ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT UserId FROM " + USER_TB_NAME + " WHERE LoweredUsername = $UserName AND ApplicationId = $ApplicationId";
					cmd.Parameters.AddWithValue ("$UserName", username.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _membershipApplicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					string userId = cmd.ExecuteScalar () as string;

					if (userId != null) {
						cmd.CommandText = "SELECT PropertyNames, PropertyValuesString, PropertyValuesBinary FROM " + PROFILE_TB_NAME + " WHERE UserId = $UserId";
						cmd.Parameters.Clear ();
						cmd.Parameters.AddWithValue ("$UserId", userId);


						using (SqliteDataReader dr = cmd.ExecuteReader()) {
							if (dr.Read ()) {
								names = dr.GetString (0).Split (':');
								values = dr.GetString (1);
								int length = (int)dr.GetBytes (2, 0L, null, 0, 0);
								buffer = new byte[length];
								dr.GetBytes (2, 0L, buffer, 0, length);
							}
						}

						cmd.CommandText = "UPDATE " + USER_TB_NAME + " SET LastActivityDate = $LastActivityDate WHERE UserId = $UserId";
						cmd.Parameters.Clear ();
						cmd.Parameters.AddWithValue ("$LastActivityDate", DateTime.UtcNow);
						cmd.Parameters.AddWithValue ("$UserId", userId);

						cmd.ExecuteNonQuery ();
					}
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}

			if (names != null && names.Length > 0) {
				ParseDataFromDb (names, values, buffer, svc);
			}
		}

		private static string GetApplicationId (string appName)
		{
			SqliteConnection cn = GetDbConnectionForProfile ();
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

		private static void VerifyApplication ()
		{
			if (String.IsNullOrEmpty (_applicationId) || String.IsNullOrEmpty (_membershipApplicationName)) {
				SqliteConnection cn = GetDbConnectionForProfile ();
				try {
					using (SqliteCommand cmd = cn.CreateCommand()) {
						cmd.CommandText = "INSERT INTO " + APP_TB_NAME + " (ApplicationId, ApplicationName, Description) VALUES ($ApplicationId, $ApplicationName, $Description)";

						string profileApplicationId = Guid.NewGuid ().ToString ();

						cmd.Parameters.AddWithValue ("$ApplicationId", profileApplicationId);
						cmd.Parameters.AddWithValue ("$ApplicationName", _applicationName);
						cmd.Parameters.AddWithValue ("$Description", String.Empty);

						if (cn.State == ConnectionState.Closed)
							cn.Open ();

						if (String.IsNullOrEmpty (_applicationId)) {
							cmd.ExecuteNonQuery ();

							_applicationId = profileApplicationId;
						}

						if ((_applicationName != _membershipApplicationName) && (String.IsNullOrEmpty (_membershipApplicationId))) {
							_membershipApplicationId = Guid.NewGuid ().ToString ();

							cmd.Parameters ["$ApplicationId"].Value = _membershipApplicationId;
							cmd.Parameters ["$ApplicationName"].Value = _membershipApplicationName;

							cmd.ExecuteNonQuery ();
						}
					}
				} finally {
					if (!IsTransactionInProgress ())
						cn.Dispose ();
				}
			}
		}

		private static ProfileInfoCollection GetProfilesForQuery (string sqlQuery, SqliteParameter[] args, int pageIndex, int pageSize, out int totalRecords)
		{
			if (pageIndex < 0)
				throw new ArgumentException ("Page index must be non-negative", "pageIndex");

			if (pageSize < 1)
				throw new ArgumentException ("Page size must be positive", "pageSize");

			long lBound = (long)pageIndex * pageSize;
			long uBound = lBound + pageSize - 1;

			if (uBound > Int32.MaxValue) {
				throw new ArgumentException ("pageIndex*pageSize too large");
			}

			SqliteConnection cn = GetDbConnectionForProfile ();
			try {
				ProfileInfoCollection profiles = new ProfileInfoCollection ();
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = sqlQuery;

					for (int iter = 0; iter < args.Length; iter++) {
						cmd.Parameters.Add (args [iter]);
					}

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					using (SqliteDataReader dr = cmd.ExecuteReader()) {
						totalRecords = 0;
						while (dr.Read()) {
							totalRecords++;
							if ((totalRecords - 1 < lBound) || (totalRecords - 1 > uBound))
								continue;

							string username = dr.GetString (0);
							bool isAnon = dr.GetBoolean (1);
							DateTime dtLastActivity = dr.GetDateTime (2);
							DateTime dtLastUpdated = dr.GetDateTime (3);
							int size = dr.GetInt32 (4);
							profiles.Add (new ProfileInfo (username, isAnon, dtLastActivity, dtLastUpdated, size));
						}

						return profiles;
					}
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		private static bool DeleteProfile (SqliteConnection cn, SqliteTransaction tran, string username)
		{
			bool deleteSuccessful = false;

			if (cn.State != ConnectionState.Open)
				cn.Open ();

			using (SqliteCommand cmd = cn.CreateCommand()) {
				cmd.CommandText = "SELECT UserId FROM " + USER_TB_NAME + " WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId";

				cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
				cmd.Parameters.AddWithValue ("$ApplicationId", _membershipApplicationId);

				if (tran != null)
					cmd.Transaction = tran;

				string userId = cmd.ExecuteScalar () as string;
				if (userId != null) {
					cmd.CommandText = "DELETE FROM " + PROFILE_TB_NAME + " WHERE UserId = $UserId";
					cmd.Parameters.Clear ();
					cmd.Parameters.Add ("$UserId", DbType.String, 36).Value = userId;

					deleteSuccessful = (cmd.ExecuteNonQuery () != 0);
				}

				return (deleteSuccessful);
			}
		}

		private static object Deserialize (SettingsPropertyValue prop, object obj)
		{
			object val = null;

			if (obj != null) {
				if (obj is string) {
					val = GetObjectFromString (prop.Property.PropertyType, prop.Property.SerializeAs, (string)obj);
				} else {
					MemoryStream ms = new MemoryStream ((byte[])obj);
					try {
						val = (new BinaryFormatter ()).Deserialize (ms);
					} finally {
						ms.Close ();
					}
				}

				if (val != null && !prop.Property.PropertyType.IsAssignableFrom (val.GetType ()))
					val = null;
			}

			if (val == null) {
				if (prop.Property.DefaultValue == null || prop.Property.DefaultValue.ToString () == "[null]") {
					if (prop.Property.PropertyType.IsValueType)
						return Activator.CreateInstance (prop.Property.PropertyType);
					else
						return null;
				}
				if (!(prop.Property.DefaultValue is string)) {
					val = prop.Property.DefaultValue;
				} else {
					val = GetObjectFromString (prop.Property.PropertyType, prop.Property.SerializeAs, (string)prop.Property.DefaultValue);
				}

				if (val != null && !prop.Property.PropertyType.IsAssignableFrom (val.GetType ()))
					throw new ArgumentException ("Could not create from default value for property: " + prop.Property.Name);
			}

			if (val == null) {
				if (prop.Property.PropertyType == typeof(string))
					val = "";
				else
					val = Activator.CreateInstance (prop.Property.PropertyType);
			}
			return val;
		}

		private static void PrepareDataForSaving (ref string allNames, ref string allValues, ref byte[] buf, bool binarySupported, SettingsPropertyValueCollection properties, bool userIsAuthenticated)
		{
			StringBuilder names = new StringBuilder ();
			StringBuilder values = new StringBuilder ();

			MemoryStream ms = (binarySupported ? new MemoryStream () : null);
			try {
				bool anyItemsToSave = false;

				foreach (SettingsPropertyValue pp in properties) {
					if (pp.IsDirty) {
						if (!userIsAuthenticated) {
							bool allowAnonymous = (bool)pp.Property.Attributes ["AllowAnonymous"];
							if (!allowAnonymous)
								continue;
						}
						anyItemsToSave = true;
						break;
					}
				}

				if (!anyItemsToSave)
					return;

				foreach (SettingsPropertyValue pp in properties) {
					if (!userIsAuthenticated) {
						bool allowAnonymous = (bool)pp.Property.Attributes ["AllowAnonymous"];
						if (!allowAnonymous)
							continue;
					}

					if (!pp.IsDirty && pp.UsingDefaultValue)
						continue;

					int len, startPos = 0;
					string propValue = null;

					if (pp.Deserialized && pp.PropertyValue == null) {
						len = -1;
					} else {
						object sVal = SerializePropertyValue (pp);

						if (sVal == null) {
							len = -1;
						} else {
							if (!(sVal is string) && !binarySupported) {
								sVal = Convert.ToBase64String ((byte[])sVal);
							}

							if (sVal is string) {
								propValue = (string)sVal;
								len = propValue.Length;
								startPos = values.Length;
							} else {
								byte[] b2 = (byte[])sVal;

								if (ms != null) {
									startPos = (int)ms.Position;
									ms.Write (b2, 0, b2.Length);
									ms.Position = startPos + b2.Length;
								}

								len = b2.Length;
							}
						}
					}

					names.Append (pp.Name + ":" + ((propValue != null) ? "S" : "B") + ":" + startPos.ToString (CultureInfo.InvariantCulture) + ":" + len.ToString (CultureInfo.InvariantCulture) + ":");

					if (propValue != null)
						values.Append (propValue);
				}

				if (binarySupported) {
					buf = ms.ToArray ();
				}
			} finally {
				if (ms != null)
					ms.Close ();
			}

			allNames = names.ToString ();
			allValues = values.ToString ();
		}

		private static string ConvertObjectToString (object propValue, Type type, SettingsSerializeAs serializeAs, bool throwOnError)
		{
			if (serializeAs == SettingsSerializeAs.ProviderSpecific) {
				if (type == typeof(string) || type.IsPrimitive)
					serializeAs = SettingsSerializeAs.String;
				else
					serializeAs = SettingsSerializeAs.Xml;
			}

			try {
				switch (serializeAs) {
				case SettingsSerializeAs.String:
					TypeConverter converter = TypeDescriptor.GetConverter (type);
					if (converter != null && converter.CanConvertTo (typeof(String)) && converter.CanConvertFrom (typeof(String)))
						return converter.ConvertToString (propValue);
					throw new ArgumentException ("Unable to convert type " + type.ToString () + " to string", "type");
				case SettingsSerializeAs.Binary:
					MemoryStream ms = new MemoryStream ();
					try {
						BinaryFormatter bf = new BinaryFormatter ();
						bf.Serialize (ms, propValue);
						byte[] buffer = ms.ToArray ();
						return Convert.ToBase64String (buffer);
					} finally {
						ms.Close ();
					}

				case SettingsSerializeAs.Xml:
					XmlSerializer xs = new XmlSerializer (type);
					StringWriter sw = new StringWriter (CultureInfo.InvariantCulture);

					xs.Serialize (sw, propValue);
					return sw.ToString ();
				}
			} catch (Exception) {
				if (throwOnError)
					throw;
			}
			return null;
		}

		private static object SerializePropertyValue (SettingsPropertyValue prop)
		{
			object val = prop.PropertyValue;
			if (val == null)
				return null;

			if (prop.Property.SerializeAs != SettingsSerializeAs.Binary)
				return ConvertObjectToString (val, prop.Property.PropertyType, prop.Property.SerializeAs, prop.Property.ThrowOnErrorSerializing);

			MemoryStream ms = new MemoryStream ();
			try {
				BinaryFormatter bf = new BinaryFormatter ();
				bf.Serialize (ms, val);
				return ms.ToArray ();
			} finally {
				ms.Close ();
			}
		}

		private static object GetObjectFromString (Type type, SettingsSerializeAs serializeAs, string attValue)
		{
			if (type == typeof(string) && (string.IsNullOrEmpty (attValue) || serializeAs == SettingsSerializeAs.String))
				return attValue;

			if (string.IsNullOrEmpty (attValue))
				return null;

			switch (serializeAs) {
			
				case SettingsSerializeAs.Binary:
					byte[] buf = Convert.FromBase64String(attValue);
					MemoryStream ms = null;
					try
					{
						ms = new MemoryStream(buf);
						return (new BinaryFormatter()).Deserialize(ms);
					}
					finally
					{
						if (ms != null)
							ms.Close();
					}

				
			case SettingsSerializeAs.Xml:
				StringReader sr = new StringReader (attValue);
				XmlSerializer xs = new XmlSerializer (type);
				return xs.Deserialize (sr);

			case SettingsSerializeAs.String:
				TypeConverter converter = TypeDescriptor.GetConverter (type);
				if (converter != null && converter.CanConvertTo (typeof(String)) && converter.CanConvertFrom (typeof(String)))
					return converter.ConvertFromString (attValue);
				throw new ArgumentException ("Unable to convert type: " + type.ToString () + " from string", "type");

			default:
				return null;
			}
		}

		private static string GetClauseForAuthenticationOptions (ProfileAuthenticationOption authenticationOption)
		{
			switch (authenticationOption) {
			case ProfileAuthenticationOption.Anonymous:
				return " AND IsAnonymous='1' ";

			case ProfileAuthenticationOption.Authenticated:
				return " AND IsAnonymous='0' ";

			case ProfileAuthenticationOption.All:
				return " ";

			default:
				throw new InvalidEnumArgumentException (String.Format ("Unknown ProfileAuthenticationOption value: {0}.", authenticationOption.ToString ()));
			}
		}

		[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate")]
		private static SqliteConnection GetDbConnectionForProfile ()
		{
			if (System.Web.HttpContext.Current != null) {
				SqliteTransaction tran = (SqliteTransaction)System.Web.HttpContext.Current.Items [HTTP_TRANSACTION_ID];

				if ((tran != null) && (String.Equals (tran.Connection.ConnectionString, _connectionString)))
					return tran.Connection;
			}

			return new SqliteConnection (_connectionString);
		}

		private static bool IsTransactionInProgress ()
		{
			if (System.Web.HttpContext.Current == null)
				return false;

			SqliteTransaction tran = (SqliteTransaction)System.Web.HttpContext.Current.Items [HTTP_TRANSACTION_ID];

			if ((tran != null) && (String.Equals (tran.Connection.ConnectionString, _connectionString)))
				return true;
			else
				return false;
		}

		#endregion

	}
}

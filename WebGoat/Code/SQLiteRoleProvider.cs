using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Data;
using Mono.Data.Sqlite;
using System.Web.Security;

namespace TechInfoSystems.Data.SQLite
{
	public sealed class SQLiteRoleProvider : RoleProvider
	{
		#region Private Fields

		private const string HTTP_TRANSACTION_ID = "SQLiteTran";
		private const string APP_TB_NAME = "[aspnet_Applications]";
		private const string ROLE_TB_NAME = "[aspnet_Roles]";
		private const string USER_TB_NAME = "[aspnet_Users]";
		private const string USERS_IN_ROLES_TB_NAME = "[aspnet_UsersInRoles]";
		private const int MAX_USERNAME_LENGTH = 256;
		private const int MAX_ROLENAME_LENGTH = 256;
		private const int MAX_APPLICATION_NAME_LENGTH = 256;
		private static string _applicationId;
		private static string _applicationName;
		private static string _membershipApplicationId;
		private static string _membershipApplicationName;
		private static string _connectionString;

		#endregion

		#region Public Properties

		public override string ApplicationName {
			get { return _applicationName; }
			set {
				if (value.Length > MAX_APPLICATION_NAME_LENGTH)
					throw new ProviderException (String.Format ("SQLiteRoleProvider error: applicationName must be less than or equal to {0} characters.", MAX_APPLICATION_NAME_LENGTH));

				_applicationName = value;
				_applicationId = GetApplicationId (_applicationName);
			}
		}

		public static string MembershipApplicationName {
			get { return _membershipApplicationName; }
			set {
				if (value.Length > MAX_APPLICATION_NAME_LENGTH)
					throw new ProviderException (String.Format ("SQLiteRoleProvider error: membershipApplicationName must be less than or equal to {0} characters.", MAX_APPLICATION_NAME_LENGTH));

				_membershipApplicationName = value;
				_membershipApplicationId = ((_applicationName == _membershipApplicationName) ? _applicationId : GetApplicationId (_membershipApplicationName));
			}
		}

		#endregion

		#region Public Methods

		public override void Initialize (string name, NameValueCollection config)
		{
			if (config == null)
				throw new ArgumentNullException ("config");

			if (name == null || name.Length == 0)
				name = "SQLiteRoleProvider";

			if (String.IsNullOrEmpty (config ["description"])) {
				config.Remove ("description");
				config.Add ("description", "SQLite Role provider");
			}

			base.Initialize (name, config);

			ConnectionStringSettings connectionStringSettings = ConfigurationManager.ConnectionStrings [config ["connectionStringName"]];

			if (connectionStringSettings == null || connectionStringSettings.ConnectionString.Trim () == "") {
				throw new ProviderException ("Connection string is empty for SQLiteRoleProvider. Check the web configuration file (web.config).");
			}

			_connectionString = connectionStringSettings.ConnectionString;

			if (config ["applicationName"] == null || config ["applicationName"].Trim () == "") {
				this.ApplicationName = System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath;
			} else {
				this.ApplicationName = config ["applicationName"];
			}

			if (config ["membershipApplicationName"] == null || config ["membershipApplicationName"].Trim () == "") {
				MembershipApplicationName = ApplicationName;
			} else {
				MembershipApplicationName = config ["membershipApplicationName"];
			}

			config.Remove ("connectionStringName");
			config.Remove ("applicationName");
			config.Remove ("membershipApplicationName");
			config.Remove ("name");

			if (config.Count > 0) {
				string key = config.GetKey (0);
				if (!string.IsNullOrEmpty (key)) {
					throw new ProviderException (String.Concat ("SQLiteRoleProvider configuration error: Unrecognized attribute: ", key));
				}
			}

			VerifyApplication ();
		}

		public override void AddUsersToRoles (string[] usernames, string[] roleNames)
		{
			foreach (string roleName in roleNames) {
				if (!RoleExists (roleName)) {
					throw new ProviderException ("Role name not found.");
				}
			}

			foreach (string username in usernames) {
				if (username.IndexOf (',') > 0) {
					throw new ArgumentException ("User names cannot contain commas.");
				}

				foreach (string roleName in roleNames) {
					if (IsUserInRole (username, roleName)) {
						throw new ProviderException ("User is already in role.");
					}
				}
			}

			SqliteTransaction tran = null;
			SqliteConnection cn = GetDbConnectionForRole ();
			try {
				if (cn.State == ConnectionState.Closed)
					cn.Open ();

				if (!IsTransactionInProgress ())
					tran = cn.BeginTransaction ();

				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "INSERT INTO " + USERS_IN_ROLES_TB_NAME
						+ " (UserId, RoleId)"
						+ " SELECT u.UserId, r.RoleId"
						+ " FROM " + USER_TB_NAME + " u, " + ROLE_TB_NAME + " r"
						+ " WHERE (u.LoweredUsername = $Username) AND (u.ApplicationId = $MembershipApplicationId)"
						+ " AND (r.LoweredRoleName = $RoleName) AND (r.ApplicationId = $ApplicationId)";

					SqliteParameter userParm = cmd.Parameters.Add ("$Username", DbType.String, MAX_USERNAME_LENGTH);
					SqliteParameter roleParm = cmd.Parameters.Add ("$RoleName", DbType.String, MAX_ROLENAME_LENGTH);
					cmd.Parameters.AddWithValue ("$MembershipApplicationId", _membershipApplicationId);
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					foreach (string username in usernames) {
						foreach (string roleName in roleNames) {
							userParm.Value = username.ToLowerInvariant ();
							roleParm.Value = roleName.ToLowerInvariant ();
							cmd.ExecuteNonQuery ();
						}
					}

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

		public override void CreateRole (string roleName)
		{
			if (roleName.IndexOf (',') > 0) {
				throw new ArgumentException ("Role names cannot contain commas.");
			}

			if (RoleExists (roleName)) {
				throw new ProviderException ("Role name already exists.");
			}

			if (!SecUtility.ValidateParameter (ref roleName, true, true, false, MAX_ROLENAME_LENGTH)) {
				throw new ProviderException (String.Format ("The role name is too long: it must not exceed {0} chars in length.", MAX_ROLENAME_LENGTH));
			}

			SqliteConnection cn = GetDbConnectionForRole ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "INSERT INTO " + ROLE_TB_NAME
						+ " (RoleId, RoleName, LoweredRoleName, ApplicationId) "
						+ " Values ($RoleId, $RoleName, $LoweredRoleName, $ApplicationId)";

					cmd.Parameters.AddWithValue ("$RoleId", Guid.NewGuid ().ToString ());
					cmd.Parameters.AddWithValue ("$RoleName", roleName);
					cmd.Parameters.AddWithValue ("$LoweredRoleName", roleName.ToLowerInvariant ());
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

		public override bool DeleteRole (string roleName, bool throwOnPopulatedRole)
		{
			if (!RoleExists (roleName)) {
				throw new ProviderException ("Role does not exist.");
			}

			if (throwOnPopulatedRole && GetUsersInRole (roleName).Length > 0) {
				throw new ProviderException ("Cannot delete a populated role.");
			}

			SqliteTransaction tran = null;
			SqliteConnection cn = GetDbConnectionForRole ();
			try {
				if (cn.State == ConnectionState.Closed)
					cn.Open ();

				if (!IsTransactionInProgress ())
					tran = cn.BeginTransaction ();

				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "DELETE FROM " + USERS_IN_ROLES_TB_NAME + " WHERE (RoleId IN"
														 + " (SELECT RoleId FROM " + ROLE_TB_NAME + " WHERE LoweredRoleName = $RoleName))";

					cmd.Parameters.AddWithValue ("$RoleName", roleName.ToLowerInvariant ());

					cmd.ExecuteNonQuery ();
				}

				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "DELETE FROM " + ROLE_TB_NAME + " WHERE LoweredRoleName = $RoleName AND ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue ("$RoleName", roleName.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					cmd.ExecuteNonQuery ();
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

			return true;
		}

		public override string[] GetAllRoles ()
		{
			string tmpRoleNames = String.Empty;

			SqliteConnection cn = GetDbConnectionForRole ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT RoleName FROM " + ROLE_TB_NAME + " WHERE ApplicationId = $ApplicationId";
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					using (SqliteDataReader dr = cmd.ExecuteReader()) {
						while (dr.Read()) {
							tmpRoleNames += dr.GetString (0) + ",";
						}
					}
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}

			if (tmpRoleNames.Length > 0) {
				tmpRoleNames = tmpRoleNames.Substring (0, tmpRoleNames.Length - 1);
				return tmpRoleNames.Split (',');
			}

			return new string[0];
		}

		public override string[] GetRolesForUser (string username)
		{
			string tmpRoleNames = String.Empty;

			SqliteConnection cn = GetDbConnectionForRole ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT r.RoleName FROM " + ROLE_TB_NAME + " r INNER JOIN " + USERS_IN_ROLES_TB_NAME
						+ " uir ON r.RoleId = uir.RoleId INNER JOIN " + USER_TB_NAME + " u ON uir.UserId = u.UserId"
						+ " WHERE (u.LoweredUsername = $Username) AND (u.ApplicationId = $MembershipApplicationId)";

					cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$MembershipApplicationId", _membershipApplicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					using (SqliteDataReader dr = cmd.ExecuteReader()) {
						while (dr.Read()) {
							tmpRoleNames += dr.GetString (0) + ",";
						}
					}
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}

			if (tmpRoleNames.Length > 0) {
				tmpRoleNames = tmpRoleNames.Substring (0, tmpRoleNames.Length - 1);
				return tmpRoleNames.Split (',');
			}

			return new string[0];
		}

		public override string[] GetUsersInRole (string roleName)
		{
			string tmpUserNames = String.Empty;

			SqliteConnection cn = GetDbConnectionForRole ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT u.Username FROM " + USER_TB_NAME + " u INNER JOIN " + USERS_IN_ROLES_TB_NAME
						+ " uir ON u.UserId = uir.UserId INNER JOIN " + ROLE_TB_NAME + " r ON uir.RoleId = r.RoleId"
						+ " WHERE (r.LoweredRoleName = $RoleName) AND (r.ApplicationId = $ApplicationId)";

					cmd.Parameters.AddWithValue ("$RoleName", roleName.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					using (SqliteDataReader dr = cmd.ExecuteReader()) {
						while (dr.Read()) {
							tmpUserNames += dr.GetString (0) + ",";
						}
					}
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}

			if (tmpUserNames.Length > 0) {
				tmpUserNames = tmpUserNames.Substring (0, tmpUserNames.Length - 1);
				return tmpUserNames.Split (',');
			}

			return new string[0];
		}

		public override bool IsUserInRole (string username, string roleName)
		{
			SqliteConnection cn = GetDbConnectionForRole ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT COUNT(*) FROM " + USERS_IN_ROLES_TB_NAME + " uir INNER JOIN "
						+ USER_TB_NAME + " u ON uir.UserId = u.UserId INNER JOIN " + ROLE_TB_NAME + " r ON uir.RoleId = r.RoleId "
						+ " WHERE u.LoweredUsername = $Username AND u.ApplicationId = $MembershipApplicationId"
						+ " AND r.LoweredRoleName = $RoleName AND r.ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue ("$Username", username.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$RoleName", roleName.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$MembershipApplicationId", _membershipApplicationId);
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					return (Convert.ToInt64 (cmd.ExecuteScalar ()) > 0);
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override void RemoveUsersFromRoles (string[] usernames, string[] roleNames)
		{
			foreach (string roleName in roleNames) {
				if (!RoleExists (roleName)) {
					throw new ProviderException ("Role name not found.");
				}
			}

			foreach (string username in usernames) {
				foreach (string roleName in roleNames) {
					if (!IsUserInRole (username, roleName)) {
						throw new ProviderException ("User is not in role.");
					}
				}
			}

			SqliteTransaction tran = null;
			SqliteConnection cn = GetDbConnectionForRole ();
			try {
				if (cn.State == ConnectionState.Closed)
					cn.Open ();

				if (!IsTransactionInProgress ())
					tran = cn.BeginTransaction ();

				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "DELETE FROM " + USERS_IN_ROLES_TB_NAME
						+ " WHERE UserId = (SELECT UserId FROM " + USER_TB_NAME + " WHERE LoweredUsername = $Username AND ApplicationId = $MembershipApplicationId)"
						+ " AND RoleId = (SELECT RoleId FROM " + ROLE_TB_NAME + " WHERE LoweredRoleName = $RoleName AND ApplicationId = $ApplicationId)";

					SqliteParameter userParm = cmd.Parameters.Add ("$Username", DbType.String, MAX_USERNAME_LENGTH);
					SqliteParameter roleParm = cmd.Parameters.Add ("$RoleName", DbType.String, MAX_ROLENAME_LENGTH);
					cmd.Parameters.AddWithValue ("$MembershipApplicationId", _membershipApplicationId);
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					foreach (string username in usernames) {
						foreach (string roleName in roleNames) {
							userParm.Value = username.ToLowerInvariant ();
							roleParm.Value = roleName.ToLowerInvariant ();
							cmd.ExecuteNonQuery ();
						}
					}

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

		public override bool RoleExists (string roleName)
		{
			SqliteConnection cn = GetDbConnectionForRole ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT COUNT(*) FROM " + ROLE_TB_NAME +
								" WHERE LoweredRoleName = $RoleName AND ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue ("$RoleName", roleName.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					return (Convert.ToInt64 (cmd.ExecuteScalar ()) > 0);
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}
		}

		public override string[] FindUsersInRole (string roleName, string usernameToMatch)
		{
			string tmpUserNames = String.Empty;

			SqliteConnection cn = GetDbConnectionForRole ();
			try {
				using (SqliteCommand cmd = cn.CreateCommand()) {
					cmd.CommandText = "SELECT u.Username FROM " + USERS_IN_ROLES_TB_NAME + " uir INNER JOIN " + USER_TB_NAME
						+ " u ON uir.UserId = u.UserId INNER JOIN " + ROLE_TB_NAME + " r ON r.RoleId = uir.RoleId"
						+ " WHERE u.LoweredUsername LIKE $UsernameSearch AND r.LoweredRoleName = $RoleName AND u.ApplicationId = $MembershipApplicationId"
						+ " AND r.ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue ("$UsernameSearch", usernameToMatch);
					cmd.Parameters.AddWithValue ("$RoleName", roleName.ToLowerInvariant ());
					cmd.Parameters.AddWithValue ("$MembershipApplicationId", _membershipApplicationId);
					cmd.Parameters.AddWithValue ("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open ();

					using (SqliteDataReader dr = cmd.ExecuteReader()) {
						while (dr.Read()) {
							tmpUserNames += dr.GetString (0) + ",";
						}
					}
				}
			} finally {
				if (!IsTransactionInProgress ())
					cn.Dispose ();
			}

			if (tmpUserNames.Length > 0) {
				tmpUserNames = tmpUserNames.Substring (0, tmpUserNames.Length - 1);
				return tmpUserNames.Split (',');
			}

			return new string[0];
		}

		#endregion

		#region Private Methods

		private static string GetApplicationId (string appName)
		{
			SqliteConnection cn = GetDbConnectionForRole ();
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

		private void VerifyApplication ()
		{
			if (String.IsNullOrEmpty (_applicationId) || String.IsNullOrEmpty (_membershipApplicationName)) {
				SqliteConnection cn = GetDbConnectionForRole ();
				try {
					using (SqliteCommand cmd = cn.CreateCommand()) {
						cmd.CommandText = "INSERT INTO " + APP_TB_NAME + " (ApplicationId, ApplicationName, Description) VALUES ($ApplicationId, $ApplicationName, $Description)";

						string roleApplicationId = Guid.NewGuid ().ToString ();

						cmd.Parameters.AddWithValue ("$ApplicationId", roleApplicationId);
						cmd.Parameters.AddWithValue ("$ApplicationName", _applicationName);
						cmd.Parameters.AddWithValue ("$Description", String.Empty);

						if (cn.State == ConnectionState.Closed)
							cn.Open ();

						if (String.IsNullOrEmpty (_applicationId)) {
							cmd.ExecuteNonQuery ();

							_applicationId = roleApplicationId;
						}

						if (String.IsNullOrEmpty (_membershipApplicationId)) {
							if (_applicationName == _membershipApplicationName) {
								MembershipApplicationName = ApplicationName;
							} else {
								_membershipApplicationId = Guid.NewGuid ().ToString ();

								cmd.Parameters ["$ApplicationId"].Value = _membershipApplicationId;
								cmd.Parameters ["$ApplicationName"].Value = _membershipApplicationName;

								cmd.ExecuteNonQuery ();
							}
						}
					}
				} finally {
					if (!IsTransactionInProgress ())
						cn.Dispose ();
				}
			}
		}

		[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate")]
		private static SqliteConnection GetDbConnectionForRole ()
		{
			if (System.Web.HttpContext.Current != null) {
				const string HTTP_TRANSACTION_ID = "SQLiteTran";
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

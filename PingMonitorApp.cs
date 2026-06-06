using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml;

namespace SeguritechPingMonitor
{
    public static class Program
    {
        [STAThread]
        public static void Main()
        {
            bool created;
            using (Mutex mutex = new Mutex(true, "ping_scan.SingleInstance", out created))
            {
                if (!created)
                {
                    MessageBox.Show(
                        "ping_scan ya esta abierto. Cierre la instancia actual antes de abrir otra.",
                        "ping_scan",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                    return;
                }

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                try
                {
                    UserStore userStore = new UserStore(Path.Combine(Application.StartupPath, "users.xml"));
                    while (true)
                    {
                        using (SignInDialog signIn = new SignInDialog(userStore))
                        {
                            if (signIn.ShowDialog() != DialogResult.OK)
                            {
                                return;
                            }

                            MainForm mainForm = new MainForm(signIn.Username, signIn.Role);
                            Application.Run(mainForm);
                            if (!mainForm.LogoutRequested)
                            {
                                return;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(
                        "No se pudo iniciar el control de usuarios:\r\n" + ex.Message,
                        "ping_scan",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                }
            }
        }
    }

    public sealed class DeviceRecord : INotifyPropertyChanged
    {
        private string _name;
        private string _ip;
        private string _type;
        private string _status;
        private string _latency;
        private string _lastCheck;
        private int _failures;
        private string _subcenter;
        private string _affiliation;
        private string _notes;

        public event PropertyChangedEventHandler PropertyChanged;

        public DeviceRecord()
        {
            _name = "";
            _ip = "";
            _type = "Fija";
            _status = "Pendiente";
            _latency = "";
            _lastCheck = "";
            _subcenter = "";
            _affiliation = "";
            _notes = "";
        }

        public string Name
        {
            get { return _name; }
            set { SetString(ref _name, value, "Name"); }
        }

        public string Ip
        {
            get { return _ip; }
            set { SetString(ref _ip, value, "Ip"); }
        }

        public string Type
        {
            get { return _type; }
            set { SetString(ref _type, value, "Type"); }
        }

        public string Status
        {
            get { return _status; }
            set { SetString(ref _status, value, "Status"); }
        }

        public string Latency
        {
            get { return _latency; }
            set { SetString(ref _latency, value, "Latency"); }
        }

        public string LastCheck
        {
            get { return _lastCheck; }
            set { SetString(ref _lastCheck, value, "LastCheck"); }
        }

        public int Failures
        {
            get { return _failures; }
            set
            {
                if (_failures != value)
                {
                    _failures = value;
                    OnPropertyChanged("Failures");
                }
            }
        }

        public string Affiliation
        {
            get { return _affiliation; }
            set { SetString(ref _affiliation, value, "Affiliation"); }
        }

        public string Subcenter
        {
            get { return _subcenter; }
            set { SetString(ref _subcenter, value, "Subcenter"); }
        }

        public string Notes
        {
            get { return _notes; }
            set { SetString(ref _notes, value, "Notes"); }
        }

        private void SetString(ref string field, string value, string name)
        {
            string next = value == null ? "" : value;
            if (field != next)
            {
                field = next;
                OnPropertyChanged(name);
            }
        }

        private void OnPropertyChanged(string name)
        {
            PropertyChangedEventHandler handler = PropertyChanged;
            if (handler != null)
            {
                handler(this, new PropertyChangedEventArgs(name));
            }
        }
    }

    public sealed class UserStore
    {
        public const string RoleAdministrator = "Administrador";
        public const string RoleSupervisor = "Supervisor";
        public const string RoleMonitor = "Monitor";
        public const string LanguageSpanish = "Español";
        public const string LanguageEnglish = "English";

        private const int PasswordSaltBytes = 16;
        private const int PasswordHashBytes = 32;
        private const int PasswordHashIterations = 12000;
        public const int DefaultIntervalSeconds = 3600;
        public const int DefaultTimeoutMs = 1000;
        public const int DefaultDashboardDays = 3;

        private static readonly string[] Roles = new string[]
        {
            RoleAdministrator,
            RoleSupervisor,
            RoleMonitor
        };

        private static readonly string[] Languages = new string[]
        {
            LanguageSpanish,
            LanguageEnglish
        };

        private readonly string _path;

        public UserStore(string path)
        {
            _path = path;
        }

        public bool HasUsers()
        {
            return LoadUsers().Count > 0;
        }

        public bool CreateUser(string username, string password, out string message)
        {
            return CreateUser(username, password, RoleAdministrator, out message);
        }

        public bool CreateUser(string username, string password, string role, out string message)
        {
            username = NormalizeUsername(username);
            role = NormalizeRole(role);
            if (String.IsNullOrWhiteSpace(username))
            {
                message = "Capture el usuario.";
                return false;
            }

            if (username.Length < 3)
            {
                message = "El usuario debe tener al menos 3 caracteres.";
                return false;
            }

            if (String.IsNullOrEmpty(password) || password.Length < 6)
            {
                message = "La contrasena debe tener al menos 6 caracteres.";
                return false;
            }

            List<UserAccount> users = LoadUsers();
            for (int i = 0; i < users.Count; i++)
            {
                if (String.Equals(users[i].Username, username, StringComparison.OrdinalIgnoreCase))
                {
                    message = "Ese usuario ya existe.";
                    return false;
                }
            }

            byte[] salt = CreateSalt();
            byte[] hash = HashPassword(password, salt);

            UserAccount account = new UserAccount();
            account.Username = username;
            account.PasswordSalt = Convert.ToBase64String(salt);
            account.PasswordHash = Convert.ToBase64String(hash);
            account.Role = role;
            account.Language = LanguageSpanish;
            account.ProfileImagePath = "";
            account.DefaultIntervalSeconds = DefaultIntervalSeconds;
            account.DefaultTimeoutMs = DefaultTimeoutMs;
            account.DashboardDays = DefaultDashboardDays;
            account.CreatedAt = DateTime.Now;
            users.Add(account);
            SaveUsers(users);

            message = "";
            return true;
        }

        public bool ValidateUser(string username, string password, out string message)
        {
            string role;
            return ValidateUser(username, password, out role, out message);
        }

        public bool ValidateUser(string username, string password, out string role, out string message)
        {
            role = "";
            username = NormalizeUsername(username);
            if (String.IsNullOrWhiteSpace(username) || String.IsNullOrEmpty(password))
            {
                message = "Capture usuario y contrasena.";
                return false;
            }

            List<UserAccount> users = LoadUsers();
            if (users.Count == 0)
            {
                message = "No hay usuarios registrados.";
                return false;
            }

            UserAccount account = null;
            for (int i = 0; i < users.Count; i++)
            {
                if (String.Equals(users[i].Username, username, StringComparison.OrdinalIgnoreCase))
                {
                    account = users[i];
                    break;
                }
            }

            if (account == null)
            {
                message = "Usuario o contrasena incorrectos.";
                return false;
            }

            try
            {
                byte[] salt = Convert.FromBase64String(account.PasswordSalt);
                byte[] expected = Convert.FromBase64String(account.PasswordHash);
                byte[] actual = HashPassword(password, salt);
                if (!ConstantTimeEquals(expected, actual))
                {
                    message = "Usuario o contrasena incorrectos.";
                    return false;
                }
            }
            catch
            {
                message = "No se pudo validar este usuario.";
                return false;
            }

            role = NormalizeRole(account.Role);
            message = "";
            return true;
        }

        public List<UserProfile> GetUsers()
        {
            List<UserAccount> accounts = LoadUsers();
            List<UserProfile> users = new List<UserProfile>();
            for (int i = 0; i < accounts.Count; i++)
            {
                users.Add(ToProfile(accounts[i]));
            }

            users.Sort(delegate(UserProfile left, UserProfile right)
            {
                return String.Compare(left.Username, right.Username, StringComparison.OrdinalIgnoreCase);
            });

            return users;
        }

        public UserProfile GetUserProfile(string username)
        {
            username = NormalizeUsername(username);
            List<UserAccount> users = LoadUsers();
            for (int i = 0; i < users.Count; i++)
            {
                if (String.Equals(users[i].Username, username, StringComparison.OrdinalIgnoreCase))
                {
                    return ToProfile(users[i]);
                }
            }

            UserProfile profile = new UserProfile();
            profile.Username = username;
            profile.Role = RoleAdministrator;
            profile.Language = LanguageSpanish;
            profile.ProfileImagePath = "";
            profile.DefaultIntervalSeconds = DefaultIntervalSeconds;
            profile.DefaultTimeoutMs = DefaultTimeoutMs;
            profile.DashboardDays = DefaultDashboardDays;
            return profile;
        }

        public bool UpdateAccountSettings(string username, string profileImagePath, string language, int defaultIntervalSeconds, int defaultTimeoutMs, int dashboardDays, out string message)
        {
            username = NormalizeUsername(username);
            if (String.IsNullOrWhiteSpace(username))
            {
                message = "No se encontro la sesion actual.";
                return false;
            }

            List<UserAccount> users = LoadUsers();
            int index = -1;
            for (int i = 0; i < users.Count; i++)
            {
                if (String.Equals(users[i].Username, username, StringComparison.OrdinalIgnoreCase))
                {
                    index = i;
                    break;
                }
            }

            if (index < 0)
            {
                message = "No se encontro el usuario.";
                return false;
            }

            users[index].ProfileImagePath = profileImagePath == null ? "" : profileImagePath.Trim();
            users[index].Language = NormalizeLanguage(language);
            users[index].DefaultIntervalSeconds = ClampInt(defaultIntervalSeconds, 5, 86400, DefaultIntervalSeconds);
            users[index].DefaultTimeoutMs = ClampInt(defaultTimeoutMs, 250, 10000, DefaultTimeoutMs);
            users[index].DashboardDays = ClampInt(dashboardDays, 1, 30, DefaultDashboardDays);
            SaveUsers(users);
            message = "";
            return true;
        }

        public void AppendAudit(string actor, string action, string detail)
        {
            try
            {
                string directory = Path.GetDirectoryName(_path);
                if (String.IsNullOrWhiteSpace(directory))
                {
                    directory = Application.StartupPath;
                }

                string path = Path.Combine(directory, "account_audit.log");
                string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
                    + " | actor=" + (actor == null ? "" : actor)
                    + " | action=" + (action == null ? "" : action)
                    + " | detail=" + (detail == null ? "" : detail.Replace("\r", " ").Replace("\n", " "))
                    + Environment.NewLine;
                File.AppendAllText(path, line, Encoding.UTF8);
            }
            catch
            {
                // Audit failures should not block account access.
            }
        }

        public bool UpdateUser(string originalUsername, string username, string password, bool changePassword, string role, out string message)
        {
            originalUsername = NormalizeUsername(originalUsername);
            username = NormalizeUsername(username);
            role = NormalizeRole(role);
            if (String.IsNullOrWhiteSpace(originalUsername))
            {
                message = "Seleccione un usuario.";
                return false;
            }

            if (String.IsNullOrWhiteSpace(username))
            {
                message = "Capture el usuario.";
                return false;
            }

            if (username.Length < 3)
            {
                message = "El usuario debe tener al menos 3 caracteres.";
                return false;
            }

            if (changePassword && (String.IsNullOrEmpty(password) || password.Length < 6))
            {
                message = "La contrasena debe tener al menos 6 caracteres.";
                return false;
            }

            List<UserAccount> users = LoadUsers();
            int index = -1;
            for (int i = 0; i < users.Count; i++)
            {
                if (String.Equals(users[i].Username, originalUsername, StringComparison.OrdinalIgnoreCase))
                {
                    index = i;
                    break;
                }
            }

            if (index < 0)
            {
                message = "No se encontro el usuario.";
                return false;
            }

            for (int i = 0; i < users.Count; i++)
            {
                if (i != index && String.Equals(users[i].Username, username, StringComparison.OrdinalIgnoreCase))
                {
                    message = "Ese usuario ya existe.";
                    return false;
                }
            }

            if (NormalizeRole(users[index].Role) == RoleAdministrator && role != RoleAdministrator && CountAdministrators(users) <= 1)
            {
                message = "Debe existir al menos un administrador.";
                return false;
            }

            users[index].Username = username;
            users[index].Role = role;
            if (changePassword)
            {
                byte[] salt = CreateSalt();
                byte[] hash = HashPassword(password, salt);
                users[index].PasswordSalt = Convert.ToBase64String(salt);
                users[index].PasswordHash = Convert.ToBase64String(hash);
            }

            SaveUsers(users);
            message = "";
            return true;
        }

        public bool DeleteUser(string username, out string message)
        {
            username = NormalizeUsername(username);
            if (String.IsNullOrWhiteSpace(username))
            {
                message = "Seleccione un usuario.";
                return false;
            }

            List<UserAccount> users = LoadUsers();
            if (users.Count <= 1)
            {
                message = "Debe existir al menos un usuario.";
                return false;
            }

            int index = -1;
            for (int i = 0; i < users.Count; i++)
            {
                if (String.Equals(users[i].Username, username, StringComparison.OrdinalIgnoreCase))
                {
                    index = i;
                    break;
                }
            }

            if (index < 0)
            {
                message = "No se encontro el usuario.";
                return false;
            }

            if (NormalizeRole(users[index].Role) == RoleAdministrator && CountAdministrators(users) <= 1)
            {
                message = "Debe existir al menos un administrador.";
                return false;
            }

            users.RemoveAt(index);
            SaveUsers(users);
            message = "";
            return true;
        }

        private static int CountAdministrators(List<UserAccount> users)
        {
            int count = 0;
            if (users == null)
            {
                return count;
            }

            for (int i = 0; i < users.Count; i++)
            {
                if (NormalizeRole(users[i].Role) == RoleAdministrator)
                {
                    count++;
                }
            }

            return count;
        }

        private static UserProfile ToProfile(UserAccount account)
        {
            UserProfile profile = new UserProfile();
            profile.Username = account == null ? "" : account.Username;
            profile.Role = NormalizeRole(account == null ? "" : account.Role);
            profile.ProfileImagePath = account == null ? "" : account.ProfileImagePath;
            profile.Language = NormalizeLanguage(account == null ? "" : account.Language);
            profile.DefaultIntervalSeconds = ClampInt(account == null ? 0 : account.DefaultIntervalSeconds, 5, 86400, DefaultIntervalSeconds);
            profile.DefaultTimeoutMs = ClampInt(account == null ? 0 : account.DefaultTimeoutMs, 250, 10000, DefaultTimeoutMs);
            profile.DashboardDays = ClampInt(account == null ? 0 : account.DashboardDays, 1, 30, DefaultDashboardDays);
            profile.CreatedAt = account == null ? DateTime.MinValue : account.CreatedAt;
            return profile;
        }

        private static int ClampInt(int value, int min, int max, int fallback)
        {
            if (value < min || value > max)
            {
                return fallback;
            }

            return value;
        }

        private List<UserAccount> LoadUsers()
        {
            List<UserAccount> users = new List<UserAccount>();
            if (!File.Exists(_path))
            {
                return users;
            }

            XmlDocument doc = new XmlDocument();
            doc.Load(_path);
            XmlNodeList nodes = doc.SelectNodes("/users/user");
            if (nodes == null)
            {
                return users;
            }

            foreach (XmlNode node in nodes)
            {
                UserAccount account = new UserAccount();
                account.Username = ReadAttribute(node, "username");
                account.PasswordSalt = ReadAttribute(node, "salt");
                account.PasswordHash = ReadAttribute(node, "hash");
                account.Role = NormalizeRole(ReadAttribute(node, "role"));
                account.ProfileImagePath = ReadAttribute(node, "profileImage");
                account.Language = NormalizeLanguage(ReadAttribute(node, "language"));
                account.DefaultIntervalSeconds = ReadIntAttribute(node, "intervalSeconds", DefaultIntervalSeconds);
                account.DefaultTimeoutMs = ReadIntAttribute(node, "timeoutMs", DefaultTimeoutMs);
                account.DashboardDays = ReadIntAttribute(node, "dashboardDays", DefaultDashboardDays);

                DateTime createdAt;
                if (DateTime.TryParse(ReadAttribute(node, "createdAt"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out createdAt)
                    || DateTime.TryParse(ReadAttribute(node, "createdAt"), out createdAt))
                {
                    account.CreatedAt = createdAt;
                }

                if (!String.IsNullOrWhiteSpace(account.Username)
                    && !String.IsNullOrWhiteSpace(account.PasswordSalt)
                    && !String.IsNullOrWhiteSpace(account.PasswordHash))
                {
                    users.Add(account);
                }
            }

            return users;
        }

        private void SaveUsers(List<UserAccount> users)
        {
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            settings.Encoding = Encoding.UTF8;

            using (XmlWriter writer = XmlWriter.Create(_path, settings))
            {
                writer.WriteStartDocument();
                writer.WriteStartElement("users");
                for (int i = 0; i < users.Count; i++)
                {
                    UserAccount account = users[i];
                    writer.WriteStartElement("user");
                    writer.WriteAttributeString("username", NormalizeUsername(account.Username));
                    writer.WriteAttributeString("role", NormalizeRole(account.Role));
                    writer.WriteAttributeString("profileImage", account.ProfileImagePath == null ? "" : account.ProfileImagePath);
                    writer.WriteAttributeString("language", NormalizeLanguage(account.Language));
                    writer.WriteAttributeString("intervalSeconds", ClampInt(account.DefaultIntervalSeconds, 5, 86400, DefaultIntervalSeconds).ToString(CultureInfo.InvariantCulture));
                    writer.WriteAttributeString("timeoutMs", ClampInt(account.DefaultTimeoutMs, 250, 10000, DefaultTimeoutMs).ToString(CultureInfo.InvariantCulture));
                    writer.WriteAttributeString("dashboardDays", ClampInt(account.DashboardDays, 1, 30, DefaultDashboardDays).ToString(CultureInfo.InvariantCulture));
                    writer.WriteAttributeString("salt", account.PasswordSalt == null ? "" : account.PasswordSalt);
                    writer.WriteAttributeString("hash", account.PasswordHash == null ? "" : account.PasswordHash);
                    writer.WriteAttributeString("createdAt", account.CreatedAt.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
                    writer.WriteEndElement();
                }

                writer.WriteEndElement();
                writer.WriteEndDocument();
            }
        }

        private static string NormalizeUsername(string username)
        {
            return username == null ? "" : username.Trim();
        }

        public static string[] GetRoles()
        {
            string[] copy = new string[Roles.Length];
            Array.Copy(Roles, copy, Roles.Length);
            return copy;
        }

        public static string[] GetLanguages()
        {
            string[] copy = new string[Languages.Length];
            Array.Copy(Languages, copy, Languages.Length);
            return copy;
        }

        public static string NormalizeRole(string role)
        {
            string value = role == null ? "" : role.Trim();
            string normalized = value.ToLowerInvariant();
            if (normalized == "admin" || normalized == "administrador" || normalized == "administrator")
            {
                return RoleAdministrator;
            }

            if (normalized == "supervisor")
            {
                return RoleSupervisor;
            }

            if (normalized == "monitor")
            {
                return RoleMonitor;
            }

            return RoleAdministrator;
        }

        public static string NormalizeLanguage(string language)
        {
            string value = language == null ? "" : language.Trim();
            string normalized = value.ToLowerInvariant();
            if (normalized == "en" || normalized == "en-us" || normalized == "english" || normalized == "ingles" || normalized == "inglés")
            {
                return LanguageEnglish;
            }

            return LanguageSpanish;
        }

        public static bool IsAdministrator(string role)
        {
            return NormalizeRole(role) == RoleAdministrator;
        }

        public static bool IsSupervisor(string role)
        {
            return NormalizeRole(role) == RoleSupervisor;
        }

        public static bool IsMonitor(string role)
        {
            return NormalizeRole(role) == RoleMonitor;
        }

        private static string ReadAttribute(XmlNode node, string name)
        {
            XmlAttribute attribute = node.Attributes == null ? null : node.Attributes[name];
            return attribute == null ? "" : attribute.Value;
        }

        private static int ReadIntAttribute(XmlNode node, string name, int fallback)
        {
            int value;
            return Int32.TryParse(ReadAttribute(node, name), NumberStyles.Integer, CultureInfo.InvariantCulture, out value)
                ? value
                : fallback;
        }

        private static byte[] CreateSalt()
        {
            byte[] salt = new byte[PasswordSaltBytes];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }

            return salt;
        }

        private static byte[] HashPassword(string password, byte[] salt)
        {
            using (Rfc2898DeriveBytes pbkdf = new Rfc2898DeriveBytes(password, salt, PasswordHashIterations))
            {
                return pbkdf.GetBytes(PasswordHashBytes);
            }
        }

        private static bool ConstantTimeEquals(byte[] left, byte[] right)
        {
            if (left == null || right == null)
            {
                return false;
            }

            int diff = left.Length ^ right.Length;
            int length = Math.Min(left.Length, right.Length);
            for (int i = 0; i < length; i++)
            {
                diff |= left[i] ^ right[i];
            }

            return diff == 0;
        }

        public sealed class UserProfile
        {
            public string Username;
            public string Role;
            public string ProfileImagePath;
            public string Language;
            public int DefaultIntervalSeconds;
            public int DefaultTimeoutMs;
            public int DashboardDays;
            public DateTime CreatedAt;
        }

        private sealed class UserAccount
        {
            public string Username;
            public string PasswordSalt;
            public string PasswordHash;
            public string Role;
            public string ProfileImagePath;
            public string Language;
            public int DefaultIntervalSeconds;
            public int DefaultTimeoutMs;
            public int DashboardDays;
            public DateTime CreatedAt;
        }
    }

    internal static class UiText
    {
        private static readonly string[,] Pairs = new string[,]
        {
            { "Configuracion de cuenta", "Account settings" },
            { "Control de usuarios", "User management" },
            { "Crear, editar y eliminar accesos locales", "Create, edit and delete local access" },
            { "Nuevo usuario", "New user" },
            { "Editando usuario", "Editing user" },
            { "Usuario", "User" },
            { "Rol", "Role" },
            { "Creado", "Created" },
            { "Contrasena", "Password" },
            { "Confirmar contrasena", "Confirm password" },
            { "En usuarios existentes, deje la contrasena vacia para conservarla.", "For existing users, leave the password empty to keep it." },
            { "Nuevo", "New" },
            { "Eliminar", "Delete" },
            { "Cerrar", "Close" },
            { "Guardar", "Save" },
            { "Guardar cambios", "Save changes" },
            { "Cancelar", "Cancel" },
            { "Ruta de foto", "Photo path" },
            { "Idioma", "Language" },
            { "Intervalo default (seg)", "Default interval (sec)" },
            { "Timeout default (ms)", "Default timeout (ms)" },
            { "Ventana dashboard (dias)", "Dashboard window (days)" },
            { "Cambiar foto", "Change photo" },
            { "Quitar foto", "Remove photo" },
            { "Cambios registrados en account_audit.log", "Changes are logged in account_audit.log" },
            { "Parametros operativos restringidos por rol", "Operational parameters restricted by role" },
            { "Configurar cuenta", "Account settings" },
            { "Cerrar sesion", "Sign out" },
            { "Monitor de dispositivos", "Device monitor" },
            { "Disponibilidad de la red", "Network availability" },
            { "Intervalo (seg)", "Interval (sec)" },
            { "Timeout (ms)", "Timeout (ms)" },
            { "Buscar", "Search" },
            { "Tipo", "Type" },
            { "Ubicacion / sitio", "Location / site" },
            { "Estado", "Status" },
            { "Todos", "All" },
            { "Todas", "All" },
            { "Importar", "Import" },
            { "Agregar", "Add" },
            { "Quitar", "Remove" },
            { "Gestionar dispositivos", "Manage devices" },
            { "Revisar ahora", "Check now" },
            { "Iniciar", "Start" },
            { "Detener", "Stop" },
            { "Exportar CSV", "Export CSV" },
            { "Limpiar fallos", "Clear failures" },
            { "Eliminar todo", "Delete all" },
            { "Reset historial", "Reset history" },
            { "Actualizar", "Refresh" },
            { "Descargar reporte", "Download report" },
            { "Limpiar historial", "Clear history" },
            { "Agrupar", "Group by" },
            { "Tecnologia", "Technology" },
            { "Afiliacion", "Affiliation" },
            { "IP / Dispositivo", "IP / Device" },
            { "Disponibilidad", "Availability" },
            { "Muestras", "Samples" },
            { "En linea", "Online" },
            { "Sin respuesta", "No response" },
            { "Pendiente", "Pending" },
            { "Dispositivo", "Device" },
            { "Latencia", "Latency" },
            { "Ultima revision", "Last check" },
            { "Fallos", "Failures" },
            { "Listo", "Ready" },
            { "Sin revision", "No check yet" },
            { "Sin datos", "No data" },
            { "S/D", "N/A" },
            { "Dispositivo/IP", "Device/IP" },
            { "Ubicacion/Tecnologia", "Location/Technology" },
            { "Dispositivo", "Device" },
            { "Agregar dispositivo", "Add device" },
            { "Nuevo dispositivo", "New device" },
            { "Registro para sumar al monitoreo", "Record to add to monitoring" }
        };

        public static string Pick(bool english, string spanish, string englishText)
        {
            return english ? englishText : spanish;
        }

        public static string Role(string role, bool english)
        {
            string normalized = UserStore.NormalizeRole(role);
            if (!english)
            {
                return normalized;
            }

            if (normalized == UserStore.RoleAdministrator)
            {
                return "Administrator";
            }

            if (normalized == UserStore.RoleSupervisor)
            {
                return "Supervisor";
            }

            return "Monitor";
        }

        public static string Status(string status, bool english)
        {
            string normalized = CanonicalStatus(status);
            if (normalized == "En linea")
            {
                return Pick(english, "En linea", "Online");
            }

            if (normalized == "Sin respuesta")
            {
                return Pick(english, "Sin respuesta", "No response");
            }

            if (normalized == "Pendiente")
            {
                return Pick(english, "Pendiente", "Pending");
            }

            return normalized;
        }

        public static string CanonicalStatus(string status)
        {
            string value = status == null ? "" : status.Trim();
            if (String.Equals(value, "Online", StringComparison.OrdinalIgnoreCase))
            {
                return "En linea";
            }

            if (String.Equals(value, "No response", StringComparison.OrdinalIgnoreCase))
            {
                return "Sin respuesta";
            }

            if (String.Equals(value, "Pending", StringComparison.OrdinalIgnoreCase))
            {
                return "Pendiente";
            }

            return value;
        }

        public static bool IsAll(string value)
        {
            return String.Equals(value, "Todos", StringComparison.OrdinalIgnoreCase)
                || String.Equals(value, "Todas", StringComparison.OrdinalIgnoreCase)
                || String.Equals(value, "All", StringComparison.OrdinalIgnoreCase);
        }

        public static string TranslateKnown(string value, bool english)
        {
            if (String.IsNullOrWhiteSpace(value))
            {
                return value;
            }

            string trimmed = value.Trim();
            if (StartsWithAny(trimmed, "Hola, ", "Hi, "))
            {
                string name = trimmed.StartsWith("Hola, ", StringComparison.OrdinalIgnoreCase)
                    ? trimmed.Substring(6)
                    : trimmed.Substring(4);
                return Pick(english, "Hola, ", "Hi, ") + name;
            }

            for (int i = 0; i < Pairs.GetLength(0); i++)
            {
                if (String.Equals(trimmed, Pairs[i, 0], StringComparison.OrdinalIgnoreCase)
                    || String.Equals(trimmed, Pairs[i, 1], StringComparison.OrdinalIgnoreCase))
                {
                    return Pick(english, Pairs[i, 0], Pairs[i, 1]);
                }
            }

            return value;
        }

        public static void ApplyToTree(Control root, bool english)
        {
            if (root == null)
            {
                return;
            }

            if (root is Label || root is Button || root is CheckBox || root is RadioButton || root is GroupBox)
            {
                root.Text = TranslateKnown(root.Text, english);
            }

            foreach (Control child in root.Controls)
            {
                ApplyToTree(child, english);
            }
        }

        private static bool StartsWithAny(string value, string left, string right)
        {
            return value.StartsWith(left, StringComparison.OrdinalIgnoreCase)
                || value.StartsWith(right, StringComparison.OrdinalIgnoreCase);
        }
    }

    internal static class TechStyle
    {
        private sealed class SurfaceSpec
        {
            public Color Top;
            public Color Bottom;
            public Color Accent;
            public bool StrongAccent;
        }

        private static readonly Dictionary<Control, SurfaceSpec> SurfaceSpecs = new Dictionary<Control, SurfaceSpec>();

        public static void Configure(Graphics g)
        {
            if (g == null)
            {
                return;
            }

            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.CompositingQuality = CompositingQuality.HighQuality;
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
        }

        public static void EnableDoubleBuffer(Control control)
        {
            if (control == null)
            {
                return;
            }

            try
            {
                PropertyInfo property = typeof(Control).GetProperty("DoubleBuffered", BindingFlags.Instance | BindingFlags.NonPublic);
                if (property != null)
                {
                    property.SetValue(control, true, null);
                }
            }
            catch
            {
            }
        }

        public static RectangleF Align(Rectangle rect)
        {
            return new RectangleF(rect.Left + 0.5F, rect.Top + 0.5F, Math.Max(1, rect.Width - 1), Math.Max(1, rect.Height - 1));
        }

        public static GraphicsPath RoundRect(RectangleF rect, float radius)
        {
            GraphicsPath path = new GraphicsPath();
            if (rect.Width <= 1F || rect.Height <= 1F)
            {
                path.AddRectangle(rect);
                return path;
            }

            radius = Math.Max(1F, Math.Min(radius, Math.Min(rect.Width, rect.Height) / 2F));
            float diameter = radius * 2F;
            RectangleF arc = new RectangleF(rect.Left, rect.Top, diameter, diameter);
            path.AddArc(arc, 180, 90);
            arc.X = rect.Right - diameter;
            path.AddArc(arc, 270, 90);
            arc.Y = rect.Bottom - diameter;
            path.AddArc(arc, 0, 90);
            arc.X = rect.Left;
            path.AddArc(arc, 90, 90);
            path.CloseFigure();
            return path;
        }

        public static void DrawTechPanel(Graphics g, RectangleF rect, float radius, Color top, Color bottom, Color border, Color glow)
        {
            RectangleF shadow = new RectangleF(rect.Left + 4F, rect.Top + 7F, rect.Width, rect.Height);
            using (GraphicsPath shadowPath = RoundRect(shadow, radius))
            using (PathGradientBrush shadowBrush = new PathGradientBrush(shadowPath))
            {
                shadowBrush.CenterColor = Color.FromArgb(90, 0, 0, 0);
                shadowBrush.SurroundColors = new Color[] { Color.FromArgb(0, 0, 0, 0) };
                g.FillPath(shadowBrush, shadowPath);
            }

            using (GraphicsPath path = RoundRect(rect, radius))
            using (LinearGradientBrush brush = new LinearGradientBrush(rect, top, bottom, LinearGradientMode.ForwardDiagonal))
            {
                g.FillPath(brush, path);
            }

            RectangleF shine = new RectangleF(rect.Left + 1F, rect.Top + 1F, rect.Width - 2F, Math.Max(12F, rect.Height * 0.36F));
            using (GraphicsPath clip = RoundRect(rect, radius))
            using (LinearGradientBrush shineBrush = new LinearGradientBrush(shine, Color.FromArgb(45, 255, 255, 255), Color.FromArgb(0, 255, 255, 255), LinearGradientMode.Vertical))
            {
                GraphicsState state = g.Save();
                g.SetClip(clip);
                g.FillRectangle(shineBrush, shine);
                g.Restore(state);
            }

            using (GraphicsPath borderPath = RoundRect(rect, radius))
            using (Pen glowPen = new Pen(glow, 2.4F))
            {
                g.DrawPath(glowPen, borderPath);
            }

            RectangleF inner = new RectangleF(rect.Left + 1F, rect.Top + 1F, rect.Width - 2F, rect.Height - 2F);
            using (GraphicsPath borderPath = RoundRect(inner, Math.Max(1F, radius - 1F)))
            using (Pen borderPen = new Pen(border, 1F))
            {
                g.DrawPath(borderPen, borderPath);
            }
        }

        public static void DrawHairline(Graphics g, PointF left, PointF right, Color color)
        {
            using (Pen pen = new Pen(color, 1F))
            {
                pen.Alignment = PenAlignment.Center;
                g.DrawLine(pen, left, right);
            }
        }

        public static void AttachSurface(Panel panel, Color top, Color bottom, Color accent, bool strongAccent)
        {
            if (panel == null)
            {
                return;
            }

            panel.BackColor = bottom;
            panel.BackgroundImageLayout = ImageLayout.None;
            Image old = panel.BackgroundImage;
            panel.BackgroundImage = null;
            if (old != null)
            {
                old.Dispose();
            }

            EnableDoubleBuffer(panel);
            SurfaceSpecs[panel] = new SurfaceSpec
            {
                Top = top,
                Bottom = bottom,
                Accent = accent,
                StrongAccent = strongAccent
            };
            panel.Disposed += delegate { SurfaceSpecs.Remove(panel); };
            panel.Paint += delegate(object sender, PaintEventArgs e)
            {
                SurfaceSpec spec;
                if (SurfaceSpecs.TryGetValue(panel, out spec))
                {
                    PaintSurface(e.Graphics, panel.ClientRectangle, spec.Top, spec.Bottom, spec.Accent, spec.StrongAccent);
                }
            };
            panel.Resize += delegate
            {
                panel.Invalidate(true);
            };
        }

        private static void PaintSurface(Graphics g, Rectangle rect, Color top, Color bottom, Color accent, bool strongAccent)
        {
            Configure(g);
            if (rect.Width <= 0 || rect.Height <= 0)
            {
                return;
            }

            using (LinearGradientBrush brush = new LinearGradientBrush(rect, top, bottom, LinearGradientMode.ForwardDiagonal))
            {
                g.FillRectangle(brush, rect);
            }

            using (LinearGradientBrush glow = new LinearGradientBrush(
                rect,
                Color.FromArgb(strongAccent ? 26 : 14, accent),
                Color.FromArgb(0, accent),
                LinearGradientMode.Vertical))
            {
                g.FillRectangle(glow, rect);
            }

            using (Pen grid = new Pen(Color.FromArgb(strongAccent ? 10 : 6, accent), 1F))
            {
                for (int x = 0; x < rect.Width; x += 118)
                {
                    g.DrawLine(grid, x, rect.Top, x, rect.Bottom);
                }

                for (int y = rect.Top + 22; y < rect.Bottom; y += 72)
                {
                    g.DrawLine(grid, rect.Left, y, rect.Right, y);
                }
            }

            Color line = Color.FromArgb(strongAccent ? 198 : 100, accent);
            DrawHairline(g, new PointF(rect.Left, rect.Bottom - 1.5F), new PointF(rect.Right, rect.Bottom - 1.5F), line);
            if (strongAccent)
            {
                using (LinearGradientBrush bottomGlow = new LinearGradientBrush(
                    new Rectangle(rect.Left, Math.Max(rect.Top, rect.Bottom - 20), rect.Width, 20),
                    Color.FromArgb(0, accent),
                    Color.FromArgb(34, accent),
                    LinearGradientMode.Vertical))
                {
                    g.FillRectangle(bottomGlow, rect.Left, Math.Max(rect.Top, rect.Bottom - 20), rect.Width, 20);
                }
            }
        }

        public static void MakeChromeTransparent(Control root)
        {
            if (root == null)
            {
                return;
            }

            foreach (Control child in root.Controls)
            {
                if (child is Label || child is FlowLayoutPanel)
                {
                    child.BackColor = Color.Transparent;
                    EnableDoubleBuffer(child);
                }

                MakeChromeTransparent(child);
            }
        }

        public static Color HostBackColor(Control control, Color fallback)
        {
            Control current = control == null ? null : control.Parent;
            while (current != null)
            {
                if (current.BackColor.A == 255 && current.BackColor != Color.Transparent)
                {
                    return current.BackColor;
                }

                current = current.Parent;
            }

            return fallback;
        }

        public static void PaintInheritedBackground(Graphics g, Control control, Color fallback)
        {
            if (g == null || control == null)
            {
                return;
            }

            Control current = control.Parent;
            while (current != null)
            {
                SurfaceSpec spec;
                if (SurfaceSpecs.TryGetValue(current, out spec))
                {
                    Point origin = current.PointToClient(control.PointToScreen(Point.Empty));
                    GraphicsState state = g.Save();
                    g.TranslateTransform(-origin.X, -origin.Y);
                    PaintSurface(g, current.ClientRectangle, spec.Top, spec.Bottom, spec.Accent, spec.StrongAccent);
                    g.Restore(state);
                    return;
                }

                if (current.BackgroundImage != null)
                {
                    Point origin = current.PointToClient(control.PointToScreen(Point.Empty));
                    Rectangle dest = new Rectangle(0, 0, control.Width, control.Height);
                    Rectangle src = new Rectangle(origin.X, origin.Y, control.Width, control.Height);
                    g.DrawImage(current.BackgroundImage, dest, src, GraphicsUnit.Pixel);
                    return;
                }

                current = current.Parent;
            }

            g.Clear(HostBackColor(control, fallback));
        }
    }

    public sealed class SignInDialog : Form
    {
        private static readonly Color AppBackground = Color.FromArgb(5, 12, 28);
        private static readonly Color Surface = Color.FromArgb(10, 20, 42);
        private static readonly Color SurfaceSoft = Color.FromArgb(18, 42, 78);
        private static readonly Color TextMain = Color.FromArgb(232, 240, 255);
        private static readonly Color TextMuted = Color.FromArgb(145, 170, 205);
        private static readonly Color AccentSoft = Color.FromArgb(24, 194, 215);

        private readonly UserStore _userStore;
        private readonly bool _createFirstUser;
        private TextBox _userText;
        private TextBox _passwordText;
        private TextBox _confirmText;
        private Label _errorLabel;

        public string Username { get; private set; }
        public string Role { get; private set; }

        public SignInDialog(UserStore userStore)
        {
            _userStore = userStore;
            _createFirstUser = !_userStore.HasUsers();

            Text = _createFirstUser ? "Crear usuario" : "Iniciar sesion";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterScreen;
            ControlBox = false;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = true;
            BackColor = AppBackground;
            ForeColor = TextMain;
            Font = new Font("Segoe UI", 9F);
            ClientSize = new Size(460, _createFirstUser ? 370 : 312);

            BuildInterface();
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            if (_createFirstUser)
            {
                _userText.Text = "admin";
                _userText.SelectAll();
            }

            _userText.Focus();
        }

        private void BuildInterface()
        {
            Panel header = new Panel();
            header.BackColor = Surface;
            TechStyle.AttachSurface(header, Color.FromArgb(13, 31, 58), Color.FromArgb(8, 18, 38), AccentSoft, true);
            header.SetBounds(0, 0, ClientSize.Width, 88);
            header.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(header);

            Label title = new Label();
            title.Text = _createFirstUser ? "Crear primer usuario" : "Iniciar sesion";
            title.AutoSize = false;
            title.Font = new Font("Segoe UI Semibold", 16F, FontStyle.Bold);
            title.ForeColor = TextMain;
            title.SetBounds(30, 18, 380, 32);
            header.Controls.Add(title);

            Label subtitle = new Label();
            subtitle.Text = _createFirstUser ? "Configure el acceso inicial para ping_scan" : "Acceso al monitor de disponibilidad";
            subtitle.AutoSize = false;
            subtitle.ForeColor = TextMuted;
            subtitle.SetBounds(32, 52, 390, 22);
            header.Controls.Add(subtitle);
            TechStyle.MakeChromeTransparent(header);

            int y = 122;
            _userText = AddTextBox("Usuario", 32, y, 396, false);
            y += 64;
            _passwordText = AddTextBox("Contrasena", 32, y, 396, true);
            y += 64;

            if (_createFirstUser)
            {
                _confirmText = AddTextBox("Confirmar contrasena", 32, y, 396, true);
                y += 64;
            }

            _errorLabel = new Label();
            _errorLabel.AutoSize = false;
            _errorLabel.ForeColor = Color.FromArgb(248, 113, 113);
            _errorLabel.SetBounds(32, ClientSize.Height - 88, 396, 28);
            Controls.Add(_errorLabel);

            Button primaryButton = MakeButton(_createFirstUser ? "Crear usuario" : "Entrar");
            primaryButton.BackColor = AccentSoft;
            primaryButton.ForeColor = Color.FromArgb(2, 6, 23);
            primaryButton.SetBounds(ClientSize.Width - 258, ClientSize.Height - 48, 106, 32);
            primaryButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            primaryButton.Click += delegate { Submit(); };
            Controls.Add(primaryButton);

            Button cancelButton = MakeButton("Cancelar");
            cancelButton.BackColor = SurfaceSoft;
            cancelButton.ForeColor = TextMain;
            cancelButton.DialogResult = DialogResult.Cancel;
            cancelButton.SetBounds(ClientSize.Width - 144, ClientSize.Height - 48, 112, 32);
            cancelButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            Controls.Add(cancelButton);

            AcceptButton = primaryButton;
            CancelButton = cancelButton;
        }

        private TextBox AddTextBox(string labelText, int x, int y, int width, bool password)
        {
            Label label = new Label();
            label.Text = labelText;
            label.AutoSize = false;
            label.ForeColor = TextMuted;
            label.SetBounds(x, y - 22, width, 18);
            Controls.Add(label);

            TextBox textBox = new TextBox();
            textBox.BackColor = SurfaceSoft;
            textBox.ForeColor = TextMain;
            textBox.BorderStyle = BorderStyle.FixedSingle;
            textBox.SetBounds(x, y, width, 26);
            if (password)
            {
                textBox.PasswordChar = '*';
            }
            Controls.Add(textBox);
            return textBox;
        }

        private Button MakeButton(string text)
        {
            Button button = new Button();
            button.Text = text;
            button.FlatStyle = FlatStyle.Flat;
            button.FlatAppearance.BorderColor = Color.FromArgb(52, 99, 145);
            button.FlatAppearance.MouseOverBackColor = Color.FromArgb(33, 78, 118);
            button.FlatAppearance.MouseDownBackColor = Color.FromArgb(19, 47, 78);
            button.Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold);
            return button;
        }

        private void Submit()
        {
            string username = _userText.Text == null ? "" : _userText.Text.Trim();
            string password = _passwordText.Text == null ? "" : _passwordText.Text;
            string message;
            string role = UserStore.RoleAdministrator;

            try
            {
                if (_createFirstUser)
                {
                    string confirm = _confirmText.Text == null ? "" : _confirmText.Text;
                    if (password != confirm)
                    {
                        ShowError("Las contrasenas no coinciden.");
                        return;
                    }

                    if (!_userStore.CreateUser(username, password, UserStore.RoleAdministrator, out message))
                    {
                        ShowError(message);
                        return;
                    }
                }
                else if (!_userStore.ValidateUser(username, password, out role, out message))
                {
                    ShowError(message);
                    return;
                }
            }
            catch (Exception ex)
            {
                ShowError("No se pudo validar el acceso: " + ex.Message);
                return;
            }

            Username = username;
            Role = UserStore.NormalizeRole(role);
            DialogResult = DialogResult.OK;
            Close();
        }

        private void ShowError(string message)
        {
            _errorLabel.Text = message;
        }
    }

    public sealed class UserManagementDialog : Form
    {
        private static readonly Color AppBackground = Color.FromArgb(5, 12, 28);
        private static readonly Color Surface = Color.FromArgb(10, 20, 42);
        private static readonly Color SurfaceAlt = Color.FromArgb(13, 31, 58);
        private static readonly Color SurfaceSoft = Color.FromArgb(18, 42, 78);
        private static readonly Color Border = Color.FromArgb(52, 99, 145);
        private static readonly Color TextMain = Color.FromArgb(232, 240, 255);
        private static readonly Color TextMuted = Color.FromArgb(145, 170, 205);
        private static readonly Color AccentSoft = Color.FromArgb(24, 194, 215);
        private static readonly Color DangerBack = Color.FromArgb(114, 32, 60);

        private readonly UserStore _userStore;
        private DataGridView _usersGrid;
        private TextBox _userText;
        private ComboBox _roleCombo;
        private TextBox _passwordText;
        private TextBox _confirmText;
        private Label _modeLabel;
        private Label _statusLabel;
        private Button _deleteButton;
        private string _selectedUsername;
        private bool _loadingUsers;
        private readonly bool _englishUi;

        public string CurrentUsername { get; private set; }
        public string CurrentRole { get; private set; }

        public UserManagementDialog(UserStore userStore, string currentUsername, string currentRole)
            : this(userStore, currentUsername, currentRole, false)
        {
        }

        public UserManagementDialog(UserStore userStore, string currentUsername, string currentRole, bool englishUi)
        {
            _userStore = userStore;
            CurrentUsername = currentUsername == null ? "" : currentUsername.Trim();
            CurrentRole = UserStore.NormalizeRole(currentRole);
            _englishUi = englishUi;

            Text = UiText.Pick(_englishUi, "Control de usuarios", "User management");
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            ControlBox = false;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            BackColor = AppBackground;
            ForeColor = TextMain;
            Font = new Font("Segoe UI", 9F);
            ClientSize = new Size(800, 530);

            BuildInterface();
            UiText.ApplyToTree(this, _englishUi);
            RefreshUsers(CurrentUsername);
        }

        private void BuildInterface()
        {
            Panel header = new Panel();
            header.BackColor = Surface;
            TechStyle.AttachSurface(header, Color.FromArgb(13, 31, 58), Color.FromArgb(8, 18, 38), AccentSoft, true);
            header.SetBounds(0, 0, ClientSize.Width, 82);
            header.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(header);

            Label title = new Label();
            title.Text = "Control de usuarios";
            title.AutoSize = false;
            title.Font = new Font("Segoe UI Semibold", 16F, FontStyle.Bold);
            title.ForeColor = TextMain;
            title.SetBounds(28, 16, 360, 32);
            header.Controls.Add(title);

            Label subtitle = new Label();
            subtitle.Text = "Crear, editar y eliminar accesos locales";
            subtitle.AutoSize = false;
            subtitle.ForeColor = TextMuted;
            subtitle.SetBounds(30, 50, 420, 22);
            header.Controls.Add(subtitle);

            _usersGrid = new DataGridView();
            _usersGrid.SetBounds(28, 112, 340, 334);
            _usersGrid.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Bottom;
            _usersGrid.BackgroundColor = Surface;
            _usersGrid.BorderStyle = BorderStyle.None;
            _usersGrid.AllowUserToAddRows = false;
            _usersGrid.AllowUserToDeleteRows = false;
            _usersGrid.AllowUserToResizeRows = false;
            _usersGrid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            _usersGrid.ColumnHeadersHeight = 32;
            _usersGrid.EnableHeadersVisualStyles = false;
            _usersGrid.GridColor = Border;
            _usersGrid.MultiSelect = false;
            _usersGrid.ReadOnly = true;
            _usersGrid.RowHeadersVisible = false;
            _usersGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            _usersGrid.DefaultCellStyle.BackColor = Surface;
            _usersGrid.DefaultCellStyle.ForeColor = TextMain;
            _usersGrid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(14, 116, 144);
            _usersGrid.DefaultCellStyle.SelectionForeColor = Color.White;
            _usersGrid.AlternatingRowsDefaultCellStyle.BackColor = SurfaceAlt;
            _usersGrid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(2, 6, 23);
            _usersGrid.ColumnHeadersDefaultCellStyle.ForeColor = TextMain;
            _usersGrid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold);
            _usersGrid.Columns.Add("Username", UiText.Pick(_englishUi, "Usuario", "User"));
            _usersGrid.Columns.Add("Role", UiText.Pick(_englishUi, "Rol", "Role"));
            _usersGrid.Columns.Add("CreatedAt", UiText.Pick(_englishUi, "Creado", "Created"));
            _usersGrid.SelectionChanged += delegate { LoadSelectedUser(); };
            Controls.Add(_usersGrid);

            _modeLabel = new Label();
            _modeLabel.Text = "Nuevo usuario";
            _modeLabel.AutoSize = false;
            _modeLabel.Font = new Font("Segoe UI Semibold", 12F, FontStyle.Bold);
            _modeLabel.ForeColor = TextMain;
            _modeLabel.SetBounds(400, 112, 340, 28);
            Controls.Add(_modeLabel);

            _userText = AddTextBox("Usuario", 400, 158, 340, false);
            _roleCombo = AddCombo("Rol", 400, 222, 340);
            _passwordText = AddTextBox("Contrasena", 400, 286, 340, true);
            _confirmText = AddTextBox("Confirmar contrasena", 400, 350, 340, true);

            Label hint = new Label();
            hint.Text = "En usuarios existentes, deje la contrasena vacia para conservarla.";
            hint.AutoSize = false;
            hint.ForeColor = TextMuted;
            hint.SetBounds(400, 382, 340, 36);
            Controls.Add(hint);

            _statusLabel = new Label();
            _statusLabel.AutoSize = false;
            _statusLabel.ForeColor = TextMuted;
            _statusLabel.SetBounds(28, ClientSize.Height - 64, 420, 24);
            _statusLabel.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            Controls.Add(_statusLabel);

            Button newButton = MakeButton("Nuevo");
            newButton.BackColor = SurfaceSoft;
            newButton.ForeColor = TextMain;
            newButton.SetBounds(400, ClientSize.Height - 48, 88, 32);
            newButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            newButton.Click += delegate { NewUser(); };
            Controls.Add(newButton);

            Button saveButton = MakeButton("Guardar");
            saveButton.BackColor = AccentSoft;
            saveButton.ForeColor = Color.FromArgb(2, 6, 23);
            saveButton.SetBounds(496, ClientSize.Height - 48, 98, 32);
            saveButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            saveButton.Click += delegate { SaveUser(); };
            Controls.Add(saveButton);

            _deleteButton = MakeButton("Eliminar");
            _deleteButton.BackColor = DangerBack;
            _deleteButton.ForeColor = TextMain;
            _deleteButton.SetBounds(602, ClientSize.Height - 48, 96, 32);
            _deleteButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            _deleteButton.Click += delegate { DeleteSelectedUser(); };
            Controls.Add(_deleteButton);

            Button closeButton = MakeButton("Cerrar");
            closeButton.BackColor = SurfaceSoft;
            closeButton.ForeColor = TextMain;
            closeButton.SetBounds(706, ClientSize.Height - 48, 64, 32);
            closeButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            closeButton.DialogResult = DialogResult.OK;
            Controls.Add(closeButton);

            AcceptButton = saveButton;
        }

        private TextBox AddTextBox(string labelText, int x, int y, int width, bool password)
        {
            Label label = new Label();
            label.Text = labelText;
            label.AutoSize = false;
            label.ForeColor = TextMuted;
            label.SetBounds(x, y - 22, width, 18);
            Controls.Add(label);

            TextBox textBox = new TextBox();
            textBox.BackColor = SurfaceSoft;
            textBox.ForeColor = TextMain;
            textBox.BorderStyle = BorderStyle.FixedSingle;
            textBox.SetBounds(x, y, width, 26);
            if (password)
            {
                textBox.PasswordChar = '*';
            }
            Controls.Add(textBox);
            return textBox;
        }

        private ComboBox AddCombo(string labelText, int x, int y, int width)
        {
            Label label = new Label();
            label.Text = labelText;
            label.AutoSize = false;
            label.ForeColor = TextMuted;
            label.SetBounds(x, y - 22, width, 18);
            Controls.Add(label);

            ComboBox combo = new ComboBox();
            combo.DropDownStyle = ComboBoxStyle.DropDownList;
            combo.BackColor = SurfaceSoft;
            combo.ForeColor = TextMain;
            combo.FlatStyle = FlatStyle.Flat;
            combo.SetBounds(x, y, width, 26);
            string[] roles = UserStore.GetRoles();
            for (int i = 0; i < roles.Length; i++)
            {
                combo.Items.Add(UiText.Role(roles[i], _englishUi));
            }
            combo.SelectedItem = UiText.Role(UserStore.RoleMonitor, _englishUi);
            Controls.Add(combo);
            return combo;
        }

        private Button MakeButton(string text)
        {
            Button button = new Button();
            button.Text = text;
            button.FlatStyle = FlatStyle.Flat;
            button.FlatAppearance.BorderColor = Border;
            button.FlatAppearance.MouseOverBackColor = Color.FromArgb(33, 78, 118);
            button.FlatAppearance.MouseDownBackColor = Color.FromArgb(19, 47, 78);
            button.Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold);
            return button;
        }

        private void RefreshUsers(string preferredUsername)
        {
            _loadingUsers = true;
            try
            {
                _usersGrid.Rows.Clear();
                List<UserStore.UserProfile> users = _userStore.GetUsers();
                for (int i = 0; i < users.Count; i++)
                {
                    int index = _usersGrid.Rows.Add(
                        users[i].Username,
                        UiText.Role(users[i].Role, _englishUi),
                        users[i].CreatedAt == DateTime.MinValue ? "" : users[i].CreatedAt.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture));
                    _usersGrid.Rows[index].Tag = users[i];
                }
            }
            finally
            {
                _loadingUsers = false;
            }

            if (_usersGrid.Rows.Count == 0)
            {
                NewUser();
                return;
            }

            int selectedIndex = 0;
            if (!String.IsNullOrWhiteSpace(preferredUsername))
            {
                for (int i = 0; i < _usersGrid.Rows.Count; i++)
                {
                    UserStore.UserProfile profile = _usersGrid.Rows[i].Tag as UserStore.UserProfile;
                    if (profile != null && String.Equals(profile.Username, preferredUsername, StringComparison.OrdinalIgnoreCase))
                    {
                        selectedIndex = i;
                        break;
                    }
                }
            }

            _usersGrid.ClearSelection();
            _usersGrid.Rows[selectedIndex].Selected = true;
            _usersGrid.CurrentCell = _usersGrid.Rows[selectedIndex].Cells[0];
            LoadSelectedUser();
        }

        private void LoadSelectedUser()
        {
            if (_loadingUsers || _usersGrid.SelectedRows.Count == 0)
            {
                return;
            }

            UserStore.UserProfile profile = _usersGrid.SelectedRows[0].Tag as UserStore.UserProfile;
            if (profile == null)
            {
                return;
            }

            _selectedUsername = profile.Username;
            _modeLabel.Text = UiText.Pick(_englishUi, "Editando usuario", "Editing user");
            _userText.Text = profile.Username;
            _roleCombo.SelectedItem = UiText.Role(profile.Role, _englishUi);
            _passwordText.Text = "";
            _confirmText.Text = "";
            _deleteButton.Enabled = true;
            ShowStatus(UiText.Pick(_englishUi, "Usuario seleccionado: ", "Selected user: ") + profile.Username + " (" + UiText.Role(profile.Role, _englishUi) + ")", false);
        }

        private void NewUser()
        {
            _selectedUsername = "";
            _modeLabel.Text = UiText.Pick(_englishUi, "Nuevo usuario", "New user");
            _loadingUsers = true;
            try
            {
                _usersGrid.ClearSelection();
                _usersGrid.CurrentCell = null;
            }
            finally
            {
                _loadingUsers = false;
            }
            _userText.Text = "";
            _roleCombo.SelectedItem = UiText.Role(UserStore.RoleMonitor, _englishUi);
            _passwordText.Text = "";
            _confirmText.Text = "";
            _deleteButton.Enabled = false;
            ShowStatus(UiText.Pick(_englishUi, "Capture los datos del nuevo usuario.", "Enter the new user's information."), false);
            _userText.Focus();
        }

        private void SaveUser()
        {
            string username = _userText.Text == null ? "" : _userText.Text.Trim();
            string role = _roleCombo.SelectedItem == null ? UserStore.RoleMonitor : UserStore.NormalizeRole(_roleCombo.SelectedItem.ToString());
            string password = _passwordText.Text == null ? "" : _passwordText.Text;
            string confirm = _confirmText.Text == null ? "" : _confirmText.Text;
            bool editing = !String.IsNullOrWhiteSpace(_selectedUsername);
            bool changePassword = !String.IsNullOrEmpty(password) || !String.IsNullOrEmpty(confirm);

            if (!editing)
            {
                changePassword = true;
            }

            if (changePassword && password != confirm)
            {
                ShowStatus(UiText.Pick(_englishUi, "Las contrasenas no coinciden.", "Passwords do not match."), true);
                return;
            }

            string message;
            bool ok;
            if (editing)
            {
                ok = _userStore.UpdateUser(_selectedUsername, username, password, changePassword, role, out message);
            }
            else
            {
                ok = _userStore.CreateUser(username, password, role, out message);
            }

            if (!ok)
            {
                ShowStatus(message, true);
                return;
            }

            if (editing && String.Equals(_selectedUsername, CurrentUsername, StringComparison.OrdinalIgnoreCase))
            {
                CurrentUsername = username;
                CurrentRole = UserStore.NormalizeRole(role);
            }

            _userStore.AppendAudit(CurrentUsername, editing ? "user.update" : "user.create", "target=" + username + "; role=" + UserStore.NormalizeRole(role));
            _selectedUsername = username;
            RefreshUsers(username);
            ShowStatus(UiText.Pick(_englishUi, "Usuario guardado.", "User saved."), false);
        }

        private void DeleteSelectedUser()
        {
            if (String.IsNullOrWhiteSpace(_selectedUsername))
            {
                ShowStatus(UiText.Pick(_englishUi, "Seleccione un usuario.", "Select a user."), true);
                return;
            }

            if (String.Equals(_selectedUsername, CurrentUsername, StringComparison.OrdinalIgnoreCase))
            {
                ShowStatus(UiText.Pick(_englishUi, "No puede eliminar el usuario de la sesion actual.", "You cannot delete the current session user."), true);
                return;
            }

            DialogResult result = MessageBox.Show(
                UiText.Pick(_englishUi, "Desea eliminar el usuario '", "Do you want to delete user '") + _selectedUsername + "'?",
                UiText.Pick(_englishUi, "Eliminar usuario", "Delete user"),
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);
            if (result != DialogResult.Yes)
            {
                return;
            }

            string deletedUsername = _selectedUsername;
            string message;
            if (!_userStore.DeleteUser(deletedUsername, out message))
            {
                ShowStatus(message, true);
                return;
            }

            RefreshUsers(CurrentUsername);
            _userStore.AppendAudit(CurrentUsername, "user.delete", "target=" + deletedUsername);
            ShowStatus(UiText.Pick(_englishUi, "Usuario eliminado.", "User deleted."), false);
        }

        private void ShowStatus(string message, bool error)
        {
            _statusLabel.ForeColor = error ? Color.FromArgb(248, 113, 113) : TextMuted;
            _statusLabel.Text = UiText.TranslateKnown(message, _englishUi);
        }
    }

    public sealed class AccountSettingsDialog : Form
    {
        private static readonly Color AppBackground = Color.FromArgb(5, 12, 28);
        private static readonly Color Surface = Color.FromArgb(10, 20, 42);
        private static readonly Color SurfaceSoft = Color.FromArgb(18, 42, 78);
        private static readonly Color Border = Color.FromArgb(52, 99, 145);
        private static readonly Color TextMain = Color.FromArgb(232, 240, 255);
        private static readonly Color TextMuted = Color.FromArgb(145, 170, 205);
        private static readonly Color Accent = Color.FromArgb(0, 229, 255);
        private static readonly Color AccentSoft = Color.FromArgb(24, 194, 215);

        private readonly UserStore _userStore;
        private readonly string _actor;
        private readonly string _role;
        private UserStore.UserProfile _profile;
        private AvatarPreview _avatarPreview;
        private TextBox _photoText;
        private ComboBox _languageCombo;
        private NumericUpDown _intervalInput;
        private NumericUpDown _timeoutInput;
        private NumericUpDown _dashboardDaysInput;
        private Label _subtitleLabel;
        private Label _statusLabel;

        public event EventHandler SettingsSaved;
        public UserStore.UserProfile Profile { get; private set; }

        public AccountSettingsDialog(UserStore userStore, string username, string role)
        {
            _userStore = userStore;
            _actor = username == null ? "" : username.Trim();
            _role = UserStore.NormalizeRole(role);
            _profile = _userStore.GetUserProfile(_actor);
            Profile = _profile;

            Text = "Configuracion de cuenta";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            ControlBox = false;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            BackColor = AppBackground;
            ForeColor = TextMain;
            Font = new Font("Segoe UI", 9F);
            ClientSize = new Size(720, 500);

            BuildInterface();
            LoadProfile();
            ApplyLocalization();
        }

        private void BuildInterface()
        {
            Panel header = new Panel();
            header.BackColor = Surface;
            TechStyle.AttachSurface(header, Color.FromArgb(13, 31, 58), Color.FromArgb(8, 18, 38), AccentSoft, true);
            header.SetBounds(0, 0, ClientSize.Width, 88);
            header.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(header);

            Label title = new Label();
            title.Text = "Configuracion de cuenta";
            title.AutoSize = false;
            title.Font = new Font("Segoe UI Semibold", 16F, FontStyle.Bold);
            title.ForeColor = TextMain;
            title.BackColor = Color.Transparent;
            title.SetBounds(28, 16, 360, 32);
            header.Controls.Add(title);

            _subtitleLabel = new Label();
            _subtitleLabel.Text = _profile.Username + "  |  " + UserStore.NormalizeRole(_profile.Role);
            _subtitleLabel.AutoSize = false;
            _subtitleLabel.ForeColor = TextMuted;
            _subtitleLabel.BackColor = Color.Transparent;
            _subtitleLabel.SetBounds(30, 50, 430, 22);
            header.Controls.Add(_subtitleLabel);

            _avatarPreview = new AvatarPreview();
            _avatarPreview.SetBounds(42, 128, 112, 112);
            Controls.Add(_avatarPreview);

            Button photoButton = MakeButton("Cambiar foto");
            photoButton.BackColor = AccentSoft;
            photoButton.ForeColor = Color.FromArgb(2, 6, 23);
            photoButton.SetBounds(32, 260, 132, 32);
            photoButton.Click += delegate { ChoosePhoto(); };
            Controls.Add(photoButton);

            Button clearPhotoButton = MakeButton("Quitar foto");
            clearPhotoButton.BackColor = SurfaceSoft;
            clearPhotoButton.ForeColor = TextMain;
            clearPhotoButton.SetBounds(32, 302, 132, 32);
            clearPhotoButton.Click += delegate
            {
                _photoText.Text = "";
                _avatarPreview.ImagePath = "";
                _avatarPreview.Invalidate();
            };
            Controls.Add(clearPhotoButton);

            _photoText = AddTextBox("Ruta de foto", 210, 142, 430, false);
            _photoText.ReadOnly = true;
            _languageCombo = AddCombo("Idioma", 210, 206, 210, UserStore.GetLanguages());
            _languageCombo.SelectedIndexChanged += delegate { ApplyLocalization(); };

            bool canChangeOperational = UserStore.IsAdministrator(_role) || UserStore.IsSupervisor(_role);
            _intervalInput = AddNumber("Intervalo default (seg)", 210, 280, 130, 5, 86400, UserStore.DefaultIntervalSeconds);
            _timeoutInput = AddNumber("Timeout default (ms)", 366, 280, 130, 250, 10000, UserStore.DefaultTimeoutMs);
            _dashboardDaysInput = AddNumber("Ventana dashboard (dias)", 522, 280, 118, 1, 30, UserStore.DefaultDashboardDays);
            _intervalInput.Enabled = canChangeOperational;
            _timeoutInput.Enabled = canChangeOperational;
            _dashboardDaysInput.Enabled = canChangeOperational;

            Label governance = new Label();
            governance.Text = canChangeOperational ? "Cambios registrados en account_audit.log" : "Parametros operativos restringidos por rol";
            governance.AutoSize = false;
            governance.ForeColor = TextMuted;
            governance.BackColor = Color.Transparent;
            governance.SetBounds(210, 328, 430, 24);
            Controls.Add(governance);

            _statusLabel = new Label();
            _statusLabel.AutoSize = false;
            _statusLabel.ForeColor = TextMuted;
            _statusLabel.BackColor = Color.Transparent;
            _statusLabel.SetBounds(32, ClientSize.Height - 64, 390, 24);
            _statusLabel.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            Controls.Add(_statusLabel);

            Button saveButton = MakeButton("Guardar");
            saveButton.BackColor = AccentSoft;
            saveButton.ForeColor = Color.FromArgb(2, 6, 23);
            saveButton.SetBounds(ClientSize.Width - 240, ClientSize.Height - 48, 104, 32);
            saveButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            saveButton.Click += delegate { SaveSettings(); };
            Controls.Add(saveButton);

            Button closeButton = MakeButton("Cerrar");
            closeButton.BackColor = SurfaceSoft;
            closeButton.ForeColor = TextMain;
            closeButton.SetBounds(ClientSize.Width - 124, ClientSize.Height - 48, 92, 32);
            closeButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            closeButton.DialogResult = DialogResult.OK;
            Controls.Add(closeButton);

            AcceptButton = saveButton;
        }

        private bool IsEnglishDialog()
        {
            string language = _languageCombo == null || _languageCombo.SelectedItem == null
                ? (_profile == null ? "" : _profile.Language)
                : _languageCombo.SelectedItem.ToString();
            return UserStore.NormalizeLanguage(language) == UserStore.LanguageEnglish;
        }

        private void ApplyLocalization()
        {
            bool english = IsEnglishDialog();
            Text = UiText.Pick(english, "Configuracion de cuenta", "Account settings");
            if (_subtitleLabel != null && _profile != null)
            {
                _subtitleLabel.Text = _profile.Username + "  |  " + UiText.Role(_profile.Role, english);
            }

            UiText.ApplyToTree(this, english);
        }

        private void LoadProfile()
        {
            _photoText.Text = _profile.ProfileImagePath == null ? "" : _profile.ProfileImagePath;
            _avatarPreview.Username = _profile.Username;
            _avatarPreview.ImagePath = _photoText.Text;
            _languageCombo.SelectedItem = UserStore.NormalizeLanguage(_profile.Language);
            _intervalInput.Value = ClampDecimal(_profile.DefaultIntervalSeconds, _intervalInput.Minimum, _intervalInput.Maximum);
            _timeoutInput.Value = ClampDecimal(_profile.DefaultTimeoutMs, _timeoutInput.Minimum, _timeoutInput.Maximum);
            _dashboardDaysInput.Value = ClampDecimal(_profile.DashboardDays, _dashboardDaysInput.Minimum, _dashboardDaysInput.Maximum);
        }

        private TextBox AddTextBox(string labelText, int x, int y, int width, bool password)
        {
            Label label = new Label();
            label.Text = labelText;
            label.AutoSize = false;
            label.ForeColor = TextMuted;
            label.BackColor = Color.Transparent;
            label.SetBounds(x, y - 22, width, 18);
            Controls.Add(label);

            TextBox textBox = new TextBox();
            textBox.BackColor = SurfaceSoft;
            textBox.ForeColor = TextMain;
            textBox.BorderStyle = BorderStyle.FixedSingle;
            textBox.SetBounds(x, y, width, 26);
            if (password)
            {
                textBox.PasswordChar = '*';
            }
            Controls.Add(textBox);
            return textBox;
        }

        private ComboBox AddCombo(string labelText, int x, int y, int width, string[] values)
        {
            Label label = new Label();
            label.Text = labelText;
            label.AutoSize = false;
            label.ForeColor = TextMuted;
            label.BackColor = Color.Transparent;
            label.SetBounds(x, y - 22, width, 18);
            Controls.Add(label);

            ComboBox combo = new ComboBox();
            combo.DropDownStyle = ComboBoxStyle.DropDownList;
            combo.BackColor = SurfaceSoft;
            combo.ForeColor = TextMain;
            combo.FlatStyle = FlatStyle.Flat;
            combo.SetBounds(x, y, width, 26);
            if (values != null)
            {
                for (int i = 0; i < values.Length; i++)
                {
                    combo.Items.Add(values[i]);
                }
            }
            if (combo.Items.Count > 0)
            {
                combo.SelectedIndex = 0;
            }
            Controls.Add(combo);
            return combo;
        }

        private NumericUpDown AddNumber(string labelText, int x, int y, int width, int min, int max, int value)
        {
            Label label = new Label();
            label.Text = labelText;
            label.AutoSize = false;
            label.ForeColor = TextMuted;
            label.BackColor = Color.Transparent;
            label.SetBounds(x, y - 22, width + 24, 18);
            Controls.Add(label);

            NumericUpDown input = new NumericUpDown();
            input.Minimum = min;
            input.Maximum = max;
            input.Value = Math.Max(min, Math.Min(max, value));
            input.BackColor = SurfaceSoft;
            input.ForeColor = TextMain;
            input.SetBounds(x, y, width, 26);
            Controls.Add(input);
            return input;
        }

        private Button MakeButton(string text)
        {
            Button button = new Button();
            button.Text = text;
            button.FlatStyle = FlatStyle.Flat;
            button.FlatAppearance.BorderColor = Border;
            button.FlatAppearance.MouseOverBackColor = Color.FromArgb(33, 78, 118);
            button.FlatAppearance.MouseDownBackColor = Color.FromArgb(19, 47, 78);
            button.Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold);
            return button;
        }

        private void ChoosePhoto()
        {
            using (OpenFileDialog dialog = new OpenFileDialog())
            {
                bool english = IsEnglishDialog();
                dialog.Title = UiText.Pick(english, "Seleccionar foto de perfil", "Select profile photo");
                dialog.Filter = UiText.Pick(english, "Imagenes (*.png;*.jpg;*.jpeg;*.bmp)|*.png;*.jpg;*.jpeg;*.bmp|Todos los archivos (*.*)|*.*", "Images (*.png;*.jpg;*.jpeg;*.bmp)|*.png;*.jpg;*.jpeg;*.bmp|All files (*.*)|*.*");
                dialog.RestoreDirectory = true;
                if (dialog.ShowDialog(this) != DialogResult.OK)
                {
                    return;
                }

                try
                {
                    using (Image image = Image.FromFile(dialog.FileName))
                    {
                        if (image.Width <= 0 || image.Height <= 0)
                        {
                            ShowStatus(UiText.Pick(english, "La imagen seleccionada no es valida.", "The selected image is not valid."), true);
                            return;
                        }
                    }
                }
                catch
                {
                    ShowStatus(UiText.Pick(english, "No se pudo cargar la imagen seleccionada.", "The selected image could not be loaded."), true);
                    return;
                }

                _photoText.Text = dialog.FileName;
                _avatarPreview.ImagePath = dialog.FileName;
                _avatarPreview.Invalidate();
                ShowStatus(UiText.Pick(english, "Foto seleccionada. Presione Guardar para aplicarla.", "Photo selected. Press Save to apply it."), false);
            }
        }

        private void SaveSettings()
        {
            string message;
            string language = _languageCombo.SelectedItem == null ? UserStore.LanguageSpanish : _languageCombo.SelectedItem.ToString();
            if (!_userStore.UpdateAccountSettings(
                _actor,
                _photoText.Text,
                language,
                Decimal.ToInt32(_intervalInput.Value),
                Decimal.ToInt32(_timeoutInput.Value),
                Decimal.ToInt32(_dashboardDaysInput.Value),
                out message))
            {
                ShowStatus(message, true);
                return;
            }

            _profile = _userStore.GetUserProfile(_actor);
            Profile = _profile;
            _userStore.AppendAudit(_actor, "account.settings.update", "language=" + _profile.Language + "; interval=" + _profile.DefaultIntervalSeconds.ToString(CultureInfo.InvariantCulture) + "; timeout=" + _profile.DefaultTimeoutMs.ToString(CultureInfo.InvariantCulture) + "; dashboardDays=" + _profile.DashboardDays.ToString(CultureInfo.InvariantCulture));
            ApplyLocalization();
            EventHandler handler = SettingsSaved;
            if (handler != null)
            {
                handler(this, EventArgs.Empty);
            }
            ShowStatus(UiText.Pick(IsEnglishDialog(), "Configuracion guardada.", "Settings saved."), false);
        }

        private void ShowStatus(string message, bool error)
        {
            _statusLabel.ForeColor = error ? Color.FromArgb(248, 113, 113) : TextMuted;
            _statusLabel.Text = UiText.TranslateKnown(message, IsEnglishDialog());
        }

        private static decimal ClampDecimal(int value, decimal min, decimal max)
        {
            if (value < min)
            {
                return min;
            }

            if (value > max)
            {
                return max;
            }

            return value;
        }

        private sealed class AvatarPreview : Control
        {
            public string Username { get; set; }
            public string ImagePath { get; set; }

            public AvatarPreview()
            {
                SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.UserPaint, true);
            }

            protected override void OnPaint(PaintEventArgs e)
            {
                TechStyle.Configure(e.Graphics);
                Rectangle rect = ClientRectangle;
                rect.Inflate(-3, -3);
                AccountVisuals.DrawAvatar(e.Graphics, rect, Username, ImagePath, true);
            }
        }
    }

    internal static class AccountVisuals
    {
        private static Image _defaultAvatarImage;

        public static void DrawAvatar(Graphics g, Rectangle rect, string username, string imagePath, bool large)
        {
            TechStyle.Configure(g);
            using (LinearGradientBrush ringBrush = new LinearGradientBrush(rect, Color.FromArgb(0, 229, 255), Color.FromArgb(245, 158, 11), LinearGradientMode.ForwardDiagonal))
            {
                g.FillEllipse(ringBrush, rect);
            }

            Rectangle inner = rect;
            inner.Inflate(large ? -5 : -3, large ? -5 : -3);
            using (Brush back = new SolidBrush(Color.FromArgb(8, 20, 43)))
            {
                g.FillEllipse(back, inner);
            }

            bool useDefaultAvatar = ShouldUseDefaultAvatar(imagePath);
            if (!useDefaultAvatar && !String.IsNullOrWhiteSpace(imagePath) && File.Exists(imagePath))
            {
                try
                {
                    using (Image image = Image.FromFile(imagePath))
                    using (GraphicsPath clip = new GraphicsPath())
                    {
                        clip.AddEllipse(inner);
                        GraphicsState state = g.Save();
                        g.SetClip(clip);
                        g.DrawImage(image, FitImageRect(image.Size, inner));
                        g.Restore(state);
                    }
                    return;
                }
                catch
                {
                }
            }

            Image defaultAvatar = LoadDefaultAvatarImage();
            if (defaultAvatar != null)
            {
                Rectangle iconBounds = inner;
                int inset = Math.Max(2, inner.Width / 9);
                iconBounds.Inflate(-inset, -inset);
                g.DrawImage(defaultAvatar, FitImageRect(defaultAvatar.Size, iconBounds));
                return;
            }

            if (large)
            {
                using (Font font = new Font("Segoe UI Semibold", 28F, FontStyle.Bold))
                using (StringFormat format = new StringFormat())
                using (Brush brush = new SolidBrush(Color.FromArgb(232, 240, 255)))
                {
                    format.Alignment = StringAlignment.Center;
                    format.LineAlignment = StringAlignment.Center;
                    g.DrawString(GetInitial(username), font, brush, inner, format);
                }
            }
            else
            {
                int iconCenterX = inner.Left + (inner.Width / 2);
                int iconTop = inner.Top + Math.Max(4, inner.Height / 5);
                using (Brush iconBrush = new SolidBrush(Color.FromArgb(232, 240, 255)))
                {
                    int head = Math.Max(7, inner.Width / 4);
                    g.FillEllipse(iconBrush, iconCenterX - (head / 2), iconTop, head, head);
                    using (GraphicsPath body = RoundRect(new Rectangle(iconCenterX - (inner.Width / 4), iconTop + head + 4, inner.Width / 2, Math.Max(8, inner.Height / 4)), 7))
                    {
                        g.FillPath(iconBrush, body);
                    }
                }
            }
        }

        private static bool ShouldUseDefaultAvatar(string imagePath)
        {
            if (String.IsNullOrWhiteSpace(imagePath))
            {
                return true;
            }

            try
            {
                string fileName = Path.GetFileName(imagePath);
                return String.Equals(fileName, "account_avatar_default.png", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return true;
            }
        }

        private static Image LoadDefaultAvatarImage()
        {
            if (_defaultAvatarImage != null)
            {
                return _defaultAvatarImage;
            }

            try
            {
                string path = Path.Combine(Application.StartupPath, "account_avatar_default.png");
                if (File.Exists(path))
                {
                    using (Image image = Image.FromFile(path))
                    {
                        _defaultAvatarImage = new Bitmap(image);
                    }
                    return _defaultAvatarImage;
                }

                Assembly assembly = Assembly.GetExecutingAssembly();
                using (Stream stream = assembly.GetManifestResourceStream("AccountAvatarDefault"))
                {
                    if (stream != null)
                    {
                        using (Image image = Image.FromStream(stream))
                        {
                            _defaultAvatarImage = new Bitmap(image);
                        }
                    }
                }
            }
            catch
            {
                _defaultAvatarImage = null;
            }

            return _defaultAvatarImage;
        }

        private static string GetInitial(string username)
        {
            if (String.IsNullOrWhiteSpace(username))
            {
                return "U";
            }

            return username.Trim().Substring(0, 1).ToUpperInvariant();
        }

        private static Rectangle FitImageRect(Size imageSize, Rectangle bounds)
        {
            if (imageSize.Width <= 0 || imageSize.Height <= 0)
            {
                return bounds;
            }

            float scale = Math.Max(bounds.Width / (float)imageSize.Width, bounds.Height / (float)imageSize.Height);
            int width = (int)Math.Round(imageSize.Width * scale);
            int height = (int)Math.Round(imageSize.Height * scale);
            return new Rectangle(
                bounds.Left + ((bounds.Width - width) / 2),
                bounds.Top + ((bounds.Height - height) / 2),
                width,
                height);
        }

        private static GraphicsPath RoundRect(Rectangle rect, int radius)
        {
            GraphicsPath path = new GraphicsPath();
            int diameter = radius * 2;
            Rectangle arc = new Rectangle(rect.Left, rect.Top, diameter, diameter);
            path.AddArc(arc, 180, 90);
            arc.X = rect.Right - diameter;
            path.AddArc(arc, 270, 90);
            arc.Y = rect.Bottom - diameter;
            path.AddArc(arc, 0, 90);
            arc.X = rect.Left;
            path.AddArc(arc, 90, 90);
            path.CloseFigure();
            return path;
        }
    }

    public sealed class AccountMenuPopup : Form
    {
        private static readonly Color Surface = Color.FromArgb(28, 32, 36);
        private static readonly Color SurfaceAlt = Color.FromArgb(22, 26, 31);
        private static readonly Color TextMain = Color.FromArgb(235, 240, 248);
        private static readonly Color TextMuted = Color.FromArgb(164, 176, 195);
        private static readonly Color Accent = Color.FromArgb(0, 229, 255);

        private readonly string _username;
        private readonly string _role;
        private readonly string _profileImagePath;
        private readonly bool _canManageUsers;
        private readonly bool _englishUi;
        private Rectangle _closeRect;
        private Rectangle _settingsRect;
        private Rectangle _usersRect;
        private Rectangle _signOutRect;
        private string _hoverHit;

        public event EventHandler AccountSettingsClicked;
        public event EventHandler ManageUsersClicked;
        public event EventHandler SignOutClicked;

        public AccountMenuPopup(string username, string role, string profileImagePath, bool canManageUsers)
            : this(username, role, profileImagePath, canManageUsers, false)
        {
        }

        public AccountMenuPopup(string username, string role, string profileImagePath, bool canManageUsers, bool englishUi)
        {
            _username = String.IsNullOrWhiteSpace(username) ? UiText.Pick(englishUi, "Usuario", "User") : username;
            _role = UserStore.NormalizeRole(role);
            _profileImagePath = profileImagePath == null ? "" : profileImagePath;
            _canManageUsers = canManageUsers;
            _englishUi = englishUi;

            FormBorderStyle = FormBorderStyle.None;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.Manual;
            BackColor = Color.Black;
            Font = new Font("Segoe UI", 9F);
            ClientSize = new Size(388, _canManageUsers ? 364 : 314);
            Padding = new Padding(0);

            BuildInterface();
        }

        protected override CreateParams CreateParams
        {
            get
            {
                CreateParams cp = base.CreateParams;
                cp.ExStyle |= 0x00080000; // WS_EX_LAYERED
                cp.ExStyle |= 0x00000080; // WS_EX_TOOLWINDOW
                return cp;
            }
        }

        protected override bool ShowWithoutActivation
        {
            get { return true; }
        }

        protected override void OnDeactivate(EventArgs e)
        {
            base.OnDeactivate(e);
            Close();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            RenderPopup(e.Graphics);
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            BuildLayout();
            if (IsHandleCreated && Visible)
            {
                RenderLayeredWindow();
            }
        }

        private void BuildInterface()
        {
            BuildLayout();
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            RenderLayeredWindow();
        }

        protected override void OnLocationChanged(EventArgs e)
        {
            base.OnLocationChanged(e);
            if (IsHandleCreated && Visible)
            {
                RenderLayeredWindow();
            }
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            string hit = HitTest(e.Location);
            if (!String.Equals(hit, _hoverHit, StringComparison.Ordinal))
            {
                _hoverHit = hit;
                Cursor = String.IsNullOrEmpty(hit) ? Cursors.Default : Cursors.Hand;
                RenderLayeredWindow();
            }

            base.OnMouseMove(e);
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            _hoverHit = "";
            Cursor = Cursors.Default;
            RenderLayeredWindow();
            base.OnMouseLeave(e);
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            string hit = HitTest(e.Location);
            if (hit == "close")
            {
                Close();
            }
            else if (hit == "settings")
            {
                RaiseAndClose(AccountSettingsClicked);
            }
            else if (hit == "users")
            {
                RaiseAndClose(ManageUsersClicked);
            }
            else if (hit == "signout")
            {
                RaiseAndClose(SignOutClicked);
            }

            base.OnMouseDown(e);
        }

        private void BuildLayout()
        {
            int bottomY = _canManageUsers ? ClientSize.Height - 64 : ClientSize.Height - 66;
            _closeRect = new Rectangle(ClientSize.Width - 56, 24, 34, 34);
            _settingsRect = new Rectangle(70, 244, ClientSize.Width - 140, 42);
            _usersRect = _canManageUsers ? new Rectangle(26, bottomY, (ClientSize.Width - 58) / 2, 48) : Rectangle.Empty;
            _signOutRect = _canManageUsers
                ? new Rectangle(_usersRect.Right + 6, bottomY, ClientSize.Width - _usersRect.Right - 32, 48)
                : new Rectangle(38, bottomY, ClientSize.Width - 76, 48);
        }

        private string HitTest(Point point)
        {
            if (_closeRect.Contains(point))
            {
                return "close";
            }

            if (_settingsRect.Contains(point))
            {
                return "settings";
            }

            if (!_usersRect.IsEmpty && _usersRect.Contains(point))
            {
                return "users";
            }

            if (_signOutRect.Contains(point))
            {
                return "signout";
            }

            return "";
        }

        private void RenderPopup(Graphics g)
        {
            TechStyle.Configure(g);
            g.Clear(Color.Transparent);

            RectangleF shell = new RectangleF(6F, 6F, ClientSize.Width - 12F, ClientSize.Height - 12F);
            TechStyle.DrawTechPanel(
                g,
                shell,
                30F,
                Color.FromArgb(250, 36, 42, 48),
                Color.FromArgb(250, 22, 27, 34),
                Color.FromArgb(115, 116, 136, 160),
                Color.FromArgb(62, 0, 229, 255));

            using (GraphicsPath clip = TechStyle.RoundRect(shell, 30F))
            {
                GraphicsState state = g.Save();
                g.SetClip(clip);
                DrawPopupCircuitTexture(g, shell);
                g.Restore(state);
            }

            using (Font accountFont = new Font("Segoe UI Semibold", 11F, FontStyle.Bold))
            using (Font greetingFont = new Font("Segoe UI Semibold", 18F, FontStyle.Bold))
            using (Font roleFont = new Font("Segoe UI", 9F, FontStyle.Regular))
            using (StringFormat center = CenterFormat())
            using (Brush textBrush = new SolidBrush(TextMain))
            using (Brush mutedBrush = new SolidBrush(TextMuted))
            {
                g.DrawString(_username, accountFont, textBrush, new RectangleF(62, 26, ClientSize.Width - 124, 28), center);
                Rectangle avatar = new Rectangle((ClientSize.Width - 96) / 2, 70, 96, 96);
                AccountVisuals.DrawAvatar(g, avatar, _username, _profileImagePath, true);
                g.DrawString(UiText.Pick(_englishUi, "Hola, ", "Hi, ") + _username, greetingFont, textBrush, new RectangleF(28, 174, ClientSize.Width - 56, 38), center);
                g.DrawString(UiText.Role(_role, _englishUi), roleFont, mutedBrush, new RectangleF(42, 212, ClientSize.Width - 84, 22), center);
            }

            DrawPopupButton(g, _settingsRect, UiText.Pick(_englishUi, "Configurar cuenta", "Account settings"), "settings", true);
            if (!_usersRect.IsEmpty)
            {
                DrawPopupButton(g, _usersRect, UiText.Pick(_englishUi, "Control de usuarios", "User management"), "users", false);
            }
            DrawPopupButton(g, _signOutRect, UiText.Pick(_englishUi, "Cerrar sesion", "Sign out"), "signout", false);
            DrawCloseGlyph(g);
        }

        private void DrawPopupCircuitTexture(Graphics g, RectangleF shell)
        {
            using (Pen cyan = new Pen(Color.FromArgb(34, Accent), 1F))
            using (Pen violet = new Pen(Color.FromArgb(28, 130, 90, 255), 1F))
            {
                g.DrawLine(cyan, shell.Left + 26, shell.Top + 54, shell.Right - 26, shell.Top + 54);
                g.DrawLine(violet, shell.Left + 34, shell.Bottom - 82, shell.Right - 34, shell.Bottom - 82);
                for (int x = (int)shell.Left + 42; x < shell.Right - 42; x += 54)
                {
                    g.DrawLine(cyan, x, shell.Top + 54, x + 16, shell.Top + 76);
                    g.DrawEllipse(violet, x + 14, shell.Top + 73, 4, 4);
                }
            }
        }

        private void DrawPopupButton(Graphics g, Rectangle rect, string text, string hit, bool outline)
        {
            bool hover = String.Equals(_hoverHit, hit, StringComparison.Ordinal);
            RectangleF bounds = TechStyle.Align(rect);
            Color top = hover ? Color.FromArgb(66, 82, 98) : (outline ? Surface : SurfaceAlt);
            Color bottom = hover ? Color.FromArgb(35, 47, 61) : Color.FromArgb(20, 25, 32);
            Color border = outline ? Color.FromArgb(150, 148, 170, 198) : Color.FromArgb(65, 92, 112, 136);
            using (GraphicsPath path = TechStyle.RoundRect(bounds, 22F))
            using (LinearGradientBrush brush = new LinearGradientBrush(bounds, top, bottom, LinearGradientMode.Vertical))
            {
                g.FillPath(brush, path);
            }

            using (GraphicsPath path = TechStyle.RoundRect(bounds, 22F))
            using (Pen pen = new Pen(hover ? Accent : border, hover ? 1.7F : 1F))
            {
                g.DrawPath(pen, path);
            }

            using (Font font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold))
            using (Brush brush = new SolidBrush(outline ? Color.FromArgb(196, 216, 255) : TextMain))
            using (StringFormat center = CenterFormat())
            {
                g.DrawString(text, font, brush, bounds, center);
            }
        }

        private void DrawCloseGlyph(Graphics g)
        {
            bool hover = String.Equals(_hoverHit, "close", StringComparison.Ordinal);
            RectangleF rect = TechStyle.Align(_closeRect);
            if (hover)
            {
                using (GraphicsPath path = TechStyle.RoundRect(rect, 17F))
                using (Brush brush = new SolidBrush(Color.FromArgb(58, 76, 88)))
                {
                    g.FillPath(brush, path);
                }
            }

            using (Pen pen = new Pen(hover ? Color.White : TextMuted, 2F))
            {
                pen.StartCap = LineCap.Round;
                pen.EndCap = LineCap.Round;
                g.DrawLine(pen, rect.Left + 10F, rect.Top + 10F, rect.Right - 10F, rect.Bottom - 10F);
                g.DrawLine(pen, rect.Right - 10F, rect.Top + 10F, rect.Left + 10F, rect.Bottom - 10F);
            }
        }

        private static StringFormat CenterFormat()
        {
            StringFormat format = new StringFormat();
            format.Alignment = StringAlignment.Center;
            format.LineAlignment = StringAlignment.Center;
            format.Trimming = StringTrimming.EllipsisCharacter;
            format.FormatFlags = StringFormatFlags.NoWrap;
            return format;
        }

        private void RenderLayeredWindow()
        {
            if (!IsHandleCreated || ClientSize.Width <= 0 || ClientSize.Height <= 0)
            {
                return;
            }

            using (Bitmap bitmap = new Bitmap(ClientSize.Width, ClientSize.Height, PixelFormat.Format32bppPArgb))
            {
                using (Graphics g = Graphics.FromImage(bitmap))
                {
                    RenderPopup(g);
                }

                IntPtr screenDc = GetDC(IntPtr.Zero);
                IntPtr memDc = CreateCompatibleDC(screenDc);
                IntPtr hBitmap = bitmap.GetHbitmap(Color.FromArgb(0));
                IntPtr oldBitmap = SelectObject(memDc, hBitmap);
                try
                {
                    Win32Point top = new Win32Point(Left, Top);
                    Win32Size size = new Win32Size(ClientSize.Width, ClientSize.Height);
                    Win32Point source = new Win32Point(0, 0);
                    BlendFunction blend = new BlendFunction();
                    blend.BlendOp = 0;
                    blend.BlendFlags = 0;
                    blend.SourceConstantAlpha = 255;
                    blend.AlphaFormat = 1;
                    UpdateLayeredWindow(Handle, screenDc, ref top, ref size, memDc, ref source, 0, ref blend, 2);
                }
                finally
                {
                    SelectObject(memDc, oldBitmap);
                    DeleteObject(hBitmap);
                    DeleteDC(memDc);
                    ReleaseDC(IntPtr.Zero, screenDc);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Win32Point
        {
            public int X;
            public int Y;

            public Win32Point(int x, int y)
            {
                X = x;
                Y = y;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Win32Size
        {
            public int Width;
            public int Height;

            public Win32Size(int width, int height)
            {
                Width = width;
                Height = height;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct BlendFunction
        {
            public byte BlendOp;
            public byte BlendFlags;
            public byte SourceConstantAlpha;
            public byte AlphaFormat;
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool UpdateLayeredWindow(IntPtr hwnd, IntPtr hdcDst, ref Win32Point pptDst, ref Win32Size psize, IntPtr hdcSrc, ref Win32Point pptSrc, int crKey, ref BlendFunction pblend, int dwFlags);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetDC(IntPtr hwnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int ReleaseDC(IntPtr hwnd, IntPtr hdc);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern IntPtr CreateCompatibleDC(IntPtr hdc);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern bool DeleteDC(IntPtr hdc);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern IntPtr SelectObject(IntPtr hdc, IntPtr hgdiobj);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern bool DeleteObject(IntPtr hObject);

        private void RaiseAndClose(EventHandler handler)
        {
            EventHandler current = handler;
            Close();
            if (current != null)
            {
                current(this, EventArgs.Empty);
            }
        }

        private static GraphicsPath RoundRect(Rectangle rect, int radius)
        {
            GraphicsPath path = new GraphicsPath();
            int diameter = radius * 2;
            Rectangle arc = new Rectangle(rect.Left, rect.Top, diameter, diameter);
            path.AddArc(arc, 180, 90);
            arc.X = rect.Right - diameter;
            path.AddArc(arc, 270, 90);
            arc.Y = rect.Bottom - diameter;
            path.AddArc(arc, 0, 90);
            arc.X = rect.Left;
            path.AddArc(arc, 90, 90);
            path.CloseFigure();
            return path;
        }

        private sealed class AvatarLarge : Control
        {
            public string Username { get; set; }
            public string ImagePath { get; set; }

            public AvatarLarge()
            {
                SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.UserPaint, true);
            }

            protected override void OnPaint(PaintEventArgs e)
            {
                TechStyle.Configure(e.Graphics);
                Rectangle rect = ClientRectangle;
                rect.Inflate(-2, -2);
                AccountVisuals.DrawAvatar(e.Graphics, rect, Username, ImagePath, true);

                Rectangle badge = new Rectangle(rect.Right - 30, rect.Bottom - 30, 28, 28);
                using (Brush back = new SolidBrush(Color.FromArgb(33, 38, 44)))
                {
                    e.Graphics.FillEllipse(back, badge);
                }
                using (Pen pen = new Pen(Color.FromArgb(225, 235, 245), 2F))
                {
                    e.Graphics.DrawRectangle(pen, badge.Left + 8, badge.Top + 9, 12, 10);
                    e.Graphics.DrawArc(pen, badge.Left + 10, badge.Top + 6, 8, 8, 200, 140);
                }
            }
        }
    }

    public sealed class MainForm : Form
    {
        private static readonly Color AppBackground = Color.FromArgb(5, 12, 28);
        private static readonly Color Surface = Color.FromArgb(10, 20, 42);
        private static readonly Color SurfaceAlt = Color.FromArgb(13, 31, 58);
        private static readonly Color SurfaceSoft = Color.FromArgb(18, 42, 78);
        private static readonly Color Border = Color.FromArgb(52, 99, 145);
        private static readonly Color TextMain = Color.FromArgb(232, 240, 255);
        private static readonly Color TextMuted = Color.FromArgb(145, 170, 205);
        private static readonly Color Accent = Color.FromArgb(0, 229, 255);
        private static readonly Color AccentSoft = Color.FromArgb(24, 194, 215);
        private static readonly Color AccentMagenta = Color.FromArgb(219, 60, 255);
        private static readonly Color SuccessBack = Color.FromArgb(10, 86, 76);
        private static readonly Color WarningBack = Color.FromArgb(108, 75, 20);
        private static readonly Color DangerBack = Color.FromArgb(114, 32, 60);
        private static readonly byte[] HistoryMagicV1 = Encoding.ASCII.GetBytes("SPMH1\n");
        private static readonly byte[] HistoryMagic = Encoding.ASCII.GetBytes("SPMH2\n");
        private const int MaxConcurrentPings = 32;
        private const int MaxVisibleDeviceRows = 500;

        private static readonly string[] DeviceTypes = new string[]
        {
            "PTZ",
            "F1",
            "F2",
            "LP 01",
            "LP 02",
            "Fija",
            "PMI",
            "LPR",
            "PMI Resguardo",
            "Arco",
            "Remolque",
            "Radio",
            "Switch",
            "Otro"
        };

        private static readonly string[] DashboardTechnologies = new string[]
        {
            "PMI",
            "PMI de resguardo",
            "LPR",
            "Arco",
            "Remolque",
            "Radio",
            "Switch",
            "Otro"
        };

        private readonly BindingList<DeviceRecord> _devices;
        private readonly BindingList<DeviceRecord> _visibleDevices;
        private readonly BindingSource _source;
        private readonly List<PingHistoryEntry> _history;
        private readonly System.Windows.Forms.Timer _timer;
        private readonly string _dataPath;
        private readonly string _historyPath;
        private readonly string _legacyHistoryPath;
        private readonly string _historyResetPath;
        private readonly UserStore _userStore;
        private readonly object _pendingResultLock;
        private readonly List<PingResult> _pendingResults;

        private TabControl _tabs;
        private TabPage _monitorPage;
        private TabPage _dashboardPage;
        private DataGridView _grid;
        private DataGridView _dashboardGrid;
        private DashboardView _dashboardView;
        private Panel _dashboardScrollPanel;
        private RowStyle _monitorFilterRowStyle;
        private RowStyle _monitorHeaderRowStyle;
        private RowStyle _dashboardHeaderRowStyle;
        private Button _removeButton;
        private Button _startButton;
        private Button _stopButton;
        private Button _checkNowButton;
        private Button _saveButton;
        private Button _exportButton;
        private Button _resetFailuresButton;
        private Button _resetHistoryButton;
        private Button _refreshDashboardButton;
        private Button _downloadDashboardReportButton;
        private Button _clearHistoryButton;
        private UserMenuButton _monitorUserMenuButton;
        private UserMenuButton _dashboardUserMenuButton;
        private AccountMenuPopup _accountMenuPopup;
        private NumericUpDown _intervalInput;
        private NumericUpDown _timeoutInput;
        private TextBox _filterText;
        private ComboBox _typeFilter;
        private ComboBox _monitorSubcenterFilter;
        private ComboBox _monitorStatusFilter;
        private ComboBox _dashboardGroupFilter;
        private ComboBox _dashboardTechnologyFilter;
        private ComboBox _dashboardSubcenterFilter;
        private ComboBox _dashboardAffiliationFilter;
        private TextBox _dashboardSearchText;
        private Label _summaryLabel;
        private Label _lastRunLabel;
        private Label _dashboardSummaryLabel;
        private Label _kpiAvailabilityLabel;
        private Label _kpiSamplesLabel;
        private Label _kpiOnlineLabel;
        private Label _kpiOfflineLabel;
        private StatusStrip _statusStrip;
        private ToolStripStatusLabel _statusText;

        private volatile bool _sweepRunning;
        private int _activeTasks;
        private DateTime _lastSweepStarted;
        private DashboardStats _currentDashboardTotal;
        private List<DashboardStats> _currentDashboardStats;
        private List<DashboardStats> _currentDashboardSubcenterStats;
        private DateTime _currentDashboardCutoff;
        private DateTime _currentDashboardNow;
        private string _currentDashboardGroupLabel;
        private string _currentTechnologyFilter;
        private string _currentSubcenterFilter;
        private string _currentAffiliationFilter;
        private string _currentSearchFilter;
        private bool _resultDrainScheduled;
        private bool _suppressDashboardFilterEvents;
        private bool _suppressMonitorFilterEvents;
        private bool _historyNeedsRewrite;
        private string _signedInUser;
        private string _signedInRole;
        private UserStore.UserProfile _signedInProfile;
        private int _dashboardWindowDays;

        public bool LogoutRequested { get; private set; }

        public MainForm()
            : this("", UserStore.RoleAdministrator)
        {
        }

        public MainForm(string signedInUser)
            : this(signedInUser, UserStore.RoleAdministrator)
        {
        }

        public MainForm(string signedInUser, string signedInRole)
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            UpdateStyles();

            _signedInUser = signedInUser == null ? "" : signedInUser.Trim();
            _signedInRole = UserStore.NormalizeRole(signedInRole);
            _devices = new BindingList<DeviceRecord>();
            _visibleDevices = new BindingList<DeviceRecord>();
            _source = new BindingSource();
            _history = new List<PingHistoryEntry>();
            _pendingResultLock = new object();
            _pendingResults = new List<PingResult>();
            _currentDashboardStats = new List<DashboardStats>();
            _currentDashboardSubcenterStats = new List<DashboardStats>();
            _dashboardGrid = null;
            _timer = new System.Windows.Forms.Timer();
            _timer.Interval = 3600 * 1000;
            _dataPath = Path.Combine(Application.StartupPath, "devices.xml");
            _historyPath = Path.Combine(Application.StartupPath, "history.dat");
            _legacyHistoryPath = Path.Combine(Application.StartupPath, "history.csv");
            _historyResetPath = Path.Combine(Application.StartupPath, "history_reset.txt");
            _userStore = new UserStore(Path.Combine(Application.StartupPath, "users.xml"));
            _dashboardWindowDays = UserStore.DefaultDashboardDays;

            SetSignedInUser(_signedInUser, _signedInRole);
            SetWindowIcon();
            StartPosition = FormStartPosition.CenterScreen;
            ControlBox = false;
            Width = 1180;
            Height = 720;
            MinimumSize = new Size(980, 560);
            Font = new Font("Segoe UI", 9F);
            BackColor = AppBackground;

            BuildInterface();
            WireEvents();
            ApplyUserPreferences();
            ApplyLocalization(false);
            ApplyRolePermissions();
            LoadDevices();
            EnsureHistoryResetCycle();
            LoadHistory();
            if (PruneHistory())
            {
                SaveHistory();
            }
            RefreshMonitorFilters();
            ApplyFilter();
            UpdateSummary();
            Shown += delegate
            {
                if (_devices.Count > 0 && !_timer.Enabled)
                {
                    if (!UserStore.IsMonitor(_signedInRole))
                    {
                        StartMonitoring();
                    }
                }
            };
        }

        private void SetSignedInUser(string username)
        {
            SetSignedInUser(username, _signedInRole);
        }

        private void SetSignedInUser(string username, string role)
        {
            _signedInUser = username == null ? "" : username.Trim();
            _signedInRole = UserStore.NormalizeRole(role);
            _signedInProfile = _userStore == null ? null : _userStore.GetUserProfile(_signedInUser);
            if (_signedInProfile != null)
            {
                _signedInRole = UserStore.NormalizeRole(_signedInProfile.Role);
            }
            Text = String.IsNullOrWhiteSpace(_signedInUser) ? "ping_scan" : "ping_scan - " + _signedInUser + " (" + UiText.Role(_signedInRole, IsEnglishUi()) + ")";
            UpdateUserMenuButtons();
        }

        private void UpdateUserMenuButtons()
        {
            string imagePath = _signedInProfile == null ? "" : _signedInProfile.ProfileImagePath;
            ApplyUserMenuButtonState(_monitorUserMenuButton, imagePath);
            ApplyUserMenuButtonState(_dashboardUserMenuButton, imagePath);
        }

        private void ApplyUserMenuButtonState(UserMenuButton button, string imagePath)
        {
            if (button == null)
            {
                return;
            }

            button.Username = _signedInUser;
            button.Role = UiText.Role(_signedInRole, IsEnglishUi());
            button.ProfileImagePath = imagePath;
            button.Invalidate();
        }

        private void SetWindowIcon()
        {
            try
            {
                Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
                ShowIcon = true;
            }
            catch
            {
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            try
            {
                SaveDevices();
            }
            catch
            {
                // Avoid blocking application close if the local XML cannot be written.
            }

            base.OnFormClosing(e);
        }

        private void BuildInterface()
        {
            _tabs = new TabControl();
            _tabs.Dock = DockStyle.Fill;
            _tabs.Padding = new Point(12, 4);
            _tabs.DrawMode = TabDrawMode.OwnerDrawFixed;
            _tabs.ItemSize = new Size(170, 34);
            _tabs.SizeMode = TabSizeMode.Fixed;
            TechStyle.EnableDoubleBuffer(_tabs);
            Controls.Add(_tabs);

            _monitorPage = new TabPage("Monitor");
            _monitorPage.BackColor = AppBackground;
            TechStyle.EnableDoubleBuffer(_monitorPage);
            _dashboardPage = new TabPage("Disponibilidad");
            _dashboardPage.BackColor = AppBackground;
            TechStyle.EnableDoubleBuffer(_dashboardPage);
            _tabs.TabPages.Add(_monitorPage);
            _tabs.TabPages.Add(_dashboardPage);

            TableLayoutPanel monitorLayout = new TableLayoutPanel();
            monitorLayout.Dock = DockStyle.Fill;
            monitorLayout.BackColor = AppBackground;
            TechStyle.EnableDoubleBuffer(monitorLayout);
            monitorLayout.ColumnCount = 1;
            monitorLayout.RowCount = 3;
            monitorLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            _monitorFilterRowStyle = new RowStyle(SizeType.Absolute, 92F);
            _monitorHeaderRowStyle = new RowStyle(SizeType.Absolute, 170F);
            monitorLayout.RowStyles.Add(_monitorFilterRowStyle);
            monitorLayout.RowStyles.Add(_monitorHeaderRowStyle);
            monitorLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            _monitorPage.Controls.Add(monitorLayout);

            Panel header = new Panel();
            header.Dock = DockStyle.Fill;
            header.Height = 120;
            header.BackColor = Surface;
            TechStyle.AttachSurface(header, Color.FromArgb(12, 32, 64), Color.FromArgb(7, 16, 36), Accent, true);
            header.Padding = new Padding(14, 10, 14, 8);
            monitorLayout.Controls.Add(header, 0, 1);

            Label title = new Label();
            title.Text = "Monitor de dispositivos";
            title.Font = new Font("Segoe UI Semibold", 15F, FontStyle.Bold);
            title.AutoSize = false;
            title.ForeColor = TextMain;
            title.Location = new Point(250, 10);
            header.Controls.Add(title);
            Control monitorLogo = AddLogoCard(header, new Rectangle(14, 18, 330, 92));

            _summaryLabel = new Label();
            _summaryLabel.Text = "Total: 0";
            _summaryLabel.AutoSize = false;
            _summaryLabel.ForeColor = TextMain;
            _summaryLabel.Location = new Point(254, 45);
            header.Controls.Add(_summaryLabel);

            _lastRunLabel = new Label();
            _lastRunLabel.Text = "Sin revision";
            _lastRunLabel.AutoSize = false;
            _lastRunLabel.ForeColor = TextMuted;
            _lastRunLabel.Location = new Point(254, 66);
            header.Controls.Add(_lastRunLabel);

            FlowLayoutPanel toolbar = new FlowLayoutPanel();
            toolbar.Dock = DockStyle.None;
            toolbar.Width = 620;
            toolbar.FlowDirection = FlowDirection.LeftToRight;
            toolbar.WrapContents = true;
            toolbar.BackColor = Color.Transparent;
            toolbar.Padding = new Padding(0, 1, 0, 0);
            header.Controls.Add(toolbar);

            _removeButton = MakeButton("Gestionar dispositivos");
            _checkNowButton = MakeButton("Revisar ahora");
            _startButton = MakeButton("Iniciar");
            _stopButton = MakeButton("Detener");
            _saveButton = MakeButton("Guardar cambios");
            _exportButton = MakeButton("Exportar CSV");
            _resetFailuresButton = MakeButton("Limpiar fallos");
            _resetHistoryButton = MakeButton("Reset historial");
            _resetHistoryButton.Width = 120;
            _resetHistoryButton.BackColor = Color.FromArgb(88, 63, 26);
            _checkNowButton.BackColor = Color.FromArgb(14, 116, 144);
            _startButton.BackColor = AccentSoft;
            _startButton.ForeColor = Color.FromArgb(2, 6, 23);
            _stopButton.BackColor = DangerBack;

            toolbar.Controls.Add(_removeButton);
            toolbar.Controls.Add(_checkNowButton);
            toolbar.Controls.Add(_startButton);
            toolbar.Controls.Add(_stopButton);
            toolbar.Controls.Add(_saveButton);
            toolbar.Controls.Add(_exportButton);
            toolbar.Controls.Add(_resetFailuresButton);
            toolbar.Controls.Add(_resetHistoryButton);
            TechStyle.MakeChromeTransparent(header);
            header.Resize += delegate { ArrangeMonitorHeader(header, monitorLogo, title, _summaryLabel, _lastRunLabel, toolbar); };
            ArrangeMonitorHeader(header, monitorLogo, title, _summaryLabel, _lastRunLabel, toolbar);

            Panel filters = new Panel();
            filters.Dock = DockStyle.Fill;
            filters.Height = 56;
            filters.BackColor = SurfaceAlt;
            TechStyle.AttachSurface(filters, Color.FromArgb(15, 37, 68), Color.FromArgb(10, 24, 46), AccentSoft, false);
            filters.Padding = new Padding(14, 11, 14, 8);
            monitorLayout.Controls.Add(filters, 0, 0);

            Label intervalLabel = new Label();
            intervalLabel.Text = "Intervalo (seg)";
            intervalLabel.AutoSize = true;
            intervalLabel.ForeColor = TextMuted;
            intervalLabel.Location = new Point(18, 18);
            filters.Controls.Add(intervalLabel);

            _intervalInput = new NumericUpDown();
            _intervalInput.Minimum = 5;
            _intervalInput.Maximum = 86400;
            _intervalInput.Value = 3600;
            _intervalInput.Width = 70;
            _intervalInput.BackColor = SurfaceSoft;
            _intervalInput.ForeColor = TextMain;
            _intervalInput.Location = new Point(113, 14);
            filters.Controls.Add(_intervalInput);

            Label timeoutLabel = new Label();
            timeoutLabel.Text = "Timeout (ms)";
            timeoutLabel.AutoSize = true;
            timeoutLabel.ForeColor = TextMuted;
            timeoutLabel.Location = new Point(202, 18);
            filters.Controls.Add(timeoutLabel);

            _timeoutInput = new NumericUpDown();
            _timeoutInput.Minimum = 250;
            _timeoutInput.Maximum = 10000;
            _timeoutInput.Increment = 250;
            _timeoutInput.Value = 1000;
            _timeoutInput.Width = 80;
            _timeoutInput.BackColor = SurfaceSoft;
            _timeoutInput.ForeColor = TextMain;
            _timeoutInput.Location = new Point(282, 14);
            filters.Controls.Add(_timeoutInput);

            Label filterLabel = new Label();
            filterLabel.Text = "Buscar";
            filterLabel.AutoSize = true;
            filterLabel.ForeColor = TextMuted;
            filterLabel.Location = new Point(388, 18);
            filters.Controls.Add(filterLabel);

            _filterText = new TextBox();
            _filterText.Width = 240;
            _filterText.BackColor = SurfaceSoft;
            _filterText.ForeColor = TextMain;
            _filterText.BorderStyle = BorderStyle.FixedSingle;
            _filterText.Location = new Point(435, 14);
            filters.Controls.Add(_filterText);

            Label typeLabel = new Label();
            typeLabel.Text = "Tipo";
            typeLabel.AutoSize = true;
            typeLabel.ForeColor = TextMuted;
            typeLabel.Location = new Point(695, 18);
            filters.Controls.Add(typeLabel);

            _typeFilter = new ComboBox();
            _typeFilter.DropDownStyle = ComboBoxStyle.DropDownList;
            _typeFilter.Width = 150;
            _typeFilter.BackColor = SurfaceSoft;
            _typeFilter.ForeColor = TextMain;
            _typeFilter.Location = new Point(730, 14);
            _typeFilter.Items.Add("Todos");
            for (int i = 0; i < DeviceTypes.Length; i++)
            {
                _typeFilter.Items.Add(DeviceTypes[i]);
            }

            _typeFilter.SelectedIndex = 0;
            filters.Controls.Add(_typeFilter);

            Label subcenterFilterLabel = new Label();
            subcenterFilterLabel.Text = "Ubicacion / sitio";
            subcenterFilterLabel.AutoSize = true;
            subcenterFilterLabel.ForeColor = TextMuted;
            subcenterFilterLabel.Location = new Point(900, 18);
            filters.Controls.Add(subcenterFilterLabel);

            _monitorSubcenterFilter = new ComboBox();
            _monitorSubcenterFilter.DropDownStyle = ComboBoxStyle.DropDown;
            _monitorSubcenterFilter.AutoCompleteMode = AutoCompleteMode.SuggestAppend;
            _monitorSubcenterFilter.AutoCompleteSource = AutoCompleteSource.ListItems;
            _monitorSubcenterFilter.Width = 130;
            _monitorSubcenterFilter.BackColor = SurfaceSoft;
            _monitorSubcenterFilter.ForeColor = TextMain;
            _monitorSubcenterFilter.Location = new Point(970, 14);
            filters.Controls.Add(_monitorSubcenterFilter);

            Label statusFilterLabel = new Label();
            statusFilterLabel.Text = "Estado";
            statusFilterLabel.AutoSize = true;
            statusFilterLabel.ForeColor = TextMuted;
            statusFilterLabel.Location = new Point(1120, 18);
            filters.Controls.Add(statusFilterLabel);

            _monitorStatusFilter = new ComboBox();
            _monitorStatusFilter.DropDownStyle = ComboBoxStyle.DropDownList;
            _monitorStatusFilter.Width = 135;
            _monitorStatusFilter.BackColor = SurfaceSoft;
            _monitorStatusFilter.ForeColor = TextMain;
            _monitorStatusFilter.Location = new Point(1172, 14);
            _monitorStatusFilter.Items.Add("Todos");
            _monitorStatusFilter.Items.Add("En linea");
            _monitorStatusFilter.Items.Add("Sin respuesta");
            _monitorStatusFilter.Items.Add("Error");
            _monitorStatusFilter.Items.Add("Pendiente");
            _monitorStatusFilter.SelectedIndex = 0;
            filters.Controls.Add(_monitorStatusFilter);
            _monitorUserMenuButton = CreateUserMenuButton(filters);
            TechStyle.MakeChromeTransparent(filters);
            filters.Resize += delegate
            {
                ArrangeMonitorFilters(
                    filters,
                    intervalLabel,
                    _intervalInput,
                    timeoutLabel,
                    _timeoutInput,
                    filterLabel,
                    _filterText,
                    typeLabel,
                    _typeFilter,
                    subcenterFilterLabel,
                    _monitorSubcenterFilter,
                    statusFilterLabel,
                    _monitorStatusFilter,
                    _monitorUserMenuButton);
            };
            ArrangeMonitorFilters(
                filters,
                intervalLabel,
                _intervalInput,
                timeoutLabel,
                _timeoutInput,
                filterLabel,
                _filterText,
                typeLabel,
                _typeFilter,
                subcenterFilterLabel,
                _monitorSubcenterFilter,
                statusFilterLabel,
                _monitorStatusFilter,
                _monitorUserMenuButton);

            _grid = new DataGridView();
            TechStyle.EnableDoubleBuffer(_grid);
            _grid.Dock = DockStyle.Fill;
            _grid.BackgroundColor = AppBackground;
            _grid.BorderStyle = BorderStyle.None;
            _grid.AllowUserToAddRows = false;
            _grid.AllowUserToDeleteRows = false;
            _grid.AutoGenerateColumns = false;
            _grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            _grid.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.None;
            _grid.RowHeadersVisible = false;
            _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            _grid.MultiSelect = true;
            _grid.EnableHeadersVisualStyles = false;
            _grid.GridColor = Border;
            _grid.DefaultCellStyle.BackColor = Surface;
            _grid.DefaultCellStyle.ForeColor = TextMain;
            _grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(14, 116, 144);
            _grid.DefaultCellStyle.SelectionForeColor = Color.White;
            _grid.AlternatingRowsDefaultCellStyle.BackColor = SurfaceAlt;
            _grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(2, 6, 23);
            _grid.ColumnHeadersDefaultCellStyle.ForeColor = TextMain;
            _grid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold);
            _grid.ColumnHeadersHeight = 34;
            _grid.RowTemplate.Height = 30;
            monitorLayout.Controls.Add(_grid, 0, 2);

            AddTextColumn("Name", "Dispositivo", 230, false);
            AddTextColumn("Ip", "IP", 135, false);

            DataGridViewComboBoxColumn typeColumn = new DataGridViewComboBoxColumn();
            typeColumn.DataPropertyName = "Type";
            typeColumn.HeaderText = "Tipo";
            typeColumn.Name = "Type";
            typeColumn.Width = 145;
            typeColumn.MinimumWidth = 80;
            typeColumn.FillWeight = 95;
            typeColumn.FlatStyle = FlatStyle.Flat;
            typeColumn.DataSource = DeviceTypes;
            _grid.Columns.Add(typeColumn);

            AddTextColumn("Subcenter", "Ubicacion / sitio", 150, false);
            AddTextColumn("Affiliation", "Afiliacion", 115, false);
            AddTextColumn("Status", "Estado", 120, true);
            AddTextColumn("Latency", "Latencia", 95, true);
            AddTextColumn("LastCheck", "Ultima revision", 155, true);
            AddTextColumn("Failures", "Fallos", 70, true);
            AddTextColumn("Notes", "Tecnologia", 260, false);

            _statusStrip = new StatusStrip();
            _statusStrip.BackColor = Surface;
            _statusStrip.ForeColor = TextMuted;
            _statusText = new ToolStripStatusLabel();
            _statusText.Text = "Listo";
            _statusText.ForeColor = TextMuted;
            _statusStrip.Items.Add(_statusText);
            Controls.Add(_statusStrip);

            _source.DataSource = _visibleDevices;
            _grid.DataSource = _source;

            BuildDashboardPage();
        }

        private UserMenuButton CreateUserMenuButton(Control parent)
        {
            UserMenuButton button = new UserMenuButton();
            button.Username = _signedInUser;
            button.Role = _signedInRole;
            button.ProfileImagePath = _signedInProfile == null ? "" : _signedInProfile.ProfileImagePath;
            button.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            button.Click += delegate { ShowUserMenu(button); };
            parent.Controls.Add(button);
            button.BringToFront();
            return button;
        }

        private void ArrangeUserMenuButton(UserMenuButton button, Control parent, int top)
        {
            if (button == null || parent == null)
            {
                return;
            }

            const int rightMargin = 12;
            int width = parent.ClientSize.Width < 700 ? 58 : 190;
            int height = 44;
            button.ShowCompact = parent.ClientSize.Width < 700;
            button.SetBounds(Math.Max(18, parent.ClientSize.Width - width - rightMargin), top, width, height);
            button.BringToFront();
        }

        private void ShowUserMenu(UserMenuButton sourceButton)
        {
            if (sourceButton == null)
            {
                return;
            }

            if (_accountMenuPopup != null && !_accountMenuPopup.IsDisposed)
            {
                _accountMenuPopup.Close();
                return;
            }

            string imagePath = _signedInProfile == null ? "" : _signedInProfile.ProfileImagePath;
            _accountMenuPopup = new AccountMenuPopup(_signedInUser, _signedInRole, imagePath, UserStore.IsAdministrator(_signedInRole), IsEnglishUi());
            _accountMenuPopup.AccountSettingsClicked += delegate { OpenAccountSettings(); };
            _accountMenuPopup.ManageUsersClicked += delegate { OpenUserManagement(); };
            _accountMenuPopup.SignOutClicked += delegate { SignOut(); };

            Point screen = sourceButton.PointToScreen(new Point(sourceButton.Width, sourceButton.Height + 8));
            _accountMenuPopup.Location = new Point(screen.X - _accountMenuPopup.Width, screen.Y);
            _accountMenuPopup.Show(this);
        }

        private void ApplyUserPreferences()
        {
            if (_signedInProfile == null)
            {
                _signedInProfile = _userStore.GetUserProfile(_signedInUser);
            }

            int interval = _signedInProfile == null ? UserStore.DefaultIntervalSeconds : _signedInProfile.DefaultIntervalSeconds;
            int timeout = _signedInProfile == null ? UserStore.DefaultTimeoutMs : _signedInProfile.DefaultTimeoutMs;
            _dashboardWindowDays = _signedInProfile == null ? UserStore.DefaultDashboardDays : _signedInProfile.DashboardDays;
            _dashboardWindowDays = Math.Max(1, Math.Min(30, _dashboardWindowDays));

            if (_intervalInput != null)
            {
                _intervalInput.Value = Math.Max(_intervalInput.Minimum, Math.Min(_intervalInput.Maximum, interval));
            }

            if (_timeoutInput != null)
            {
                _timeoutInput.Value = Math.Max(_timeoutInput.Minimum, Math.Min(_timeoutInput.Maximum, timeout));
            }

            if (_dashboardPage != null)
            {
                _dashboardPage.Text = T("Disponibilidad", "Availability");
            }

            if (_dashboardSummaryLabel != null)
            {
                _dashboardSummaryLabel.Text = IsEnglishUi()
                    ? "Availability from the last " + _dashboardWindowDays.ToString(CultureInfo.InvariantCulture) + " days"
                    : "Disponibilidad de los ultimos " + _dashboardWindowDays.ToString(CultureInfo.InvariantCulture) + " dias";
            }
        }

        private bool IsEnglishUi()
        {
            return _signedInProfile != null
                && UserStore.NormalizeLanguage(_signedInProfile.Language) == UserStore.LanguageEnglish;
        }

        private string T(string spanish, string english)
        {
            return UiText.Pick(IsEnglishUi(), spanish, english);
        }

        private void ApplyLocalization(bool refreshData)
        {
            bool english = IsEnglishUi();
            Text = String.IsNullOrWhiteSpace(_signedInUser) ? "ping_scan" : "ping_scan - " + _signedInUser + " (" + UiText.Role(_signedInRole, english) + ")";
            UiText.ApplyToTree(this, english);
            ApplyButtonLocalization();
            ApplyTabLocalization();
            ApplyGridHeaderLocalization();
            ApplyComboLocalization();
            if (_dashboardView != null)
            {
                _dashboardView.SetLanguage(english);
            }

            UpdateUserMenuButtons();
            if (_tabs != null)
            {
                _tabs.Invalidate();
            }

            if (refreshData)
            {
                ApplyFilter();
                UpdateSummary();
            }
        }

        private void ApplyButtonLocalization()
        {
            SetButtonText(_removeButton, T("Gestionar dispositivos", "Manage devices"), 156);
            SetButtonText(_checkNowButton, T("Revisar ahora", "Check now"), 112);
            SetButtonText(_startButton, T("Iniciar", "Start"), 92);
            SetButtonText(_stopButton, T("Detener", "Stop"), 92);
            SetButtonText(_saveButton, T("Guardar cambios", "Save changes"), 128);
            SetButtonText(_exportButton, T("Exportar CSV", "Export CSV"), 112);
            SetButtonText(_resetFailuresButton, T("Limpiar fallos", "Clear failures"), 116);
            SetButtonText(_resetHistoryButton, T("Reset historial", "Reset history"), 116);
            SetButtonText(_refreshDashboardButton, T("Actualizar", "Refresh"), 106);
            SetButtonText(_downloadDashboardReportButton, T("Descargar reporte", "Download report"), 136);
            SetButtonText(_clearHistoryButton, T("Limpiar historial", "Clear history"), 124);
        }

        private void SetButtonText(Button button, string text, int width)
        {
            if (button == null)
            {
                return;
            }

            button.Text = text;
            button.Width = Math.Max(width, TextRenderer.MeasureText(text, button.Font).Width + 30);
        }

        private void ApplyTabLocalization()
        {
            if (_monitorPage != null)
            {
                _monitorPage.Text = T("Monitor", "Monitor");
            }

            if (_dashboardPage != null)
            {
                _dashboardPage.Text = T("Disponibilidad", "Availability");
            }
        }

        private void ApplyGridHeaderLocalization()
        {
            if (_grid != null)
            {
                SetGridHeader(_grid, "Name", T("Dispositivo", "Device"));
                SetGridHeader(_grid, "Ip", "IP");
                SetGridHeader(_grid, "Type", T("Tipo", "Type"));
                SetGridHeader(_grid, "Subcenter", T("Ubicacion / sitio", "Location / site"));
                SetGridHeader(_grid, "Affiliation", T("Afiliacion", "Affiliation"));
                SetGridHeader(_grid, "Status", T("Estado", "Status"));
                SetGridHeader(_grid, "Latency", T("Latencia", "Latency"));
                SetGridHeader(_grid, "LastCheck", T("Ultima revision", "Last check"));
                SetGridHeader(_grid, "Failures", T("Fallos", "Failures"));
                SetGridHeader(_grid, "Notes", T("Tecnologia", "Technology"));
            }

            if (_dashboardGrid != null)
            {
                SetGridHeader(_dashboardGrid, "Technology", T("Tecnologia", "Technology"));
                SetGridHeader(_dashboardGrid, "Devices", T("Dispositivos", "Devices"));
                SetGridHeader(_dashboardGrid, "Samples", T("Muestras", "Samples"));
                SetGridHeader(_dashboardGrid, "Online", T("En linea", "Online"));
                SetGridHeader(_dashboardGrid, "Offline", T("Sin respuesta", "No response"));
                SetGridHeader(_dashboardGrid, "Availability", T("Disponibilidad", "Availability"));
                SetGridHeader(_dashboardGrid, "Active", T("Tiempo activo", "Active time"));
                SetGridHeader(_dashboardGrid, "LastSample", T("Ultima muestra", "Last sample"));
            }
        }

        private void SetGridHeader(DataGridView grid, string columnName, string header)
        {
            if (grid != null && grid.Columns.Contains(columnName))
            {
                grid.Columns[columnName].HeaderText = header;
            }
        }

        private void ApplyComboLocalization()
        {
            RefreshDashboardGroupItems();
            RefreshMonitorStatusFilter();
            RefreshMonitorFilters();
            RefreshDashboardFilters();
        }

        private void RefreshDashboardGroupItems()
        {
            if (_dashboardGroupFilter == null)
            {
                return;
            }

            string key = CanonicalDashboardGroup(GetComboText(_dashboardGroupFilter, "Tecnologia"));
            _suppressDashboardFilterEvents = true;
            try
            {
                _dashboardGroupFilter.BeginUpdate();
                _dashboardGroupFilter.Items.Clear();
                _dashboardGroupFilter.Items.Add(DisplayDashboardGroup("technology"));
                _dashboardGroupFilter.Items.Add(DisplayDashboardGroup("subcenter"));
                _dashboardGroupFilter.Items.Add(DisplayDashboardGroup("subtechnology"));
                _dashboardGroupFilter.Items.Add(DisplayDashboardGroup("affiliation"));
                _dashboardGroupFilter.Items.Add(DisplayDashboardGroup("device"));
                _dashboardGroupFilter.SelectedItem = DisplayDashboardGroup(key);
                if (_dashboardGroupFilter.SelectedIndex < 0)
                {
                    _dashboardGroupFilter.SelectedIndex = 0;
                }
                _dashboardGroupFilter.EndUpdate();
            }
            finally
            {
                _suppressDashboardFilterEvents = false;
            }
        }

        private void RefreshMonitorStatusFilter()
        {
            if (_monitorStatusFilter == null)
            {
                return;
            }

            string selected = UiText.CanonicalStatus(GetComboText(_monitorStatusFilter, "Todos"));
            _suppressMonitorFilterEvents = true;
            try
            {
                _monitorStatusFilter.BeginUpdate();
                _monitorStatusFilter.Items.Clear();
                _monitorStatusFilter.Items.Add(T("Todos", "All"));
                _monitorStatusFilter.Items.Add(UiText.Status("En linea", IsEnglishUi()));
                _monitorStatusFilter.Items.Add(UiText.Status("Sin respuesta", IsEnglishUi()));
                _monitorStatusFilter.Items.Add("Error");
                _monitorStatusFilter.Items.Add(UiText.Status("Pendiente", IsEnglishUi()));
                SelectComboValue(_monitorStatusFilter, selected);
                _monitorStatusFilter.EndUpdate();
            }
            finally
            {
                _suppressMonitorFilterEvents = false;
            }
        }

        private void SelectComboValue(ComboBox combo, string selected)
        {
            if (combo == null || combo.Items.Count == 0)
            {
                return;
            }

            int index = 0;
            for (int i = 0; i < combo.Items.Count; i++)
            {
                string item = Convert.ToString(combo.Items[i], CultureInfo.InvariantCulture);
                if (ComboValuesMatch(item, selected))
                {
                    index = i;
                    break;
                }
            }

            combo.SelectedIndex = index;
        }

        private string DisplayDashboardGroup(string key)
        {
            string normalized = String.IsNullOrWhiteSpace(key) ? "technology" : key.ToLowerInvariant();
            if (normalized == "subcenter")
            {
                return T("Ubicacion / sitio", "Location / site");
            }

            if (normalized == "subtechnology")
            {
                return T("Ubicacion/Tecnologia", "Location/Technology");
            }

            if (normalized == "affiliation")
            {
                return T("Afiliacion", "Affiliation");
            }

            if (normalized == "device")
            {
                return T("Dispositivo/IP", "Device/IP");
            }

            return T("Tecnologia", "Technology");
        }

        private string CanonicalDashboardGroup(string value)
        {
            string text = value == null ? "" : value.Trim();
            if (String.Equals(text, "Subcentro", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Subcenter", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Ubicacion / sitio", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Ubicacion", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Lugar", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Sitio", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Location / site", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Location", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Site", StringComparison.OrdinalIgnoreCase))
            {
                return "subcenter";
            }

            if (String.Equals(text, "Sub/Tecnologia", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Sub/Technology", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Subcentro/Tecnologia", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Subcenter/Technology", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Ubicacion/Tecnologia", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Ubicacion / Tecnologia", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Location/Technology", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Location / Technology", StringComparison.OrdinalIgnoreCase))
            {
                return "subtechnology";
            }

            if (String.Equals(text, "Afiliacion", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Affiliation", StringComparison.OrdinalIgnoreCase))
            {
                return "affiliation";
            }

            if (String.Equals(text, "Camara/IP", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Camera/IP", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Dispositivo/IP", StringComparison.OrdinalIgnoreCase)
                || String.Equals(text, "Device/IP", StringComparison.OrdinalIgnoreCase))
            {
                return "device";
            }

            return "technology";
        }

        private void ApplyRolePermissions()
        {
            bool admin = UserStore.IsAdministrator(_signedInRole);
            bool supervisor = UserStore.IsSupervisor(_signedInRole);
            bool monitor = UserStore.IsMonitor(_signedInRole);

            if (monitor && _tabs.TabPages.Contains(_monitorPage))
            {
                _tabs.TabPages.Remove(_monitorPage);
                _tabs.SelectedTab = _dashboardPage;
            }

            bool canOperateInventory = admin || supervisor;
            bool canUseDestructiveTools = admin;
            SetButtonEnabled(_removeButton, canOperateInventory);
            SetButtonEnabled(_checkNowButton, canOperateInventory);
            SetButtonEnabled(_startButton, canOperateInventory);
            SetButtonEnabled(_stopButton, canOperateInventory);
            SetButtonEnabled(_saveButton, canOperateInventory);
            SetButtonEnabled(_exportButton, canOperateInventory);
            SetButtonEnabled(_resetFailuresButton, canOperateInventory);
            SetButtonEnabled(_resetHistoryButton, canUseDestructiveTools);
            SetButtonEnabled(_clearHistoryButton, canUseDestructiveTools);
            SetButtonEnabled(_downloadDashboardReportButton, !monitor);

            if (_grid != null)
            {
                _grid.ReadOnly = !canOperateInventory;
            }

            if (monitor)
            {
                SetStatus(T("Sesion Monitor: acceso de solo visualizacion al dashboard.", "Monitor session: dashboard view-only access."));
            }
            else if (supervisor)
            {
                SetStatus(T("Sesion Supervisor: monitor, listado y dashboard activos; gestion de usuarios bloqueada.", "Supervisor session: monitor, list and dashboard enabled; user management blocked."));
            }
            else
            {
                SetStatus(T("Sesion Administrador: acceso completo.", "Administrator session: full access."));
            }
        }

        private void SetButtonEnabled(Button button, bool enabled)
        {
            if (button == null)
            {
                return;
            }

            button.Enabled = enabled;
            button.ForeColor = enabled
                ? (button.BackColor == AccentSoft ? Color.FromArgb(2, 6, 23) : TextMain)
                : Color.FromArgb(94, 113, 143);
        }

        private void BuildDashboardPage()
        {
            TableLayoutPanel dashboardLayout = new TableLayoutPanel();
            dashboardLayout.Dock = DockStyle.Fill;
            dashboardLayout.BackColor = AppBackground;
            TechStyle.EnableDoubleBuffer(dashboardLayout);
            dashboardLayout.ColumnCount = 1;
            dashboardLayout.RowCount = 2;
            dashboardLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            _dashboardHeaderRowStyle = new RowStyle(SizeType.Absolute, 236F);
            dashboardLayout.RowStyles.Add(_dashboardHeaderRowStyle);
            dashboardLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            _dashboardPage.Controls.Add(dashboardLayout);

            Panel header = new Panel();
            header.Dock = DockStyle.Fill;
            header.Height = 236;
            header.BackColor = Surface;
            TechStyle.AttachSurface(header, Color.FromArgb(12, 32, 64), Color.FromArgb(7, 16, 36), Accent, true);
            header.Padding = new Padding(14, 10, 14, 8);
            dashboardLayout.Controls.Add(header, 0, 0);

            Label title = new Label();
            title.Text = "Disponibilidad de la red";
            title.Font = new Font("Segoe UI Semibold", 15F, FontStyle.Bold);
            title.AutoSize = false;
            title.ForeColor = TextMain;
            title.Location = new Point(250, 10);
            header.Controls.Add(title);
            Control dashboardLogo = AddLogoCard(header, new Rectangle(14, 18, 330, 92));

            _dashboardSummaryLabel = new Label();
            _dashboardSummaryLabel.Text = "Disponibilidad de los ultimos " + _dashboardWindowDays.ToString(CultureInfo.InvariantCulture) + " dias";
            _dashboardSummaryLabel.AutoSize = false;
            _dashboardSummaryLabel.ForeColor = TextMuted;
            _dashboardSummaryLabel.Location = new Point(254, 48);
            header.Controls.Add(_dashboardSummaryLabel);

            Label groupLabel = new Label();
            groupLabel.Text = "Agrupar";
            groupLabel.AutoSize = true;
            groupLabel.ForeColor = TextMuted;
            groupLabel.Location = new Point(18, 82);
            header.Controls.Add(groupLabel);

            _dashboardGroupFilter = new ComboBox();
            _dashboardGroupFilter.DropDownStyle = ComboBoxStyle.DropDownList;
            _dashboardGroupFilter.BackColor = SurfaceSoft;
            _dashboardGroupFilter.ForeColor = TextMain;
            _dashboardGroupFilter.Width = 125;
            _dashboardGroupFilter.Location = new Point(74, 78);
            _dashboardGroupFilter.Items.Add("Tecnologia");
            _dashboardGroupFilter.Items.Add("Ubicacion / sitio");
            _dashboardGroupFilter.Items.Add("Ubicacion/Tecnologia");
            _dashboardGroupFilter.Items.Add("Afiliacion");
            _dashboardGroupFilter.Items.Add("Dispositivo/IP");
            _dashboardGroupFilter.SelectedIndex = 0;
            header.Controls.Add(_dashboardGroupFilter);

            Label technologyLabel = new Label();
            technologyLabel.Text = "Tecnologia";
            technologyLabel.AutoSize = true;
            technologyLabel.ForeColor = TextMuted;
            technologyLabel.Location = new Point(220, 82);
            header.Controls.Add(technologyLabel);

            _dashboardTechnologyFilter = new ComboBox();
            _dashboardTechnologyFilter.DropDownStyle = ComboBoxStyle.DropDownList;
            _dashboardTechnologyFilter.BackColor = SurfaceSoft;
            _dashboardTechnologyFilter.ForeColor = TextMain;
            _dashboardTechnologyFilter.Width = 150;
            _dashboardTechnologyFilter.Location = new Point(294, 78);
            header.Controls.Add(_dashboardTechnologyFilter);

            Label subcenterLabel = new Label();
            subcenterLabel.Text = "Ubicacion / sitio";
            subcenterLabel.AutoSize = true;
            subcenterLabel.ForeColor = TextMuted;
            subcenterLabel.Location = new Point(466, 82);
            header.Controls.Add(subcenterLabel);

            _dashboardSubcenterFilter = new ComboBox();
            _dashboardSubcenterFilter.DropDownStyle = ComboBoxStyle.DropDown;
            _dashboardSubcenterFilter.AutoCompleteMode = AutoCompleteMode.SuggestAppend;
            _dashboardSubcenterFilter.AutoCompleteSource = AutoCompleteSource.ListItems;
            _dashboardSubcenterFilter.BackColor = SurfaceSoft;
            _dashboardSubcenterFilter.ForeColor = TextMain;
            _dashboardSubcenterFilter.Width = 135;
            _dashboardSubcenterFilter.Location = new Point(540, 78);
            header.Controls.Add(_dashboardSubcenterFilter);

            Label affiliationLabel = new Label();
            affiliationLabel.Text = "Afiliacion";
            affiliationLabel.AutoSize = true;
            affiliationLabel.ForeColor = TextMuted;
            affiliationLabel.Location = new Point(692, 82);
            header.Controls.Add(affiliationLabel);

            _dashboardAffiliationFilter = new ComboBox();
            _dashboardAffiliationFilter.DropDownStyle = ComboBoxStyle.DropDown;
            _dashboardAffiliationFilter.AutoCompleteMode = AutoCompleteMode.SuggestAppend;
            _dashboardAffiliationFilter.AutoCompleteSource = AutoCompleteSource.ListItems;
            _dashboardAffiliationFilter.BackColor = SurfaceSoft;
            _dashboardAffiliationFilter.ForeColor = TextMain;
            _dashboardAffiliationFilter.Width = 135;
            _dashboardAffiliationFilter.Location = new Point(762, 78);
            header.Controls.Add(_dashboardAffiliationFilter);

            Label searchLabel = new Label();
            searchLabel.Text = "IP / Dispositivo";
            searchLabel.AutoSize = true;
            searchLabel.ForeColor = TextMuted;
            searchLabel.Location = new Point(918, 82);
            header.Controls.Add(searchLabel);

            _dashboardSearchText = new TextBox();
            _dashboardSearchText.BackColor = SurfaceSoft;
            _dashboardSearchText.ForeColor = TextMain;
            _dashboardSearchText.BorderStyle = BorderStyle.FixedSingle;
            _dashboardSearchText.Width = 130;
            _dashboardSearchText.Location = new Point(1000, 78);
            header.Controls.Add(_dashboardSearchText);

            FlowLayoutPanel actions = new FlowLayoutPanel();
            actions.Dock = DockStyle.None;
            actions.Width = 430;
            actions.FlowDirection = FlowDirection.LeftToRight;
            actions.WrapContents = true;
            actions.BackColor = Color.Transparent;
            actions.Padding = new Padding(0, 8, 0, 0);
            header.Controls.Add(actions);
            _dashboardUserMenuButton = CreateUserMenuButton(header);

            _refreshDashboardButton = MakeButton("Actualizar");
            _downloadDashboardReportButton = MakeButton("Descargar reporte");
            _downloadDashboardReportButton.Width = 140;
            _clearHistoryButton = MakeButton("Limpiar historial");
            _clearHistoryButton.Width = 120;
            actions.Controls.Add(_refreshDashboardButton);
            actions.Controls.Add(_downloadDashboardReportButton);
            actions.Controls.Add(_clearHistoryButton);

            FlowLayoutPanel kpis = new FlowLayoutPanel();
            kpis.Location = new Point(14, 116);
            kpis.Size = new Size(880, 64);
            kpis.FlowDirection = FlowDirection.LeftToRight;
            kpis.WrapContents = true;
            kpis.BackColor = Color.Transparent;
            header.Controls.Add(kpis);

            _kpiAvailabilityLabel = AddKpiCard(kpis, "Disponibilidad");
            _kpiSamplesLabel = AddKpiCard(kpis, "Muestras");
            _kpiOnlineLabel = AddKpiCard(kpis, "En linea");
            _kpiOfflineLabel = AddKpiCard(kpis, "Sin respuesta");
            TechStyle.MakeChromeTransparent(header);
            header.Resize += delegate
            {
                ArrangeDashboardHeader(
                    header,
                    dashboardLogo,
                    title,
                    _dashboardSummaryLabel,
                    groupLabel,
                    _dashboardGroupFilter,
                    technologyLabel,
                    _dashboardTechnologyFilter,
                    subcenterLabel,
                    _dashboardSubcenterFilter,
                    affiliationLabel,
                    _dashboardAffiliationFilter,
                    searchLabel,
                    _dashboardSearchText,
                    actions,
                    kpis,
                    _dashboardUserMenuButton);
            };
            ArrangeDashboardHeader(
                header,
                dashboardLogo,
                title,
                _dashboardSummaryLabel,
                groupLabel,
                _dashboardGroupFilter,
                technologyLabel,
                _dashboardTechnologyFilter,
                subcenterLabel,
                _dashboardSubcenterFilter,
                affiliationLabel,
                _dashboardAffiliationFilter,
                searchLabel,
                _dashboardSearchText,
                actions,
                kpis,
                _dashboardUserMenuButton);

            _dashboardScrollPanel = new Panel();
            _dashboardScrollPanel.Dock = DockStyle.Fill;
            _dashboardScrollPanel.BackColor = AppBackground;
            _dashboardScrollPanel.AutoScroll = true;
            TechStyle.EnableDoubleBuffer(_dashboardScrollPanel);
            dashboardLayout.Controls.Add(_dashboardScrollPanel, 0, 1);

            _dashboardView = new DashboardView();
            _dashboardView.BackColor = AppBackground;
            _dashboardScrollPanel.Controls.Add(_dashboardView);
            _dashboardScrollPanel.Resize += delegate { ArrangeDashboardCanvas(); };
            ArrangeDashboardCanvas();
        }

        private Label AddKpiCard(FlowLayoutPanel parent, string title)
        {
            Panel card = new Panel();
            TechStyle.EnableDoubleBuffer(card);
            card.Width = 200;
            card.Height = 66;
            card.Margin = new Padding(0, 0, 12, 0);
            card.BackColor = SurfaceAlt;
            card.Padding = new Padding(12, 7, 12, 6);

            Label titleLabel = new Label();
            titleLabel.Text = title;
            titleLabel.AutoSize = false;
            titleLabel.SetBounds(12, 8, card.Width - 24, 18);
            titleLabel.Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right;
            titleLabel.ForeColor = TextMuted;
            titleLabel.Font = new Font("Segoe UI", 8.5F, FontStyle.Regular);
            card.Controls.Add(titleLabel);

            Label valueLabel = new Label();
            valueLabel.Text = "-";
            valueLabel.AutoSize = false;
            valueLabel.SetBounds(12, 28, card.Width - 24, 30);
            valueLabel.Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right;
            valueLabel.ForeColor = Accent;
            valueLabel.Font = new Font("Segoe UI Semibold", 15F, FontStyle.Bold);
            valueLabel.TextAlign = ContentAlignment.MiddleLeft;
            card.Controls.Add(valueLabel);
            card.Resize += delegate
            {
                titleLabel.SetBounds(12, 8, Math.Max(20, card.ClientSize.Width - 24), 18);
                valueLabel.SetBounds(12, 28, Math.Max(20, card.ClientSize.Width - 24), 30);
            };

            parent.Controls.Add(card);
            return valueLabel;
        }

        private Control AddLogoCard(Control parent, Rectangle bounds)
        {
            LogoCard card = new LogoCard();
            card.Bounds = bounds;
            card.Logo = LoadLogoImage();
            parent.Controls.Add(card);
            card.BringToFront();
            return card;
        }

        private Image LoadLogoImage()
        {
            try
            {
                Assembly assembly = Assembly.GetExecutingAssembly();
                using (Stream stream = assembly.GetManifestResourceStream("PingScanLogo"))
                {
                    if (stream != null)
                    {
                        using (Image image = Image.FromStream(stream))
                        {
                            return ProcessLogoForDarkTheme(new Bitmap(image));
                        }
                    }
                }
            }
            catch
            {
            }

            string localLogo = Path.Combine(Application.StartupPath, "ping_scan_logo.png");
            if (File.Exists(localLogo))
            {
                using (Image image = Image.FromFile(localLogo))
                {
                    return ProcessLogoForDarkTheme(new Bitmap(image));
                }
            }

            return null;
        }

        private Image ProcessLogoForDarkTheme(Bitmap source)
        {
            Bitmap output = new Bitmap(source.Width, source.Height, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
            for (int y = 0; y < source.Height; y++)
            {
                for (int x = 0; x < source.Width; x++)
                {
                    Color pixel = source.GetPixel(x, y);
                    int max = Math.Max(pixel.R, Math.Max(pixel.G, pixel.B));
                    int min = Math.Min(pixel.R, Math.Min(pixel.G, pixel.B));
                    bool whiteBackground = max > 238 && (max - min) < 28;
                    bool colorLogoPixel = pixel.A > 0
                        && ((pixel.G > 92 && pixel.B > 88)
                            || (pixel.B > 120 && pixel.R < 90)
                            || (pixel.G > 125 && pixel.R < 95));
                    bool darkBackground = pixel.A > 0
                        && max < 82
                        && !colorLogoPixel;

                    if (whiteBackground || darkBackground)
                    {
                        output.SetPixel(x, y, Color.Transparent);
                    }
                    else if (pixel.R > 210 && pixel.G > 210 && pixel.B > 210 && (max - min) < 28)
                    {
                        output.SetPixel(x, y, Color.Transparent);
                    }
                    else
                    {
                        output.SetPixel(x, y, pixel);
                    }
                }
            }

            source.Dispose();
            return output;
        }

        private void AddDashboardColumn(string name, string header, int width)
        {
            DataGridViewTextBoxColumn column = new DataGridViewTextBoxColumn();
            column.Name = name;
            column.HeaderText = header;
            column.Width = width;
            column.SortMode = DataGridViewColumnSortMode.NotSortable;
            _dashboardGrid.Columns.Add(column);
        }

        private void ArrangeMonitorHeader(Control header, Control logo, Label title, Label summary, Label lastRun, FlowLayoutPanel toolbar)
        {
            int width = Math.Max(1, header.ClientSize.Width);
            float desiredHeight = width < 1180 ? 238F : 220F;
            if (_monitorHeaderRowStyle != null && Math.Abs(_monitorHeaderRowStyle.Height - desiredHeight) > 0.5F)
            {
                _monitorHeaderRowStyle.Height = desiredHeight;
                if (header.Parent != null)
                {
                    header.Parent.PerformLayout();
                }
            }

            int logoWidth = width < 760 ? 300 : width < 1120 ? 350 : width < 1450 ? 430 : 490;
            int logoHeight = Math.Max(78, (int)Math.Round(logoWidth / 4.2F));
            logo.SetBounds(14, 18, logoWidth, logoHeight);

            int textX = logo.Right + 26;
            if (width < 1180)
            {
                int textWidth = Math.Max(260, width - textX - 36);
                if (width < 760)
                {
                    textX = 18;
                    textWidth = Math.Max(260, width - 36);
                    logo.SetBounds(14, 64, logoWidth, logoHeight);
                }
                title.SetBounds(textX, 10, textWidth, 28);
                summary.SetBounds(textX + 4, 43, textWidth, 20);
                lastRun.SetBounds(textX + 4, 64, textWidth, 20);
                int toolbarTop = Math.Max(132, logo.Bottom + 12);
                toolbar.SetBounds(Math.Max(18, textX), toolbarTop, Math.Max(300, width - Math.Max(18, textX) - 18), Math.Max(82, header.ClientSize.Height - toolbarTop - 8));
            }
            else
            {
                int toolbarWidth = Math.Min(920, Math.Max(620, width - textX - 210));
                int toolbarTop = Math.Max(132, logo.Bottom + 10);
                toolbar.SetBounds(width - toolbarWidth - 18, toolbarTop, toolbarWidth, Math.Max(68, header.ClientSize.Height - toolbarTop - 10));

                int textWidth = Math.Max(220, width - textX - 36);
                title.SetBounds(textX, 22, textWidth, 32);
                summary.SetBounds(textX + 4, 64, textWidth, 20);
                lastRun.SetBounds(textX + 4, 87, textWidth, 20);
            }
        }

        private void ArrangeMonitorFilters(
            Control filters,
            Label intervalLabel,
            NumericUpDown intervalInput,
            Label timeoutLabel,
            NumericUpDown timeoutInput,
            Label searchLabel,
            TextBox searchText,
            Label typeLabel,
            ComboBox typeFilter,
            Label subcenterLabel,
            ComboBox subcenterFilter,
            Label statusLabel,
            ComboBox statusFilter,
            UserMenuButton accountButton)
        {
            int width = Math.Max(1, filters.ClientSize.Width);
            ArrangeUserMenuButton(accountButton, filters, 6);
            int accountLeft = accountButton == null ? width - 18 : accountButton.Left;
            float desiredHeight = width < 1540 ? 92F : 56F;
            if (_monitorFilterRowStyle != null && Math.Abs(_monitorFilterRowStyle.Height - desiredHeight) > 0.5F)
            {
                _monitorFilterRowStyle.Height = desiredHeight;
                if (filters.Parent != null)
                {
                    filters.Parent.PerformLayout();
                }
            }

            if (width < 1540)
            {
                int y1 = 14;
                int y2 = 52;
                intervalLabel.SetBounds(18, y1 + 4, 92, 20);
                intervalInput.SetBounds(113, y1, 70, 24);
                timeoutLabel.SetBounds(206, y1 + 4, 76, 20);
                timeoutInput.SetBounds(286, y1, 80, 24);
                searchLabel.SetBounds(392, y1 + 4, 45, 20);
                searchText.SetBounds(440, y1, Math.Max(160, Math.Min(340, accountLeft - 458)), 24);

                typeLabel.SetBounds(18, y2 + 4, 34, 20);
                typeFilter.SetBounds(58, y2, 154, 24);
                subcenterLabel.SetBounds(238, y2 + 4, 112, 20);
                subcenterFilter.SetBounds(354, y2, Math.Max(130, Math.Min(180, width - 700)), 24);
                statusLabel.SetBounds(560, y2 + 4, 52, 20);
                statusFilter.SetBounds(616, y2, 145, 24);
            }
            else
            {
                int y = 14;
                intervalLabel.SetBounds(18, y + 4, 92, 20);
                intervalInput.SetBounds(113, y, 70, 24);
                timeoutLabel.SetBounds(202, y + 4, 76, 20);
                timeoutInput.SetBounds(282, y, 80, 24);
                searchLabel.SetBounds(388, y + 4, 45, 20);
                searchText.SetBounds(435, y, 240, 24);
                typeLabel.SetBounds(695, y + 4, 34, 20);
                typeFilter.SetBounds(730, y, 150, 24);
                subcenterLabel.SetBounds(900, y + 4, 112, 20);
                subcenterFilter.SetBounds(1016, y, 130, 24);
                statusLabel.SetBounds(1164, y + 4, 52, 20);
                statusFilter.SetBounds(1220, y, 135, 24);
            }
        }

        private void ArrangeDashboardHeader(
            Control header,
            Control logo,
            Label title,
            Label summary,
            Label groupLabel,
            ComboBox groupFilter,
            Label technologyLabel,
            ComboBox technologyFilter,
            Label subcenterLabel,
            ComboBox subcenterFilter,
            Label affiliationLabel,
            ComboBox affiliationFilter,
            Label searchLabel,
            TextBox searchText,
            FlowLayoutPanel actions,
            FlowLayoutPanel kpis,
            UserMenuButton accountButton)
        {
            int width = Math.Max(1, header.ClientSize.Width);
            bool stackTopControls = width < 1180;
            float desiredHeight = width < 920 ? 368F : stackTopControls ? 346F : width < 1380 ? 306F : 276F;
            if (_dashboardHeaderRowStyle != null && Math.Abs(_dashboardHeaderRowStyle.Height - desiredHeight) > 0.5F)
            {
                _dashboardHeaderRowStyle.Height = desiredHeight;
                if (header.Parent != null)
                {
                    header.Parent.PerformLayout();
                }
            }

            int logoWidth = width < 1100 ? 280 : width < 1500 ? 350 : 430;
            int logoHeight = Math.Max(76, (int)Math.Round(logoWidth / 4.2F));
            logo.SetBounds(18, 18, logoWidth, logoHeight);
            ArrangeUserMenuButton(accountButton, header, 6);

            actions.Width = stackTopControls ? Math.Max(300, width - 36) : 430;
            actions.Height = 72;
            int accountLeft = accountButton == null ? width - 18 : accountButton.Left;

            int textX = logo.Right + 28;
            int textRight = stackTopControls ? accountLeft - 24 : accountLeft - actions.Width - 40;
            int textWidth = Math.Max(220, textRight - textX);
            title.SetBounds(textX, 22, textWidth, 32);
            summary.SetBounds(textX, 64, textWidth, 24);

            if (stackTopControls)
            {
                actions.SetBounds(18, 118, actions.Width, 44);
            }
            else
            {
                actions.SetBounds(Math.Max(18, accountLeft - actions.Width - 16), 24, actions.Width, 72);
            }

            if (width < 1380)
            {
                int y1 = stackTopControls ? 178 : 132;
                int y2 = stackTopControls ? 212 : 166;
                groupLabel.SetBounds(18, y1 + 4, 55, 22);
                groupFilter.SetBounds(76, y1, 126, 24);
                technologyLabel.SetBounds(220, y1 + 4, 72, 22);
                technologyFilter.SetBounds(296, y1, 150, 24);
                subcenterLabel.SetBounds(464, y1 + 4, 112, 22);
                subcenterFilter.SetBounds(580, y1, 132, 24);
                affiliationLabel.SetBounds(18, y2 + 4, 68, 22);
                affiliationFilter.SetBounds(92, y2, 132, 24);
                searchLabel.SetBounds(244, y2 + 4, 118, 22);
                searchText.SetBounds(378, y2, Math.Min(260, width - 406), 24);
                kpis.SetBounds(18, stackTopControls ? 258 : 212, Math.Max(260, width - 36), 76);
            }
            else
            {
                int y = 134;
                groupLabel.SetBounds(18, y + 4, 55, 22);
                groupFilter.SetBounds(76, y, 126, 24);
                technologyLabel.SetBounds(226, y + 4, 72, 22);
                technologyFilter.SetBounds(304, y, 150, 24);
                subcenterLabel.SetBounds(478, y + 4, 112, 22);
                subcenterFilter.SetBounds(594, y, 135, 24);
                affiliationLabel.SetBounds(748, y + 4, 68, 22);
                affiliationFilter.SetBounds(822, y, 135, 24);
                searchLabel.SetBounds(978, y + 4, 118, 22);
                searchText.SetBounds(1112, y, Math.Max(80, Math.Min(190, width - 1344)), 24);
                kpis.SetBounds(18, 178, Math.Max(260, width - 36), 76);
            }
        }

        private void ArrangeDashboardCanvas()
        {
            if (_dashboardScrollPanel == null || _dashboardView == null)
            {
                return;
            }

            int visibleRows = CountDashboardVisualRows(_currentDashboardStats);
            int subcenterRows = CountDashboardVisualRows(_currentDashboardSubcenterStats);
            int minWidth = 1120;
            int availabilityHeight = 170 + (Math.Max(visibleRows, 8) * 54);
            int subcenterHeight = 520 + (Math.Max(subcenterRows, 8) * 48);
            int minHeight = Math.Max(720, Math.Max(availabilityHeight, subcenterHeight));
            int width = Math.Max(minWidth, _dashboardScrollPanel.ClientSize.Width);
            int height = Math.Max(minHeight, _dashboardScrollPanel.ClientSize.Height);

            _dashboardScrollPanel.AutoScrollMinSize = new Size(width, height);
            _dashboardView.SetBounds(0, 0, width, height);
        }

        private int CountDashboardVisualRows(List<DashboardStats> stats)
        {
            if (stats == null)
            {
                return 0;
            }

            int count = 0;
            for (int i = 0; i < stats.Count; i++)
            {
                DashboardStats stat = stats[i];
                if (stat != null && (stat.Devices > 0 || stat.Samples > 0))
                {
                    count++;
                }
            }

            return count;
        }

        private Button MakeButton(string text)
        {
            MaterialButton button = new MaterialButton();
            button.Text = text;
            button.AutoSize = false;
            button.Width = text.Length > 12 ? 112 : 92;
            button.Height = 30;
            button.Margin = new Padding(3, 2, 3, 4);
            button.BackColor = SurfaceSoft;
            button.ForeColor = TextMain;
            return button;
        }

        private void AddTextColumn(string property, string header, int width, bool readOnly)
        {
            DataGridViewTextBoxColumn column = new DataGridViewTextBoxColumn();
            column.DataPropertyName = property;
            column.HeaderText = header;
            column.Name = property;
            column.Width = width;
            column.MinimumWidth = Math.Min(width, 70);
            column.FillWeight = width;
            column.ReadOnly = readOnly;
            column.SortMode = DataGridViewColumnSortMode.Automatic;
            _grid.Columns.Add(column);
        }

        private void TabsDrawItem(object sender, DrawItemEventArgs e)
        {
            if (e.Index < 0 || e.Index >= _tabs.TabPages.Count)
            {
                return;
            }

            bool selected = e.Index == _tabs.SelectedIndex;
            Rectangle bounds = e.Bounds;
            Color back = selected ? SurfaceAlt : Color.FromArgb(2, 6, 23);
            Color fore = selected ? TextMain : TextMuted;

            using (Brush brush = new SolidBrush(back))
            {
                e.Graphics.FillRectangle(brush, bounds);
            }

            if (selected)
            {
                using (Pen pen = new Pen(Accent, 3F))
                {
                    e.Graphics.DrawLine(pen, bounds.Left + 8, bounds.Bottom - 2, bounds.Right - 8, bounds.Bottom - 2);
                }
            }

            TextRenderer.DrawText(
                e.Graphics,
                _tabs.TabPages[e.Index].Text,
                new Font("Segoe UI Semibold", 9F, FontStyle.Bold),
                bounds,
                fore,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
        }

        private void WireEvents()
        {
            _tabs.DrawItem += TabsDrawItem;
            _timer.Tick += delegate { RunPingSweep(); };

            _removeButton.Click += delegate { OpenDeviceManagement(); };
            _checkNowButton.Click += delegate { RunPingSweep(); };
            _startButton.Click += delegate { StartMonitoring(); };
            _stopButton.Click += delegate { StopMonitoring(); };
            _saveButton.Click += delegate
            {
                CommitGridEdits();
                SaveDevices();
                SetStatus(T("Cambios guardados.", "Changes saved."));
            };
            _exportButton.Click += delegate { ExportCsv(); };
            _resetFailuresButton.Click += delegate { ResetFailures(); };
            _resetHistoryButton.Click += delegate { ClearHistory(); };
            _refreshDashboardButton.Click += delegate
            {
                UpdateDashboard();
                SetStatus(T("Dashboard actualizado.", "Dashboard refreshed."));
            };
            _downloadDashboardReportButton.Click += delegate { ExportDashboardReport(); };
            _clearHistoryButton.Click += delegate { ClearHistory(); };
            _dashboardGroupFilter.SelectedIndexChanged += delegate { if (!_suppressDashboardFilterEvents) UpdateDashboard(); };
            _dashboardTechnologyFilter.SelectedIndexChanged += delegate { if (!_suppressDashboardFilterEvents) UpdateDashboard(); };
            _dashboardSubcenterFilter.SelectedIndexChanged += delegate { if (!_suppressDashboardFilterEvents) UpdateDashboard(); };
            _dashboardSubcenterFilter.TextChanged += delegate { if (!_suppressDashboardFilterEvents) UpdateDashboard(); };
            _dashboardAffiliationFilter.SelectedIndexChanged += delegate { if (!_suppressDashboardFilterEvents) UpdateDashboard(); };
            _dashboardAffiliationFilter.TextChanged += delegate { if (!_suppressDashboardFilterEvents) UpdateDashboard(); };
            _dashboardSearchText.TextChanged += delegate { if (!_suppressDashboardFilterEvents) UpdateDashboard(); };

            _filterText.TextChanged += delegate { if (!_suppressMonitorFilterEvents) ApplyFilter(); };
            _typeFilter.SelectedIndexChanged += delegate { if (!_suppressMonitorFilterEvents) ApplyFilter(); };
            _monitorSubcenterFilter.SelectedIndexChanged += delegate { if (!_suppressMonitorFilterEvents) ApplyFilter(); };
            _monitorSubcenterFilter.TextChanged += delegate { if (!_suppressMonitorFilterEvents) ApplyFilter(); };
            _monitorStatusFilter.SelectedIndexChanged += delegate { if (!_suppressMonitorFilterEvents) ApplyFilter(); };

            _grid.CellFormatting += GridCellFormatting;
            _grid.CellValueChanged += delegate { UpdateSummary(false); };
            _grid.UserDeletedRow += delegate { UpdateSummary(); };
            _grid.DataError += delegate(object sender, DataGridViewDataErrorEventArgs e)
            {
                e.ThrowException = false;
                SetStatus(T("Revise el valor capturado en la tabla.", "Check the value entered in the table."));
            };

            if (_dashboardGrid != null)
            {
                _dashboardGrid.CellPainting += DashboardCellPainting;
                _dashboardGrid.CellFormatting += DashboardCellFormatting;
            }

            _tabs.SelectedIndexChanged += delegate
            {
                if (_tabs.SelectedTab == _dashboardPage)
                {
                    RefreshDashboardFilters();
                    UpdateDashboard();
                }
            };
        }

        private void CommitGridEdits()
        {
            if (_grid != null)
            {
                try
                {
                    if (_grid.IsCurrentCellDirty)
                    {
                        _grid.CommitEdit(DataGridViewDataErrorContexts.Commit);
                    }

                    _grid.EndEdit();
                }
                catch
                {
                    // A pending invalid edit is handled by the grid validation path.
                }
            }

            if (_source != null)
            {
                try
                {
                    _source.EndEdit();
                }
                catch
                {
                }
            }
        }

        private void OpenUserManagement()
        {
            if (!UserStore.IsAdministrator(_signedInRole))
            {
                MessageBox.Show(
                    "Solo el rol Administrador puede gestionar usuarios.",
                    "Control de usuarios",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            using (UserManagementDialog dialog = new UserManagementDialog(_userStore, _signedInUser, _signedInRole, IsEnglishUi()))
            {
                dialog.ShowDialog(this);
                if (!String.Equals(dialog.CurrentUsername, _signedInUser, StringComparison.OrdinalIgnoreCase)
                    || !String.Equals(dialog.CurrentRole, _signedInRole, StringComparison.OrdinalIgnoreCase))
                {
                    SetSignedInUser(dialog.CurrentUsername, dialog.CurrentRole);
                    ApplyLocalization(false);
                    ApplyRolePermissions();
                }
            }

            SetStatus(T("Control de usuarios actualizado.", "User management updated."));
        }

        private void OpenAccountSettings()
        {
            using (AccountSettingsDialog dialog = new AccountSettingsDialog(_userStore, _signedInUser, _signedInRole))
            {
                dialog.SettingsSaved += delegate
                {
                    _signedInProfile = dialog.Profile;
                    ApplyUserPreferences();
                    ApplyLocalization(true);
                    UpdateUserMenuButtons();
                    UpdateDashboard();
                };
                dialog.ShowDialog(this);
                _signedInProfile = _userStore.GetUserProfile(_signedInUser);
                ApplyUserPreferences();
                ApplyLocalization(true);
                UpdateUserMenuButtons();
                UpdateDashboard();
            }

            SetStatus(T("Configuracion de cuenta actualizada.", "Account settings updated."));
        }

        private void SignOut()
        {
            DialogResult result = MessageBox.Show(
                T("Desea cerrar la sesion actual?", "Do you want to sign out of the current session?"),
                T("Cerrar sesion", "Sign out"),
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);
            if (result != DialogResult.Yes)
            {
                return;
            }

            try
            {
                _timer.Stop();
                SaveDevices();
            }
            catch
            {
                // The close path already protects against save failures.
            }

            LogoutRequested = true;
            Close();
        }

        private void AddDevice()
        {
            using (DeviceEditorDialog dialog = new DeviceEditorDialog(
                BuildTechnologyFilterValues(),
                BuildSubcenterFilterValues(),
                BuildAffiliationFilterValues(),
                IsEnglishUi()))
            {
                if (dialog.ShowDialog(this) != DialogResult.OK)
                {
                    return;
                }

                DeviceRecord record = dialog.Device;
                if (record == null)
                {
                    return;
                }

                record.Name = String.IsNullOrWhiteSpace(record.Name) ? record.Ip : record.Name.Trim();
                record.Ip = record.Ip.Trim();
                record.Type = NormalizeType(record.Type);
                record.Subcenter = NormalizeSubcenter(record.Subcenter);
                record.Affiliation = NormalizeAffiliation(record.Affiliation, record.Name);
                record.Notes = NormalizeTechnologyLabel(record.Notes);
                record.Status = String.IsNullOrWhiteSpace(record.Status) ? "Pendiente" : record.Status.Trim();
                record.Latency = "";
                record.LastCheck = "";
                record.Failures = Math.Max(0, record.Failures);

                if (FindDeviceByIp(record.Ip) != null)
                {
                    MessageBox.Show(
                        T("Ya existe un dispositivo registrado con la IP ", "A device is already registered with IP ") + record.Ip + ".",
                        T("Agregar dispositivo", "Add device"),
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                    return;
                }

                _devices.Add(record);
                ApplyFilter();
                UpdateSummary();
                SaveDevices();

                int rowIndex = _source.IndexOf(record);
                if (rowIndex >= 0)
                {
                    _grid.ClearSelection();
                    _grid.Rows[rowIndex].Selected = true;
                    _grid.CurrentCell = _grid.Rows[rowIndex].Cells["Name"];
                }

                SetStatus(T("Dispositivo agregado: ", "Device added: ") + record.Name + " (" + record.Ip + ").");
            }
        }

        private void RemoveSelectedDevices()
        {
            if (_grid.SelectedRows.Count == 0)
            {
                SetStatus(T("Seleccione uno o mas dispositivos para quitar.", "Select one or more devices to remove."));
                return;
            }

            DialogResult result = MessageBox.Show(
                T("Desea quitar los dispositivos seleccionados?", "Do you want to remove the selected devices?"),
                T("Confirmar", "Confirm"),
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (result != DialogResult.Yes)
            {
                return;
            }

            List<DeviceRecord> selected = new List<DeviceRecord>();
            foreach (DataGridViewRow row in _grid.SelectedRows)
            {
                DeviceRecord record = row.DataBoundItem as DeviceRecord;
                if (record != null)
                {
                    selected.Add(record);
                }
            }

            for (int i = 0; i < selected.Count; i++)
            {
                _devices.Remove(selected[i]);
            }

            ApplyFilter();
            UpdateSummary();
            SetStatus(T("Dispositivos quitados: ", "Devices removed: ") + selected.Count.ToString(CultureInfo.InvariantCulture));
        }

        private void OpenDeviceManagement()
        {
            using (DeviceManagementDialog dialog = new DeviceManagementDialog(
                _devices,
                BuildTechnologyFilterValues(),
                BuildSubcenterFilterValues(),
                BuildAffiliationFilterValues(),
                IsEnglishUi(),
                UserStore.IsAdministrator(_signedInRole)))
            {
                dialog.AddDeviceRequested = TryAddManagedDevice;
                dialog.EditDeviceRequested = TryEditManagedDevice;
                dialog.DeleteDeviceRequested = TryDeleteManagedDevice;
                dialog.ImportDevicesRequested = delegate { return ImportDevices(dialog); };
                dialog.DeleteAllDevicesRequested = ClearAllDevices;
                dialog.ShowDialog(this);
            }
        }

        private bool TryAddManagedDevice(DeviceRecord record)
        {
            if (record == null)
            {
                return false;
            }

            NormalizeNewDevice(record);
            if (FindDeviceByIp(record.Ip) != null)
            {
                MessageBox.Show(
                    T("Ya existe un dispositivo registrado con la IP ", "A device is already registered with IP ") + record.Ip + ".",
                    T("Gestionar dispositivos", "Manage devices"),
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return false;
            }

            _devices.Add(record);
            ApplyFilter();
            UpdateSummary();
            SaveDevices();
            SetStatus(T("Dispositivo agregado: ", "Device added: ") + record.Name + " (" + record.Ip + ").");
            return true;
        }

        private bool TryEditManagedDevice(DeviceRecord target, DeviceRecord updated)
        {
            if (target == null || updated == null)
            {
                return false;
            }

            NormalizeEditedDevice(updated, target);
            DeviceRecord duplicate = FindDeviceByIp(updated.Ip);
            if (duplicate != null && !Object.ReferenceEquals(duplicate, target))
            {
                MessageBox.Show(
                    T("Ya existe otro dispositivo registrado con la IP ", "Another device is already registered with IP ") + updated.Ip + ".",
                    T("Gestionar dispositivos", "Manage devices"),
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return false;
            }

            target.Name = updated.Name;
            target.Ip = updated.Ip;
            target.Type = updated.Type;
            target.Subcenter = updated.Subcenter;
            target.Affiliation = updated.Affiliation;
            target.Notes = updated.Notes;
            ApplyFilter();
            UpdateSummary();
            SaveDevices();
            SetStatus(T("Cambios guardados.", "Changes saved."));
            return true;
        }

        private bool TryDeleteManagedDevice(DeviceRecord target)
        {
            if (target == null)
            {
                return false;
            }

            string name = String.IsNullOrWhiteSpace(target.Name) ? target.Ip : target.Name;
            if (!_devices.Remove(target))
            {
                return false;
            }

            ApplyFilter();
            UpdateSummary();
            SaveDevices();
            SetStatus(T("Dispositivo eliminado: ", "Device deleted: ") + name + ".");
            return true;
        }

        private void NormalizeNewDevice(DeviceRecord record)
        {
            if (record == null)
            {
                return;
            }

            record.Name = String.IsNullOrWhiteSpace(record.Name) ? record.Ip : record.Name.Trim();
            record.Ip = record.Ip == null ? "" : record.Ip.Trim();
            record.Type = NormalizeType(record.Type);
            record.Subcenter = NormalizeSubcenter(record.Subcenter);
            record.Affiliation = NormalizeAffiliation(record.Affiliation, record.Name);
            record.Notes = NormalizeTechnologyLabel(record.Notes);
            record.Status = String.IsNullOrWhiteSpace(record.Status) ? "Pendiente" : record.Status.Trim();
            record.Latency = "";
            record.LastCheck = "";
            record.Failures = Math.Max(0, record.Failures);
        }

        private void NormalizeEditedDevice(DeviceRecord record, DeviceRecord current)
        {
            NormalizeNewDevice(record);
            if (current != null)
            {
                record.Status = String.IsNullOrWhiteSpace(current.Status) ? "Pendiente" : current.Status;
                record.Latency = current.Latency == null ? "" : current.Latency;
                record.LastCheck = current.LastCheck == null ? "" : current.LastCheck;
                record.Failures = Math.Max(0, current.Failures);
            }
        }

        private bool ClearAllDevices()
        {
            if (_devices.Count == 0)
            {
                SetStatus(T("No hay camaras registradas para eliminar.", "There are no cameras registered to delete."));
                return false;
            }

            if (_sweepRunning)
            {
                MessageBox.Show(
                    T("Hay una revision en proceso. Espere a que termine antes de eliminar el inventario.", "A check is in progress. Wait until it finishes before deleting the inventory."),
                    T("Eliminar inventario", "Delete inventory"),
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return false;
            }

            DialogResult result = MessageBox.Show(
                T("Desea eliminar todas las camaras registradas?\r\n\r\nEsto dejara vacio el inventario para cargar una nueva lista.", "Do you want to delete all registered cameras?\r\n\r\nThis will empty the inventory so a new list can be loaded."),
                T("Eliminar todas las camaras", "Delete all cameras"),
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);

            if (result != DialogResult.Yes)
            {
                return false;
            }

            _timer.Stop();
            _devices.Clear();
            _visibleDevices.Clear();
            SaveDevices();
            RefreshMonitorFilters();
            ApplyFilter();
            UpdateSummary();
            UpdateDashboard();
            _lastRunLabel.Text = T("Sin revision", "No check yet");
            SetStatus(T("Inventario eliminado. Puede importar una nueva lista.", "Inventory deleted. You can import a new list."));
            return true;
        }

        private void StartMonitoring()
        {
            _timer.Interval = Decimal.ToInt32(_intervalInput.Value) * 1000;
            _timer.Start();
            SetStatus(T("Monitoreo iniciado. Revision cada ", "Monitoring started. Check every ") + Decimal.ToInt32(_intervalInput.Value).ToString(CultureInfo.InvariantCulture) + T(" segundos.", " seconds."));
            RunPingSweep();
        }

        private void StopMonitoring()
        {
            _timer.Stop();
            SetStatus(T("Monitoreo detenido.", "Monitoring stopped."));
        }

        private void RunPingSweep()
        {
            if (_sweepRunning)
            {
                SetStatus(T("Revision anterior aun en proceso.", "Previous check still in progress."));
                return;
            }

            List<DeviceRecord> targets = new List<DeviceRecord>();
            for (int i = 0; i < _devices.Count; i++)
            {
                if (!String.IsNullOrWhiteSpace(_devices[i].Ip))
                {
                    targets.Add(_devices[i]);
                }
            }

            if (targets.Count == 0)
            {
                SetStatus(T("No hay IPs para revisar.", "There are no IPs to check."));
                return;
            }

            _sweepRunning = true;
            _activeTasks = targets.Count;
            _lastSweepStarted = DateTime.Now;
            _lastRunLabel.Text = T("Revision iniciada: ", "Check started: ") + _lastSweepStarted.ToString("yyyy-MM-dd HH:mm:ss");
            EnsureHistoryResetCycle();
            SetStatus(T("Revisando ", "Checking ") + targets.Count.ToString(CultureInfo.InvariantCulture) + T(" dispositivos con concurrencia optimizada...", " devices with optimized concurrency..."));

            int timeout = Decimal.ToInt32(_timeoutInput.Value);
            int workerCount = Math.Min(targets.Count, MaxConcurrentPings);
            int nextIndex = -1;
            for (int i = 0; i < workerCount; i++)
            {
                Task.Factory.StartNew(delegate
                {
                    while (true)
                    {
                        int index = Interlocked.Increment(ref nextIndex);
                        if (index >= targets.Count)
                        {
                            break;
                        }

                        PingJob job = new PingJob();
                        job.Record = targets[index];
                        job.Timeout = timeout;
                        PingDevice(job);
                    }
                });
            }
        }

        private void PingDevice(object state)
        {
            PingJob job = state as PingJob;
            if (job == null || job.Record == null)
            {
                FinishPingTask();
                return;
            }

            PingResult result = new PingResult();
            result.Record = job.Record;
            result.CheckedAt = DateTime.Now;

            try
            {
                using (Ping ping = new Ping())
                {
                    PingReply reply = ping.Send(job.Record.Ip.Trim(), job.Timeout);
                    if (reply != null && reply.Status == IPStatus.Success)
                    {
                        result.Status = "En linea";
                        result.Latency = reply.RoundtripTime.ToString(CultureInfo.InvariantCulture) + " ms";
                        result.Success = true;
                    }
                    else
                    {
                        result.Status = "Sin respuesta";
                        result.Latency = "";
                        result.Success = false;
                    }
                }
            }
            catch (Exception ex)
            {
                result.Status = "Error";
                result.Latency = "";
                result.Success = false;
                result.ErrorText = ex.Message;
            }

            if (!IsDisposed && IsHandleCreated)
            {
                QueuePingResult(result);
            }
            else
            {
                FinishPingTask();
            }
        }

        private void QueuePingResult(PingResult result)
        {
            bool scheduleDrain = false;
            lock (_pendingResultLock)
            {
                _pendingResults.Add(result);
                if (!_resultDrainScheduled)
                {
                    _resultDrainScheduled = true;
                    scheduleDrain = true;
                }
            }

            if (scheduleDrain)
            {
                try
                {
                    BeginInvoke(new Action(DrainPingResults));
                }
                catch
                {
                    lock (_pendingResultLock)
                    {
                        _pendingResults.Remove(result);
                        if (_pendingResults.Count == 0)
                        {
                            _resultDrainScheduled = false;
                        }
                    }
                    FinishPingTask();
                }
            }
        }

        private void DrainPingResults()
        {
            List<PingResult> results;
            lock (_pendingResultLock)
            {
                results = new List<PingResult>(_pendingResults);
                _pendingResults.Clear();
                _resultDrainScheduled = false;
            }

            if (results.Count == 0)
            {
                return;
            }

            List<PingHistoryEntry> newEntries = new List<PingHistoryEntry>();
            bool oldRaiseEvents = _source.RaiseListChangedEvents;
            _source.RaiseListChangedEvents = false;
            _grid.SuspendLayout();
            try
            {
                for (int i = 0; i < results.Count; i++)
                {
                    PingHistoryEntry entry = ApplyPingResultCore(results[i]);
                    if (entry != null)
                    {
                        _history.Add(entry);
                        newEntries.Add(entry);
                    }
                }
            }
            finally
            {
                _grid.ResumeLayout();
                _source.RaiseListChangedEvents = oldRaiseEvents;
                _source.ResetBindings(false);
            }

            try
            {
                AppendHistoryEntries(newEntries);
            }
            catch (Exception ex)
            {
                SetStatus("No se pudo guardar el historial: " + ex.Message);
            }
            _grid.Invalidate();

            for (int i = 0; i < results.Count; i++)
            {
                FinishPingTask();
            }
        }

        private PingHistoryEntry ApplyPingResultCore(PingResult result)
        {
            result.Record.Status = result.Status;
            result.Record.Latency = result.Latency;
            result.Record.LastCheck = result.CheckedAt.ToString("yyyy-MM-dd HH:mm:ss");
            if (!result.Success)
            {
                result.Record.Failures = result.Record.Failures + 1;
                if (!String.IsNullOrWhiteSpace(result.ErrorText))
                {
                    SetStatus("Error en " + result.Record.Ip + ": " + result.ErrorText);
                }
            }

            return CreateHistoryEntry(result);
        }

        private void FinishPingTask()
        {
            int left = Interlocked.Decrement(ref _activeTasks);
            if (left <= 0)
            {
                _sweepRunning = false;
                if (!IsDisposed && IsHandleCreated)
                {
                    try
                    {
                        BeginInvoke(new Action(delegate
                        {
                            EnsureHistoryResetCycle();
                            if (PruneHistory())
                            {
                                SaveHistory();
                            }

                            UpdateSummary();
                            if (HasActiveMonitorFilter())
                            {
                                ApplyFilter();
                            }
                            _lastRunLabel.Text = T("Ultima revision: ", "Last check: ") + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                            SetStatus(T("Revision completada.", "Check completed."));
                        }));
                    }
                    catch
                    {
                    }
                }
            }
        }

        private void GridCellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            if (e.RowIndex < 0 || e.RowIndex >= _grid.Rows.Count)
            {
                return;
            }

            DataGridViewRow row = _grid.Rows[e.RowIndex];
            DeviceRecord record = row.DataBoundItem as DeviceRecord;
            if (record == null)
            {
                return;
            }

            Color back = e.RowIndex % 2 == 0 ? Surface : SurfaceAlt;
            Color fore = TextMain;
            if (record.Status == "En linea")
            {
                back = SuccessBack;
                fore = Color.FromArgb(209, 250, 229);
            }
            else if (record.Status == "Sin respuesta")
            {
                back = DangerBack;
                fore = Color.FromArgb(254, 226, 226);
            }
            else if (record.Status == "Error")
            {
                back = WarningBack;
                fore = Color.FromArgb(254, 243, 199);
            }

            if (_grid.Columns[e.ColumnIndex].Name == "Status")
            {
                e.Value = UiText.Status(record.Status, IsEnglishUi());
                e.FormattingApplied = true;
            }

            row.DefaultCellStyle.BackColor = back;
            row.DefaultCellStyle.ForeColor = fore;
            row.DefaultCellStyle.SelectionBackColor = Color.FromArgb(14, 116, 144);
            row.DefaultCellStyle.SelectionForeColor = Color.White;
        }

        private bool ImportDevices()
        {
            return ImportDevices(this);
        }

        private bool ImportDevices(IWin32Window owner)
        {
            IWin32Window dialogOwner = owner == null ? (IWin32Window)this : owner;
            using (OpenFileDialog dialog = new OpenFileDialog())
            {
                dialog.Title = "Importar listado";
                dialog.Filter = "Listados (*.csv;*.txt;*.tsv;*.xlsx)|*.csv;*.txt;*.tsv;*.xlsx|Todos los archivos (*.*)|*.*";
                if (dialog.ShowDialog(dialogOwner) != DialogResult.OK)
                {
                    return false;
                }

                try
                {
                    List<DeviceRecord> imported = ImportFile(dialog.FileName);
                    if (imported.Count == 0)
                    {
                        MessageBox.Show(
                            dialogOwner,
                            "No se encontraron registros validos. Revise que exista una columna IP.",
                            "Importar",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information);
                        return false;
                    }

                    bool replace = true;
                    if (_devices.Count > 0)
                    {
                        DialogResult choice = MessageBox.Show(
                            dialogOwner,
                            "Desea reemplazar el listado actual?\r\n\r\nSi = reemplazar\r\nNo = agregar al listado existente",
                            "Importar listado",
                            MessageBoxButtons.YesNoCancel,
                            MessageBoxIcon.Question);
                        if (choice == DialogResult.Cancel)
                        {
                            return false;
                        }

                        replace = choice == DialogResult.Yes;
                    }

                    if (replace)
                    {
                        _devices.Clear();
                    }

                    for (int i = 0; i < imported.Count; i++)
                    {
                        _devices.Add(imported[i]);
                    }

                    ApplyFilter();
                    UpdateSummary();
                    SaveDevices();
                    StartMonitoring();
                    SetStatus("Importados: " + imported.Count.ToString(CultureInfo.InvariantCulture) + ". Monitoreo horario activo.");
                    return true;
                }
                catch (Exception ex)
                {
                    MessageBox.Show(
                        dialogOwner,
                        "No se pudo importar el archivo:\r\n" + ex.Message,
                        "Importar",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                    return false;
                }
            }
        }

        private List<DeviceRecord> ImportFile(string path)
        {
            string ext = Path.GetExtension(path).ToLowerInvariant();
            List<List<string>> rows;
            if (ext == ".xlsx")
            {
                rows = ReadXlsx(path);
            }
            else
            {
                rows = ReadDelimited(path);
            }

            return ConvertRowsToDevices(rows);
        }

        private List<List<string>> ReadDelimited(string path)
        {
            string[] lines = File.ReadAllLines(path, Encoding.Default);
            char delimiter = DetectDelimiter(lines, path);
            List<List<string>> rows = new List<List<string>>();
            for (int i = 0; i < lines.Length; i++)
            {
                if (!String.IsNullOrWhiteSpace(lines[i]))
                {
                    rows.Add(ParseDelimitedLine(lines[i], delimiter));
                }
            }

            return rows;
        }

        private char DetectDelimiter(string[] lines, string path)
        {
            string ext = Path.GetExtension(path).ToLowerInvariant();
            if (ext == ".tsv")
            {
                return '\t';
            }

            int comma = 0;
            int semicolon = 0;
            int tab = 0;
            int max = Math.Min(lines.Length, 5);
            for (int i = 0; i < max; i++)
            {
                comma += CountChar(lines[i], ',');
                semicolon += CountChar(lines[i], ';');
                tab += CountChar(lines[i], '\t');
            }

            if (tab > comma && tab > semicolon)
            {
                return '\t';
            }

            if (semicolon > comma)
            {
                return ';';
            }

            return ',';
        }

        private int CountChar(string text, char ch)
        {
            int count = 0;
            for (int i = 0; i < text.Length; i++)
            {
                if (text[i] == ch)
                {
                    count++;
                }
            }

            return count;
        }

        private List<string> ParseDelimitedLine(string line, char delimiter)
        {
            List<string> values = new List<string>();
            StringBuilder current = new StringBuilder();
            bool inQuotes = false;

            for (int i = 0; i < line.Length; i++)
            {
                char ch = line[i];
                if (ch == '"')
                {
                    if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                    {
                        current.Append('"');
                        i++;
                    }
                    else
                    {
                        inQuotes = !inQuotes;
                    }
                }
                else if (ch == delimiter && !inQuotes)
                {
                    values.Add(current.ToString().Trim());
                    current.Length = 0;
                }
                else
                {
                    current.Append(ch);
                }
            }

            values.Add(current.ToString().Trim());
            return values;
        }

        private List<DeviceRecord> ConvertRowsToDevices(List<List<string>> rows)
        {
            List<DeviceRecord> devices = new List<DeviceRecord>();
            if (rows == null || rows.Count == 0)
            {
                return devices;
            }

            List<string> header = rows[0];
            int ipIndex = FindHeader(header, new string[] { "ip", "direccionip", "direccion", "host", "address" });
            int nameIndex = FindHeader(header, new string[] { "nombre", "camara", "camera", "dispositivo", "equipo", "name" });
            int typeIndex = FindHeader(header, new string[] { "tipo", "type", "categoria", "clasificacion" });
            int subcenterIndex = FindHeader(header, new string[] { "ubicacion", "lugar", "sitio", "site", "location", "subcentro", "subcenter", "centro", "subcentros" });
            int affiliationIndex = FindHeader(header, new string[] { "afiliacion", "afiliation", "affiliation", "cliente", "dependencia", "municipio", "zona" });
            int notesIndex = FindHeader(header, new string[] { "tecnologia", "technology", "tech", "observaciones", "notas", "nota", "comentarios" });

            bool hasHeader = ipIndex >= 0 || nameIndex >= 0 || typeIndex >= 0;
            int startRow = hasHeader ? 1 : 0;

            if (!hasHeader)
            {
                ipIndex = 0;
                nameIndex = 1;
                typeIndex = 2;
                subcenterIndex = -1;
                affiliationIndex = -1;
                notesIndex = 3;
            }
            else if (ipIndex < 0)
            {
                ipIndex = 0;
            }

            for (int r = startRow; r < rows.Count; r++)
            {
                List<string> row = rows[r];
                string ip = GetCell(row, ipIndex).Trim();
                if (String.IsNullOrWhiteSpace(ip))
                {
                    continue;
                }

                DeviceRecord record = new DeviceRecord();
                record.Ip = ip;
                record.Name = GetCell(row, nameIndex).Trim();
                if (String.IsNullOrWhiteSpace(record.Name))
                {
                    record.Name = ip;
                }

                string type = NormalizeType(GetCell(row, typeIndex));
                record.Type = type;
                record.Subcenter = NormalizeSubcenter(GetCell(row, subcenterIndex));
                record.Affiliation = NormalizeAffiliation(GetCell(row, affiliationIndex), record.Name);
                record.Notes = NormalizeTechnologyLabel(GetCell(row, notesIndex));
                devices.Add(record);
            }

            return devices;
        }

        private string GetCell(List<string> row, int index)
        {
            if (row == null || index < 0 || index >= row.Count)
            {
                return "";
            }

            return row[index] == null ? "" : row[index];
        }

        private int FindHeader(List<string> header, string[] candidates)
        {
            if (header == null)
            {
                return -1;
            }

            for (int i = 0; i < header.Count; i++)
            {
                string normalized = NormalizeHeader(header[i]);
                for (int c = 0; c < candidates.Length; c++)
                {
                    if (normalized == candidates[c])
                    {
                        return i;
                    }
                }
            }

            return -1;
        }

        private string NormalizeHeader(string value)
        {
            string text = RemoveDiacritics(value == null ? "" : value).ToLowerInvariant();
            StringBuilder clean = new StringBuilder();
            for (int i = 0; i < text.Length; i++)
            {
                char ch = text[i];
                if (Char.IsLetterOrDigit(ch))
                {
                    clean.Append(ch);
                }
            }

            return clean.ToString();
        }

        private string NormalizeType(string value)
        {
            string text = value == null ? "" : value.Trim();
            if (String.IsNullOrWhiteSpace(text))
            {
                return "Fija";
            }

            string normalized = NormalizeHeader(text);
            for (int i = 0; i < DeviceTypes.Length; i++)
            {
                if (NormalizeHeader(DeviceTypes[i]) == normalized)
                {
                    return DeviceTypes[i];
                }
            }

            if (normalized == "pmi")
            {
                return "PMI";
            }

            if (normalized == "pmiresguardo" || normalized == "pmideresguardo" || normalized == "resguardo")
            {
                return "PMI Resguardo";
            }

            if (normalized == "lp1" || normalized == "lp01" || normalized == "lpr1" || normalized == "lpr01")
            {
                return "LP 01";
            }

            if (normalized == "lp2" || normalized == "lp02" || normalized == "lpr2" || normalized == "lpr02")
            {
                return "LP 02";
            }

            if (normalized == "arcos")
            {
                return "Arco";
            }

            if (normalized == "remolque" || normalized == "remolques")
            {
                return "Remolque";
            }

            return "Otro";
        }

        private string GetRecordTechnology(DeviceRecord record)
        {
            if (record == null)
            {
                return "Otro";
            }

            string technology = record.Notes == null ? "" : record.Notes.Trim();
            if (!String.IsNullOrWhiteSpace(technology))
            {
                return NormalizeTechnologyLabel(technology);
            }

            return NormalizeTechnology(record.Type);
        }

        private string GetRecordAffiliation(DeviceRecord record)
        {
            if (record == null)
            {
                return "Sin afiliacion";
            }

            return NormalizeAffiliation(record.Affiliation, record.Name);
        }

        private string GetRecordSubcenter(DeviceRecord record)
        {
            if (record == null)
            {
                return "Sin ubicacion";
            }

            return NormalizeSubcenter(record.Subcenter);
        }

        private string NormalizeSubcenter(string value)
        {
            string text = value == null ? "" : value.Trim();
            if (!String.IsNullOrWhiteSpace(text))
            {
                if (String.Equals(text, "Sin subcentro", StringComparison.OrdinalIgnoreCase)
                    || String.Equals(text, "No subcenter", StringComparison.OrdinalIgnoreCase))
                {
                    return "Sin ubicacion";
                }

                return text;
            }

            return "Sin ubicacion";
        }

        private string NormalizeAffiliation(string value, string deviceName)
        {
            string text = value == null ? "" : value.Trim();
            if (!String.IsNullOrWhiteSpace(text))
            {
                return text.ToUpperInvariant();
            }

            string name = deviceName == null ? "" : deviceName.Trim();
            string[] parts = name.Split(new char[] { '-' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2 && !String.IsNullOrWhiteSpace(parts[1]))
            {
                return parts[1].Trim().ToUpperInvariant();
            }

            return "Sin afiliacion";
        }

        private string NormalizeTechnology(string value)
        {
            string normalized = NormalizeHeader(value);
            if (String.IsNullOrWhiteSpace(normalized))
            {
                return "Otro";
            }

            if (normalized.Contains("remolque"))
            {
                return "Remolque";
            }

            if (normalized.Contains("radio"))
            {
                return "Radio";
            }

            if (normalized.Contains("switch"))
            {
                return "Switch";
            }

            if (normalized.Contains("arco"))
            {
                return "Arco";
            }

            if (normalized.Contains("lpr") || normalized.Contains("lp01") || normalized.Contains("lp02"))
            {
                return "LPR";
            }

            bool hasPmi = normalized.Contains("pmi");
            bool hasResguardo = normalized.Contains("resguardo");
            if ((hasPmi && hasResguardo) || normalized == "resguardo")
            {
                return "PMI de resguardo";
            }

            if (hasPmi)
            {
                return "PMI";
            }

            return "Otro";
        }

        private string NormalizeTechnologyLabel(string value)
        {
            string text = value == null ? "" : value.Trim();
            if (String.IsNullOrWhiteSpace(text))
            {
                return "";
            }

            string normalized = NormalizeTechnology(text);
            return normalized == "Otro" ? text : normalized;
        }

        private string RemoveDiacritics(string text)
        {
            string normalized = text.Normalize(NormalizationForm.FormD);
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < normalized.Length; i++)
            {
                UnicodeCategory category = CharUnicodeInfo.GetUnicodeCategory(normalized[i]);
                if (category != UnicodeCategory.NonSpacingMark)
                {
                    builder.Append(normalized[i]);
                }
            }

            return builder.ToString().Normalize(NormalizationForm.FormC);
        }

        private List<List<string>> ReadXlsx(string path)
        {
            List<List<string>> rows = new List<List<string>>();
            using (ZipArchive archive = ZipFile.OpenRead(path))
            {
                List<string> sharedStrings = LoadSharedStrings(archive);
                ZipArchiveEntry sheetEntry = GetFirstSheetEntry(archive);
                if (sheetEntry == null)
                {
                    throw new InvalidOperationException("No se encontro una hoja de calculo dentro del XLSX.");
                }

                XmlDocument doc = new XmlDocument();
                using (Stream stream = sheetEntry.Open())
                {
                    doc.Load(stream);
                }

                XmlNodeList rowNodes = doc.GetElementsByTagName("row", "*");
                foreach (XmlNode rowNode in rowNodes)
                {
                    Dictionary<int, string> cells = new Dictionary<int, string>();
                    int nextColumn = 0;
                    foreach (XmlNode cellNode in rowNode.ChildNodes)
                    {
                        if (cellNode.LocalName != "c")
                        {
                            continue;
                        }

                        int column = nextColumn;
                        XmlAttribute reference = cellNode.Attributes == null ? null : cellNode.Attributes["r"];
                        if (reference != null)
                        {
                            column = CellReferenceToColumn(reference.Value);
                        }

                        cells[column] = ReadXlsxCellValue(cellNode, sharedStrings);
                        nextColumn = column + 1;
                    }

                    if (cells.Count > 0)
                    {
                        int max = -1;
                        foreach (int index in cells.Keys)
                        {
                            if (index > max)
                            {
                                max = index;
                            }
                        }

                        List<string> values = new List<string>();
                        for (int i = 0; i <= max; i++)
                        {
                            string value;
                            values.Add(cells.TryGetValue(i, out value) ? value : "");
                        }

                        rows.Add(values);
                    }
                }
            }

            return rows;
        }

        private List<string> LoadSharedStrings(ZipArchive archive)
        {
            List<string> values = new List<string>();
            ZipArchiveEntry entry = archive.GetEntry("xl/sharedStrings.xml");
            if (entry == null)
            {
                return values;
            }

            XmlDocument doc = new XmlDocument();
            using (Stream stream = entry.Open())
            {
                doc.Load(stream);
            }

            XmlNodeList items = doc.GetElementsByTagName("si", "*");
            foreach (XmlNode item in items)
            {
                StringBuilder text = new StringBuilder();
                XmlNodeList textNodes = ((XmlElement)item).GetElementsByTagName("t", "*");
                foreach (XmlNode textNode in textNodes)
                {
                    text.Append(textNode.InnerText);
                }

                values.Add(text.ToString());
            }

            return values;
        }

        private ZipArchiveEntry GetFirstSheetEntry(ZipArchive archive)
        {
            ZipArchiveEntry workbook = archive.GetEntry("xl/workbook.xml");
            ZipArchiveEntry relationships = archive.GetEntry("xl/_rels/workbook.xml.rels");

            if (workbook != null && relationships != null)
            {
                XmlDocument workbookDoc = new XmlDocument();
                using (Stream stream = workbook.Open())
                {
                    workbookDoc.Load(stream);
                }

                XmlNodeList sheets = workbookDoc.GetElementsByTagName("sheet", "*");
                if (sheets.Count > 0)
                {
                    XmlAttribute relId = sheets[0].Attributes == null ? null : sheets[0].Attributes["r:id"];
                    if (relId != null)
                    {
                        XmlDocument relDoc = new XmlDocument();
                        using (Stream stream = relationships.Open())
                        {
                            relDoc.Load(stream);
                        }

                        XmlNodeList rels = relDoc.GetElementsByTagName("Relationship", "*");
                        foreach (XmlNode rel in rels)
                        {
                            XmlAttribute id = rel.Attributes == null ? null : rel.Attributes["Id"];
                            XmlAttribute target = rel.Attributes == null ? null : rel.Attributes["Target"];
                            if (id != null && target != null && id.Value == relId.Value)
                            {
                                string targetPath = target.Value.Replace("\\", "/");
                                if (targetPath.StartsWith("/", StringComparison.Ordinal))
                                {
                                    targetPath = targetPath.TrimStart('/');
                                }
                                else if (!targetPath.StartsWith("xl/", StringComparison.Ordinal))
                                {
                                    targetPath = "xl/" + targetPath;
                                }

                                ZipArchiveEntry entry = archive.GetEntry(targetPath);
                                if (entry != null)
                                {
                                    return entry;
                                }
                            }
                        }
                    }
                }
            }

            return archive.GetEntry("xl/worksheets/sheet1.xml");
        }

        private int CellReferenceToColumn(string reference)
        {
            int column = 0;
            for (int i = 0; i < reference.Length; i++)
            {
                char ch = reference[i];
                if (ch >= 'A' && ch <= 'Z')
                {
                    column = column * 26 + (ch - 'A' + 1);
                }
                else if (ch >= 'a' && ch <= 'z')
                {
                    column = column * 26 + (ch - 'a' + 1);
                }
                else
                {
                    break;
                }
            }

            return Math.Max(0, column - 1);
        }

        private string ReadXlsxCellValue(XmlNode cellNode, List<string> sharedStrings)
        {
            string type = "";
            XmlAttribute typeAttribute = cellNode.Attributes == null ? null : cellNode.Attributes["t"];
            if (typeAttribute != null)
            {
                type = typeAttribute.Value;
            }

            if (type == "inlineStr")
            {
                StringBuilder inline = new StringBuilder();
                XmlNodeList textNodes = ((XmlElement)cellNode).GetElementsByTagName("t", "*");
                foreach (XmlNode textNode in textNodes)
                {
                    inline.Append(textNode.InnerText);
                }

                return inline.ToString();
            }

            XmlNode valueNode = null;
            foreach (XmlNode child in cellNode.ChildNodes)
            {
                if (child.LocalName == "v")
                {
                    valueNode = child;
                    break;
                }
            }

            string raw = valueNode == null ? "" : valueNode.InnerText;
            if (type == "s")
            {
                int index;
                if (Int32.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out index))
                {
                    if (index >= 0 && index < sharedStrings.Count)
                    {
                        return sharedStrings[index];
                    }
                }
            }

            return raw;
        }

        private void ApplyFilter()
        {
            string text = _filterText.Text == null ? "" : _filterText.Text.Trim().ToLowerInvariant();
            string type = _typeFilter.SelectedItem == null ? T("Todos", "All") : _typeFilter.SelectedItem.ToString();
            string subcenter = GetComboText(_monitorSubcenterFilter, T("Todos", "All"));
            string status = _monitorStatusFilter.SelectedItem == null ? T("Todos", "All") : _monitorStatusFilter.SelectedItem.ToString();

            bool hasActiveFilter = !String.IsNullOrWhiteSpace(text)
                || !UiText.IsAll(type)
                || !UiText.IsAll(subcenter)
                || !UiText.IsAll(status);

            int matches = 0;
            int added = 0;
            bool hideUnfilteredLargeList = !hasActiveFilter && _devices.Count > MaxVisibleDeviceRows;

            _source.RaiseListChangedEvents = false;
            _visibleDevices.Clear();
            for (int i = 0; i < _devices.Count; i++)
            {
                DeviceRecord record = _devices[i];
                if (!MatchesMonitorFilters(record, text, type, subcenter, status))
                {
                    continue;
                }

                matches++;
                if (!hideUnfilteredLargeList && added < MaxVisibleDeviceRows)
                {
                    _visibleDevices.Add(record);
                    added++;
                }
            }

            _source.RaiseListChangedEvents = true;
            _source.ResetBindings(false);

            if (hideUnfilteredLargeList)
            {
                SetStatus(T("Vista optimizada: use Buscar o filtros para mostrar dispositivos. Total cargado: ", "Optimized view: use Search or filters to show devices. Total loaded: ") + _devices.Count.ToString(CultureInfo.InvariantCulture));
            }
            else if (matches > added)
            {
                SetStatus(T("Mostrando ", "Showing ") + added.ToString(CultureInfo.InvariantCulture) + T(" de ", " of ") + matches.ToString(CultureInfo.InvariantCulture) + T(" coincidencias. Refine la busqueda para ver menos resultados.", " matches. Refine the search to show fewer results."));
            }
            else
            {
                SetStatus(T("Mostrando ", "Showing ") + added.ToString(CultureInfo.InvariantCulture) + T(" dispositivos.", " devices."));
            }
        }

        private bool HasActiveMonitorFilter()
        {
            string text = _filterText == null || _filterText.Text == null ? "" : _filterText.Text.Trim();
            string type = _typeFilter == null || _typeFilter.SelectedItem == null ? T("Todos", "All") : _typeFilter.SelectedItem.ToString();
            string subcenter = GetComboText(_monitorSubcenterFilter, T("Todos", "All"));
            string status = _monitorStatusFilter == null || _monitorStatusFilter.SelectedItem == null ? T("Todos", "All") : _monitorStatusFilter.SelectedItem.ToString();

            return !String.IsNullOrWhiteSpace(text)
                || !UiText.IsAll(type)
                || !UiText.IsAll(subcenter)
                || !UiText.IsAll(status);
        }

        private bool MatchesMonitorFilters(DeviceRecord record, string text, string type, string subcenter, string status)
        {
            if (record == null)
            {
                return false;
            }

            bool matchesText = String.IsNullOrWhiteSpace(text)
                || Contains(record.Name, text)
                || Contains(record.Ip, text)
                || Contains(record.Type, text)
                || Contains(GetRecordTechnology(record), text)
                || Contains(GetRecordSubcenter(record), text)
                || Contains(GetRecordAffiliation(record), text)
                || Contains(record.Status, text)
                || Contains(record.Notes, text);

            string canonicalStatus = UiText.CanonicalStatus(status);
            bool matchesType = UiText.IsAll(type)
                || record.Type == type
                || TechnologyMatches(GetRecordTechnology(record), type);
            bool matchesSubcenter = UiText.IsAll(subcenter)
                || NormalizeHeader(GetRecordSubcenter(record)).Contains(NormalizeHeader(subcenter));
            bool matchesStatus = UiText.IsAll(status) || record.Status == canonicalStatus;
            return matchesText && matchesType && matchesSubcenter && matchesStatus;
        }

        private bool Contains(string value, string text)
        {
            return value != null && value.ToLowerInvariant().Contains(text);
        }

        private bool TechnologyMatches(string technology, string selectedTechnology)
        {
            if (String.Equals(selectedTechnology, "Todas", StringComparison.OrdinalIgnoreCase)
                || String.Equals(selectedTechnology, "Todos", StringComparison.OrdinalIgnoreCase)
                || String.Equals(selectedTechnology, "All", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return String.Equals(
                NormalizeTechnologyLabel(technology),
                NormalizeTechnologyLabel(selectedTechnology),
                StringComparison.OrdinalIgnoreCase);
        }

        private void RefreshMonitorFilters()
        {
            if (_monitorSubcenterFilter == null || _typeFilter == null)
            {
                return;
            }

            string selectedType = GetComboText(_typeFilter, T("Todos", "All"));
            string selectedSubcenter = GetComboText(_monitorSubcenterFilter, T("Todos", "All"));
            _suppressMonitorFilterEvents = true;
            try
            {
                FillCombo(_typeFilter, BuildMonitorTypeFilterValues(), selectedType);
                FillCombo(_monitorSubcenterFilter, BuildMonitorSubcenterFilterValues(), selectedSubcenter);
            }
            finally
            {
                _suppressMonitorFilterEvents = false;
            }
        }

        private List<string> BuildMonitorTypeFilterValues()
        {
            List<string> values = new List<string>();
            values.Add(T("Todos", "All"));
            for (int i = 0; i < DeviceTypes.Length; i++)
            {
                AddUnique(values, DeviceTypes[i]);
            }

            for (int i = 0; i < _devices.Count; i++)
            {
                AddUnique(values, GetRecordTechnology(_devices[i]));
            }

            return values;
        }

        private List<string> BuildMonitorSubcenterFilterValues()
        {
            List<string> values = new List<string>();
            values.Add(T("Todos", "All"));
            for (int i = 0; i < _devices.Count; i++)
            {
                AddUnique(values, GetRecordSubcenter(_devices[i]));
            }

            return values;
        }

        private void UpdateSummary()
        {
            UpdateSummary(true);
        }

        private void UpdateSummary(bool refreshRelatedViews)
        {
            int total = _devices.Count;
            int online = 0;
            int offline = 0;
            int error = 0;
            int pending = 0;

            for (int i = 0; i < _devices.Count; i++)
            {
                string status = _devices[i].Status;
                if (status == "En linea")
                {
                    online++;
                }
                else if (status == "Sin respuesta")
                {
                    offline++;
                }
                else if (status == "Error")
                {
                    error++;
                }
                else
                {
                    pending++;
                }
            }

            _summaryLabel.Text = "Total: " + total.ToString(CultureInfo.InvariantCulture)
                + "   " + T("En linea", "Online") + ": " + online.ToString(CultureInfo.InvariantCulture)
                + "   " + T("Sin respuesta", "No response") + ": " + offline.ToString(CultureInfo.InvariantCulture)
                + "   Error: " + error.ToString(CultureInfo.InvariantCulture)
                + "   " + T("Pendiente", "Pending") + ": " + pending.ToString(CultureInfo.InvariantCulture)
                + "   " + T("Vista", "View") + ": " + _visibleDevices.Count.ToString(CultureInfo.InvariantCulture)
                + "/" + total.ToString(CultureInfo.InvariantCulture);

            if (refreshRelatedViews)
            {
                RefreshMonitorFilters();
                RefreshDashboardFilters();
                UpdateDashboard();
            }
        }

        private void SetStatus(string text)
        {
            if (_statusText != null)
            {
                _statusText.Text = UiText.TranslateKnown(text, IsEnglishUi());
            }
        }

        private void RefreshDashboardFilters()
        {
            if (_dashboardTechnologyFilter == null || _dashboardSubcenterFilter == null || _dashboardAffiliationFilter == null)
            {
                return;
            }

            string selectedTechnology = GetComboText(_dashboardTechnologyFilter, T("Todas", "All"));
            string selectedSubcenter = GetComboText(_dashboardSubcenterFilter, T("Todas", "All"));
            string selectedAffiliation = GetComboText(_dashboardAffiliationFilter, T("Todas", "All"));

            _suppressDashboardFilterEvents = true;
            try
            {
                FillCombo(_dashboardTechnologyFilter, BuildTechnologyFilterValues(), selectedTechnology);
                FillCombo(_dashboardSubcenterFilter, BuildSubcenterFilterValues(), selectedSubcenter);
                FillCombo(_dashboardAffiliationFilter, BuildAffiliationFilterValues(), selectedAffiliation);
            }
            finally
            {
                _suppressDashboardFilterEvents = false;
            }
        }

        private List<string> BuildTechnologyFilterValues()
        {
            List<string> values = new List<string>();
            values.Add(T("Todas", "All"));
            for (int i = 0; i < DashboardTechnologies.Length; i++)
            {
                AddUnique(values, DashboardTechnologies[i]);
            }

            for (int i = 0; i < _devices.Count; i++)
            {
                AddUnique(values, GetRecordTechnology(_devices[i]));
            }

            return values;
        }

        private List<string> BuildAffiliationFilterValues()
        {
            List<string> values = new List<string>();
            values.Add(T("Todas", "All"));
            for (int i = 0; i < _devices.Count; i++)
            {
                AddUnique(values, GetRecordAffiliation(_devices[i]));
            }

            return values;
        }

        private List<string> BuildSubcenterFilterValues()
        {
            List<string> values = new List<string>();
            values.Add(T("Todas", "All"));
            for (int i = 0; i < _devices.Count; i++)
            {
                AddUnique(values, GetRecordSubcenter(_devices[i]));
            }

            return values;
        }

        private void FillCombo(ComboBox combo, List<string> values, string selected)
        {
            combo.BeginUpdate();
            combo.Items.Clear();
            for (int i = 0; i < values.Count; i++)
            {
                combo.Items.Add(values[i]);
            }

            int index = 0;
            for (int i = 0; i < combo.Items.Count; i++)
            {
                if (ComboValuesMatch(Convert.ToString(combo.Items[i], CultureInfo.InvariantCulture), selected))
                {
                    index = i;
                    break;
                }
            }

            if (combo.Items.Count > 0)
            {
                combo.SelectedIndex = index;
            }

            if (combo.DropDownStyle == ComboBoxStyle.DropDown && !String.IsNullOrWhiteSpace(selected))
            {
                combo.Text = UiText.IsAll(selected) && combo.Items.Count > 0 ? Convert.ToString(combo.Items[index], CultureInfo.InvariantCulture) : selected;
            }

            combo.EndUpdate();
        }

        private string GetComboText(ComboBox combo, string fallback)
        {
            if (combo == null)
            {
                return fallback;
            }

            string value = combo.Text;
            if (String.IsNullOrWhiteSpace(value) && combo.SelectedItem != null)
            {
                value = combo.SelectedItem.ToString();
            }

            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }

        private bool ComboValuesMatch(string left, string right)
        {
            if (UiText.IsAll(left) && UiText.IsAll(right))
            {
                return true;
            }

            return String.Equals(left, right, StringComparison.OrdinalIgnoreCase);
        }

        private void AddUnique(List<string> values, string value)
        {
            string text = String.IsNullOrWhiteSpace(value) ? "Sin afiliacion" : value.Trim();
            for (int i = 0; i < values.Count; i++)
            {
                if (String.Equals(values[i], text, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }
            }

            values.Add(text);
        }

        private void ResetFailures()
        {
            for (int i = 0; i < _devices.Count; i++)
            {
                _devices[i].Failures = 0;
            }

            UpdateSummary();
            SetStatus("Contadores de fallos reiniciados.");
        }

        private PingHistoryEntry CreateHistoryEntry(PingResult result)
        {
            if (result == null || result.Record == null || String.IsNullOrWhiteSpace(result.Record.Ip))
            {
                return null;
            }

            PingHistoryEntry entry = new PingHistoryEntry();
            entry.CheckedAt = result.CheckedAt;
            entry.Ip = result.Record.Ip.Trim();
            entry.Type = GetRecordTechnology(result.Record);
            entry.Subcenter = GetRecordSubcenter(result.Record);
            entry.Affiliation = GetRecordAffiliation(result.Record);
            entry.Success = result.Success;
            entry.LatencyMs = ParseLatencyMs(result.Latency);

            return entry;
        }

        private int ParseLatencyMs(string value)
        {
            if (String.IsNullOrWhiteSpace(value))
            {
                return -1;
            }

            string clean = value.Replace("ms", "").Trim();
            int latency;
            return Int32.TryParse(clean, NumberStyles.Integer, CultureInfo.InvariantCulture, out latency) ? latency : -1;
        }

        private void AppendHistoryEntries(List<PingHistoryEntry> entries)
        {
            if (entries == null || entries.Count == 0)
            {
                return;
            }

            bool writeHeader = !File.Exists(_historyPath) || new FileInfo(_historyPath).Length == 0;
            using (FileStream stream = new FileStream(_historyPath, FileMode.Append, FileAccess.Write, FileShare.Read))
            {
                if (writeHeader)
                {
                    stream.Write(HistoryMagic, 0, HistoryMagic.Length);
                }

                using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8))
                {
                    for (int i = 0; i < entries.Count; i++)
                    {
                        WriteHistoryEntry(writer, entries[i]);
                    }
                }
            }
        }

        private void LoadHistory()
        {
            _history.Clear();
            _historyNeedsRewrite = false;
            if (File.Exists(_historyPath))
            {
                LoadCompactHistory(_historyPath);
                if (_historyNeedsRewrite)
                {
                    SaveHistory();
                }
                return;
            }

            if (File.Exists(_legacyHistoryPath))
            {
                LoadLegacyCsvHistory(_legacyHistoryPath);
                if (_history.Count > 0)
                {
                    SaveHistory();
                }
            }
        }

        private void LoadCompactHistory(string path)
        {
            try
            {
                using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    byte[] header = new byte[HistoryMagic.Length];
                    int read = stream.Read(header, 0, header.Length);
                    bool version2 = read == header.Length && BytesEqual(header, HistoryMagic);
                    bool version1 = read == header.Length && BytesEqual(header, HistoryMagicV1);
                    if (!version2 && !version1)
                    {
                        return;
                    }
                    _historyNeedsRewrite = version1;

                    using (BinaryReader reader = new BinaryReader(stream, Encoding.UTF8))
                    {
                        while (stream.Position < stream.Length)
                        {
                            PingHistoryEntry entry = new PingHistoryEntry();
                            entry.CheckedAt = DateTime.FromBinary(reader.ReadInt64());
                            entry.Ip = reader.ReadString();
                            entry.Type = NormalizeTechnologyLabel(reader.ReadString());
                            entry.Subcenter = version2 ? NormalizeSubcenter(reader.ReadString()) : FindSubcenterByIp(entry.Ip);
                            entry.Affiliation = NormalizeAffiliation(reader.ReadString(), "");
                            entry.Success = reader.ReadBoolean();
                            entry.LatencyMs = reader.ReadInt32();
                            _history.Add(entry);
                        }
                    }
                }
            }
            catch (EndOfStreamException)
            {
                // Ignore a partially written tail; the next cycle will continue with valid data.
            }
            catch
            {
                _history.Clear();
            }
        }

        private bool BytesEqual(byte[] left, byte[] right)
        {
            if (left == null || right == null || left.Length != right.Length)
            {
                return false;
            }

            for (int i = 0; i < left.Length; i++)
            {
                if (left[i] != right[i])
                {
                    return false;
                }
            }

            return true;
        }

        private void LoadLegacyCsvHistory(string path)
        {
            string[] lines = File.ReadAllLines(path, Encoding.UTF8);
            for (int i = 0; i < lines.Length; i++)
            {
                if (String.IsNullOrWhiteSpace(lines[i]))
                {
                    continue;
                }

                List<string> row = ParseDelimitedLine(lines[i], ',');
                if (row.Count == 0)
                {
                    continue;
                }

                if (i == 0 && NormalizeHeader(row[0]) == "checkedat")
                {
                    continue;
                }

                DateTime checkedAt;
                if (!DateTime.TryParse(row[0], CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out checkedAt)
                    && !DateTime.TryParse(row[0], out checkedAt))
                {
                    continue;
                }

                PingHistoryEntry entry = new PingHistoryEntry();
                entry.CheckedAt = checkedAt;
                entry.Ip = row.Count > 1 ? row[1] : "";
                entry.Type = NormalizeTechnologyLabel(row.Count > 2 ? row[2] : "");
                if (row.Count >= 7)
                {
                    entry.Subcenter = NormalizeSubcenter(row[3]);
                    entry.Affiliation = NormalizeAffiliation(row[4], "");
                    entry.Success = ParseHistorySuccess(row[5]);
                    int latency;
                    entry.LatencyMs = Int32.TryParse(row[6], NumberStyles.Integer, CultureInfo.InvariantCulture, out latency)
                        ? latency
                        : -1;
                }
                else if (row.Count >= 6)
                {
                    entry.Subcenter = FindSubcenterByIp(entry.Ip);
                    entry.Affiliation = NormalizeAffiliation(row[3], "");
                    entry.Success = ParseHistorySuccess(row[4]);
                    int latency;
                    entry.LatencyMs = Int32.TryParse(row[5], NumberStyles.Integer, CultureInfo.InvariantCulture, out latency)
                        ? latency
                        : -1;
                }
                else
                {
                    entry.Subcenter = FindSubcenterByIp(entry.Ip);
                    entry.Affiliation = FindAffiliationByIp(entry.Ip);
                    entry.Success = ParseHistorySuccess(row.Count > 3 ? row[3] : "");
                    int latency;
                    entry.LatencyMs = row.Count > 4 && Int32.TryParse(row[4], NumberStyles.Integer, CultureInfo.InvariantCulture, out latency)
                        ? latency
                        : -1;
                }
                _history.Add(entry);
            }
        }

        private string FindAffiliationByIp(string ip)
        {
            for (int i = 0; i < _devices.Count; i++)
            {
                if (String.Equals(_devices[i].Ip, ip, StringComparison.OrdinalIgnoreCase))
                {
                    return GetRecordAffiliation(_devices[i]);
                }
            }

            return "Sin afiliacion";
        }

        private string FindSubcenterByIp(string ip)
        {
            for (int i = 0; i < _devices.Count; i++)
            {
                if (String.Equals(_devices[i].Ip, ip, StringComparison.OrdinalIgnoreCase))
                {
                    return GetRecordSubcenter(_devices[i]);
                }
            }

            return "Sin ubicacion";
        }

        private bool ParseHistorySuccess(string value)
        {
            string normalized = NormalizeHeader(value);
            return normalized == "1" || normalized == "true" || normalized == "enlinea" || normalized == "online" || normalized == "success";
        }

        private bool PruneHistory()
        {
            DateTime cutoff = DateTime.Now.AddDays(-5);
            int before = _history.Count;
            _history.RemoveAll(delegate(PingHistoryEntry entry)
            {
                return entry.CheckedAt < cutoff;
            });

            return before != _history.Count;
        }

        private void EnsureHistoryResetCycle()
        {
            DateTime lastReset = ReadHistoryResetDate();
            DateTime now = DateTime.Now;
            if ((now - lastReset).TotalDays >= 5.0)
            {
                _history.Clear();
                SaveHistoryResetDate(now);
                SaveHistory();
                if (File.Exists(_legacyHistoryPath))
                {
                    File.Delete(_legacyHistoryPath);
                }
                SetStatus("Historial reiniciado automaticamente por ciclo de 5 dias.");
                return;
            }

            if (!File.Exists(_historyResetPath))
            {
                SaveHistoryResetDate(lastReset);
            }
        }

        private DateTime ReadHistoryResetDate()
        {
            if (File.Exists(_historyResetPath))
            {
                string text = File.ReadAllText(_historyResetPath, Encoding.UTF8).Trim();
                DateTime parsed;
                if (DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out parsed)
                    || DateTime.TryParse(text, out parsed))
                {
                    return parsed;
                }
            }

            if (File.Exists(_historyPath))
            {
                DateTime created = File.GetCreationTime(_historyPath);
                if (created > DateTime.MinValue)
                {
                    return created;
                }
            }

            if (File.Exists(_legacyHistoryPath))
            {
                DateTime created = File.GetCreationTime(_legacyHistoryPath);
                if (created > DateTime.MinValue)
                {
                    return created;
                }
            }

            return DateTime.Now;
        }

        private void SaveHistoryResetDate(DateTime value)
        {
            File.WriteAllText(
                _historyResetPath,
                value.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                Encoding.UTF8);
        }

        private void SaveHistory()
        {
            using (FileStream stream = new FileStream(_historyPath, FileMode.Create, FileAccess.Write, FileShare.Read))
            {
                stream.Write(HistoryMagic, 0, HistoryMagic.Length);
                using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8))
                {
                    for (int i = 0; i < _history.Count; i++)
                    {
                        WriteHistoryEntry(writer, _history[i]);
                    }
                }
            }
        }

        private void WriteHistoryEntry(BinaryWriter writer, PingHistoryEntry entry)
        {
            writer.Write(entry.CheckedAt.ToBinary());
            writer.Write(entry.Ip == null ? "" : entry.Ip);
            writer.Write(entry.Type == null ? "" : entry.Type);
            writer.Write(entry.Subcenter == null ? "" : entry.Subcenter);
            writer.Write(entry.Affiliation == null ? "" : entry.Affiliation);
            writer.Write(entry.Success);
            writer.Write(entry.LatencyMs);
        }

        private void ClearHistory()
        {
            DialogResult result = MessageBox.Show(
                "Desea limpiar el historial de disponibilidad del dashboard?",
                "Limpiar historial",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (result != DialogResult.Yes)
            {
                return;
            }

            _history.Clear();
            if (File.Exists(_historyPath))
            {
                File.Delete(_historyPath);
            }
            if (File.Exists(_legacyHistoryPath))
            {
                File.Delete(_legacyHistoryPath);
            }

            SaveHistoryResetDate(DateTime.Now);
            UpdateDashboard();
            SetStatus("Historial de disponibilidad limpiado.");
        }

        private void UpdateDashboard()
        {
            if (_dashboardView == null || _dashboardSummaryLabel == null)
            {
                return;
            }

            DateTime now = DateTime.Now;
            DateTime cutoff = now.AddDays(-_dashboardWindowDays);
            string selectedTechnology = GetComboText(_dashboardTechnologyFilter, T("Todas", "All"));
            string selectedSubcenter = GetComboText(_dashboardSubcenterFilter, T("Todas", "All"));
            string selectedAffiliation = GetComboText(_dashboardAffiliationFilter, T("Todas", "All"));
            string searchText = _dashboardSearchText == null ? "" : _dashboardSearchText.Text.Trim();
            string groupMode = CanonicalDashboardGroup(GetComboText(_dashboardGroupFilter, DisplayDashboardGroup("technology")));
            bool groupBySubcenterTechnology = groupMode == "subtechnology";
            bool groupBySubcenter = groupMode == "subcenter";
            bool groupByAffiliation = groupMode == "affiliation";
            bool groupByDevice = groupMode == "device";
            string groupKind = groupByDevice ? "Dispositivo" : groupBySubcenterTechnology ? "Mixto" : groupBySubcenter ? "Ubicacion" : groupByAffiliation ? "Afiliacion" : "Tecnologia";
            Dictionary<string, DashboardStats> stats = new Dictionary<string, DashboardStats>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, DashboardStats> subcenterStats = new Dictionary<string, DashboardStats>(StringComparer.OrdinalIgnoreCase);
            List<string> orderedSubcenters = new List<string>();
            Dictionary<string, DeviceRecord> devicesByIp = BuildDeviceLookup();

            if (groupByDevice)
            {
                for (int i = 0; i < _devices.Count; i++)
                {
                    string technology = GetRecordTechnology(_devices[i]);
                    string subcenter = GetRecordSubcenter(_devices[i]);
                    string affiliation = GetRecordAffiliation(_devices[i]);
                    if (MatchesDashboardFilters(_devices[i].Name, _devices[i].Ip, technology, subcenter, affiliation, selectedTechnology, selectedSubcenter, selectedAffiliation, searchText))
                    {
                        EnsureDashboardStats(stats, FormatDeviceGroup(_devices[i]), groupKind);
                    }
                }
            }
            else if (groupBySubcenterTechnology)
            {
                for (int i = 0; i < _devices.Count; i++)
                {
                    string technology = GetRecordTechnology(_devices[i]);
                    string subcenter = GetRecordSubcenter(_devices[i]);
                    string affiliation = GetRecordAffiliation(_devices[i]);
                    if (MatchesDashboardFilters(_devices[i].Name, _devices[i].Ip, technology, subcenter, affiliation, selectedTechnology, selectedSubcenter, selectedAffiliation, searchText))
                    {
                        EnsureDashboardStats(stats, FormatSubcenterTechnologyGroup(subcenter, technology), groupKind);
                    }
                }
            }
            else if (groupBySubcenter)
            {
                List<string> subcenters = BuildSubcenterFilterValues();
                for (int i = 0; i < subcenters.Count; i++)
                {
                    if (!UiText.IsAll(subcenters[i]))
                    {
                        EnsureDashboardStats(stats, subcenters[i], groupKind);
                    }
                }
            }
            else if (groupByAffiliation)
            {
                List<string> affiliations = BuildAffiliationFilterValues();
                for (int i = 0; i < affiliations.Count; i++)
                {
                    if (!UiText.IsAll(affiliations[i]))
                    {
                        EnsureDashboardStats(stats, affiliations[i], groupKind);
                    }
                }
            }
            else
            {
                for (int i = 0; i < DashboardTechnologies.Length; i++)
                {
                    EnsureDashboardStats(stats, DashboardTechnologies[i], groupKind);
                }
            }

            for (int i = 0; i < _devices.Count; i++)
            {
                string technology = GetRecordTechnology(_devices[i]);
                string subcenter = GetRecordSubcenter(_devices[i]);
                string affiliation = GetRecordAffiliation(_devices[i]);
                if (!MatchesDashboardFilters(_devices[i].Name, _devices[i].Ip, technology, subcenter, affiliation, selectedTechnology, selectedSubcenter, selectedAffiliation, searchText))
                {
                    continue;
                }

                string groupKey = groupByDevice ? FormatDeviceGroup(_devices[i]) : groupBySubcenterTechnology ? FormatSubcenterTechnologyGroup(subcenter, technology) : groupBySubcenter ? subcenter : groupByAffiliation ? affiliation : technology;
                DashboardStats stat = EnsureDashboardStats(stats, groupKey, groupKind);
                stat.Devices++;

                DashboardStats subcenterStat = EnsureDashboardStats(subcenterStats, subcenter, "Ubicacion");
                subcenterStat.Devices++;
                AddUnique(orderedSubcenters, subcenter);
            }

            DashboardStats total = new DashboardStats();
            total.Technology = "TOTAL";

            for (int i = 0; i < _history.Count; i++)
            {
                PingHistoryEntry entry = _history[i];
                if (entry.CheckedAt < cutoff)
                {
                    continue;
                }

                string technology = NormalizeTechnologyLabel(entry.Type);
                DeviceRecord device = null;
                if (!String.IsNullOrWhiteSpace(entry.Ip))
                {
                    devicesByIp.TryGetValue(entry.Ip, out device);
                }
                string name = device == null ? entry.Ip : device.Name;
                string subcenter = NormalizeSubcenter(String.IsNullOrWhiteSpace(entry.Subcenter) && device != null ? GetRecordSubcenter(device) : entry.Subcenter);
                string affiliation = NormalizeAffiliation(entry.Affiliation, name);
                if (!MatchesDashboardFilters(name, entry.Ip, technology, subcenter, affiliation, selectedTechnology, selectedSubcenter, selectedAffiliation, searchText))
                {
                    continue;
                }

                string groupKey = groupByDevice ? FormatDeviceGroup(name, entry.Ip) : groupBySubcenterTechnology ? FormatSubcenterTechnologyGroup(subcenter, technology) : groupBySubcenter ? subcenter : groupByAffiliation ? affiliation : technology;
                DashboardStats stat = EnsureDashboardStats(stats, groupKey, groupKind);
                AddDashboardSample(stat, entry);

                DashboardStats subcenterStat = EnsureDashboardStats(subcenterStats, subcenter, "Ubicacion");
                AddDashboardSample(subcenterStat, entry);

                AddDashboardSample(total, entry);
            }

            total.Devices = CountDashboardDevices(selectedTechnology, selectedSubcenter, selectedAffiliation, searchText);
            List<string> orderedTypes = new List<string>();
            if (groupByDevice)
            {
                for (int i = 0; i < _devices.Count; i++)
                {
                    string technology = GetRecordTechnology(_devices[i]);
                    string subcenter = GetRecordSubcenter(_devices[i]);
                    string affiliation = GetRecordAffiliation(_devices[i]);
                    if (MatchesDashboardFilters(_devices[i].Name, _devices[i].Ip, technology, subcenter, affiliation, selectedTechnology, selectedSubcenter, selectedAffiliation, searchText))
                    {
                        orderedTypes.Add(FormatDeviceGroup(_devices[i]));
                    }
                }
            }
            else if (groupBySubcenterTechnology)
            {
                for (int i = 0; i < _devices.Count; i++)
                {
                    string technology = GetRecordTechnology(_devices[i]);
                    string subcenter = GetRecordSubcenter(_devices[i]);
                    string affiliation = GetRecordAffiliation(_devices[i]);
                    if (MatchesDashboardFilters(_devices[i].Name, _devices[i].Ip, technology, subcenter, affiliation, selectedTechnology, selectedSubcenter, selectedAffiliation, searchText))
                    {
                        AddUnique(orderedTypes, FormatSubcenterTechnologyGroup(subcenter, technology));
                    }
                }
            }
            else if (groupBySubcenter)
            {
                List<string> subcenters = BuildSubcenterFilterValues();
                for (int i = 0; i < subcenters.Count; i++)
                {
                    if (!UiText.IsAll(subcenters[i]))
                    {
                        orderedTypes.Add(subcenters[i]);
                    }
                }
            }
            else if (groupByAffiliation)
            {
                List<string> affiliations = BuildAffiliationFilterValues();
                for (int i = 0; i < affiliations.Count; i++)
                {
                    if (!UiText.IsAll(affiliations[i]))
                    {
                        orderedTypes.Add(affiliations[i]);
                    }
                }
            }
            else
            {
                for (int i = 0; i < DashboardTechnologies.Length; i++)
                {
                    orderedTypes.Add(DashboardTechnologies[i]);
                }
            }

            foreach (string key in stats.Keys)
            {
                bool exists = false;
                for (int i = 0; i < orderedTypes.Count; i++)
                {
                    if (String.Equals(orderedTypes[i], key, StringComparison.OrdinalIgnoreCase))
                    {
                        exists = true;
                        break;
                    }
                }

                if (!exists)
                {
                    orderedTypes.Add(key);
                }
            }

            List<DashboardStats> orderedStats = new List<DashboardStats>();
            for (int i = 0; i < orderedTypes.Count; i++)
            {
                DashboardStats stat;
                if (stats.TryGetValue(orderedTypes[i], out stat))
                {
                    orderedStats.Add(stat);
                }
            }

            foreach (string key in subcenterStats.Keys)
            {
                bool exists = false;
                for (int i = 0; i < orderedSubcenters.Count; i++)
                {
                    if (String.Equals(orderedSubcenters[i], key, StringComparison.OrdinalIgnoreCase))
                    {
                        exists = true;
                        break;
                    }
                }

                if (!exists)
                {
                    orderedSubcenters.Add(key);
                }
            }

            List<DashboardStats> orderedSubcenterStats = new List<DashboardStats>();
            for (int i = 0; i < orderedSubcenters.Count; i++)
            {
                DashboardStats stat;
                if (subcenterStats.TryGetValue(orderedSubcenters[i], out stat))
                {
                    orderedSubcenterStats.Add(stat);
                }
            }

            double totalAvailability = total.Samples == 0 ? -1 : (total.Online * 100.0 / total.Samples);
            string availabilityText = totalAvailability < 0
                ? T("Sin datos", "No data")
                : totalAvailability.ToString("0.00", CultureInfo.InvariantCulture) + " %";

            if (IsEnglishUi())
            {
                _dashboardSummaryLabel.Text = "Window: "
                    + cutoff.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)
                    + " to "
                    + now.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)
                    + "   Overall availability: "
                    + availabilityText
                    + "   Samples: "
                    + total.Samples.ToString(CultureInfo.InvariantCulture)
                    + "   Filters: "
                    + selectedTechnology
                    + " / "
                    + selectedSubcenter
                    + " / "
                    + selectedAffiliation
                    + (String.IsNullOrWhiteSpace(searchText) ? "" : " / search: " + searchText);
            }
            else
            {
                _dashboardSummaryLabel.Text = "Ventana: "
                    + cutoff.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)
                    + " a "
                    + now.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)
                    + "   Disponibilidad general: "
                    + availabilityText
                    + "   Muestras: "
                    + total.Samples.ToString(CultureInfo.InvariantCulture)
                    + "   Filtros: "
                    + selectedTechnology
                    + " / "
                    + selectedSubcenter
                    + " / "
                    + selectedAffiliation
                    + (String.IsNullOrWhiteSpace(searchText) ? "" : " / busqueda: " + searchText);
            }

            if (_kpiAvailabilityLabel != null)
            {
                _kpiAvailabilityLabel.Text = availabilityText;
            }

            if (_kpiSamplesLabel != null)
            {
                _kpiSamplesLabel.Text = total.Samples.ToString(CultureInfo.InvariantCulture);
            }

            if (_kpiOnlineLabel != null)
            {
                _kpiOnlineLabel.Text = total.Online.ToString(CultureInfo.InvariantCulture);
            }

            if (_kpiOfflineLabel != null)
            {
                _kpiOfflineLabel.Text = total.Offline.ToString(CultureInfo.InvariantCulture);
            }

            _currentDashboardTotal = total;
            _currentDashboardStats = new List<DashboardStats>(orderedStats);
            _currentDashboardSubcenterStats = new List<DashboardStats>(orderedSubcenterStats);
            _currentDashboardCutoff = cutoff;
            _currentDashboardNow = now;
            _currentDashboardGroupLabel = groupByDevice ? T("dispositivo/IP", "device/IP") : groupBySubcenterTechnology ? T("ubicacion/tecnologia", "location/technology") : groupBySubcenter ? T("ubicacion", "location") : groupByAffiliation ? T("afiliacion", "affiliation") : T("tecnologia", "technology");
            _currentTechnologyFilter = selectedTechnology;
            _currentSubcenterFilter = selectedSubcenter;
            _currentAffiliationFilter = selectedAffiliation;
            _currentSearchFilter = searchText;

            _dashboardView.SetData(
                total,
                orderedStats,
                orderedSubcenterStats,
                cutoff,
                now,
                _currentDashboardGroupLabel,
                selectedTechnology,
                selectedSubcenter,
                selectedAffiliation,
                searchText);
            ArrangeDashboardCanvas();
        }

        private bool MatchesDashboardFilters(string name, string ip, string technology, string subcenter, string affiliation, string selectedTechnology, string selectedSubcenter, string selectedAffiliation, string searchText)
        {
            bool technologyOk = TechnologyMatches(technology, selectedTechnology);
            bool subcenterOk = UiText.IsAll(selectedSubcenter)
                || NormalizeHeader(NormalizeSubcenter(subcenter)).Contains(NormalizeHeader(selectedSubcenter));
            bool affiliationOk = UiText.IsAll(selectedAffiliation)
                || NormalizeHeader(NormalizeAffiliation(affiliation, "")).Contains(NormalizeHeader(selectedAffiliation));
            bool searchOk = String.IsNullOrWhiteSpace(searchText)
                || Contains(name, searchText.ToLowerInvariant())
                || Contains(ip, searchText.ToLowerInvariant())
                || Contains(subcenter, searchText.ToLowerInvariant())
                || Contains(affiliation, searchText.ToLowerInvariant())
                || Contains(technology, searchText.ToLowerInvariant());
            return technologyOk && subcenterOk && affiliationOk && searchOk;
        }

        private int CountDashboardDevices(string selectedTechnology, string selectedSubcenter, string selectedAffiliation, string searchText)
        {
            int count = 0;
            for (int i = 0; i < _devices.Count; i++)
            {
                if (MatchesDashboardFilters(
                    _devices[i].Name,
                    _devices[i].Ip,
                    GetRecordTechnology(_devices[i]),
                    GetRecordSubcenter(_devices[i]),
                    GetRecordAffiliation(_devices[i]),
                    selectedTechnology,
                    selectedSubcenter,
                    selectedAffiliation,
                    searchText))
                {
                    count++;
                }
            }

            return count;
        }

        private Dictionary<string, DeviceRecord> BuildDeviceLookup()
        {
            Dictionary<string, DeviceRecord> lookup = new Dictionary<string, DeviceRecord>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < _devices.Count; i++)
            {
                string ip = _devices[i].Ip == null ? "" : _devices[i].Ip.Trim();
                if (!String.IsNullOrWhiteSpace(ip) && !lookup.ContainsKey(ip))
                {
                    lookup.Add(ip, _devices[i]);
                }
            }

            return lookup;
        }

        private DeviceRecord FindDeviceByIp(string ip)
        {
            for (int i = 0; i < _devices.Count; i++)
            {
                if (String.Equals(_devices[i].Ip, ip, StringComparison.OrdinalIgnoreCase))
                {
                    return _devices[i];
                }
            }

            return null;
        }

        private string FormatDeviceGroup(DeviceRecord record)
        {
            if (record == null)
            {
                return "Sin dispositivo";
            }

            return FormatDeviceGroup(record.Name, record.Ip);
        }

        private string FormatDeviceGroup(string name, string ip)
        {
            string cleanName = String.IsNullOrWhiteSpace(name) ? "Sin nombre" : name.Trim();
            string cleanIp = String.IsNullOrWhiteSpace(ip) ? "Sin IP" : ip.Trim();
            return cleanName + "  |  " + cleanIp;
        }

        private string FormatSubcenterTechnologyGroup(string subcenter, string technology)
        {
            return NormalizeSubcenter(subcenter) + " / " + NormalizeTechnologyLabel(technology);
        }

        private DashboardStats EnsureDashboardStats(Dictionary<string, DashboardStats> stats, string value, string groupKind)
        {
            string kind = String.IsNullOrWhiteSpace(groupKind) ? "Tecnologia" : groupKind;
            string type = kind == "Afiliacion"
                ? NormalizeAffiliation(value, "")
                : kind == "Ubicacion"
                    ? NormalizeSubcenter(value)
                : kind == "Dispositivo"
                    ? (String.IsNullOrWhiteSpace(value) ? "Sin dispositivo" : value.Trim())
                    : kind == "Mixto"
                        ? (String.IsNullOrWhiteSpace(value) ? "Sin grupo" : value.Trim())
                    : NormalizeTechnologyLabel(value);
            if (String.IsNullOrWhiteSpace(type))
            {
                type = "Otro";
            }
            DashboardStats stat;
            if (!stats.TryGetValue(type, out stat))
            {
                stat = new DashboardStats();
                stat.Technology = type;
                stat.GroupKind = kind;
                stats[type] = stat;
            }

            return stat;
        }

        private void AddDashboardSample(DashboardStats stat, PingHistoryEntry entry)
        {
            stat.Samples++;
            if (entry.Success)
            {
                stat.Online++;
            }
            else
            {
                stat.Offline++;
            }

            if (!stat.HasSample || entry.CheckedAt < stat.FirstSample)
            {
                stat.FirstSample = entry.CheckedAt;
            }

            if (!stat.HasSample || entry.CheckedAt > stat.LastSample)
            {
                stat.LastSample = entry.CheckedAt;
            }

            stat.HasSample = true;
        }

        private void ExportDashboardReport()
        {
            UpdateDashboard();
            if (_currentDashboardTotal == null)
            {
                SetStatus("No hay datos de dashboard para exportar.");
                return;
            }

            using (SaveFileDialog dialog = new SaveFileDialog())
            {
                dialog.Title = "Descargar reporte del dashboard";
                dialog.Filter = "PDF (*.pdf)|*.pdf";
                dialog.FileName = "reporte-dashboard-" + DateTime.Now.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + ".pdf";
                if (dialog.ShowDialog(this) != DialogResult.OK)
                {
                    return;
                }

                SaveDashboardReportPdf(dialog.FileName);

                SetStatus("Reporte PDF del dashboard descargado.");
            }
        }

        private void SaveDashboardReportPdf(string path)
        {
            const int width = 1754;
            const int height = 1240;
            List<byte[]> pages = new List<byte[]>();

            pages.Add(RenderDashboardSnapshotPageImage(width, height));

            WriteMultiPagePdf(path, pages, width, height);
        }

        private byte[] RenderDashboardSnapshotPageImage(int width, int height)
        {
            using (Bitmap page = new Bitmap(width, height))
            {
                page.SetResolution(144F, 144F);
                using (DashboardView reportView = new DashboardView())
                {
                    reportView.Size = new Size(width, height);
                    reportView.BackColor = AppBackground;
                    reportView.SetData(
                        _currentDashboardTotal,
                        _currentDashboardStats,
                        _currentDashboardSubcenterStats,
                        _currentDashboardCutoff,
                        _currentDashboardNow,
                        _currentDashboardGroupLabel,
                        _currentTechnologyFilter,
                        _currentSubcenterFilter,
                        _currentAffiliationFilter,
                        _currentSearchFilter);
                    reportView.CreateControl();
                    reportView.DrawToBitmap(page, new Rectangle(0, 0, width, height));
                }

                return EncodeReportPage(page);
            }
        }

        private byte[] RenderReportPageImage(int width, int height, Action<Graphics, Rectangle> drawPage)
        {
            using (Bitmap page = new Bitmap(width, height))
            {
                page.SetResolution(144F, 144F);
                using (Graphics g = Graphics.FromImage(page))
                {
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                    drawPage(g, new Rectangle(0, 0, width, height));
                }

                return EncodeReportPage(page);
            }
        }

        private byte[] EncodeReportPage(Bitmap page)
        {
            using (MemoryStream imageStream = new MemoryStream())
            {
                ImageCodecInfo codec = GetJpegCodec();
                if (codec != null)
                {
                    EncoderParameters parameters = new EncoderParameters(1);
                    parameters.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, 94L);
                    page.Save(imageStream, codec, parameters);
                }
                else
                {
                    page.Save(imageStream, ImageFormat.Jpeg);
                }

                return imageStream.ToArray();
            }
        }

        private ImageCodecInfo GetJpegCodec()
        {
            ImageCodecInfo[] codecs = ImageCodecInfo.GetImageEncoders();
            for (int i = 0; i < codecs.Length; i++)
            {
                if (codecs[i].FormatID == ImageFormat.Jpeg.Guid)
                {
                    return codecs[i];
                }
            }

            return null;
        }

        private void DrawDashboardReportPage(Graphics g, Rectangle page)
        {
            Color purple = Color.FromArgb(43, 0, 111);
            Color purpleDark = Color.FromArgb(20, 0, 66);
            Color mint = Color.FromArgb(79, 242, 185);
            Color cyan = Color.FromArgb(0, 229, 255);
            Color panel = Color.FromArgb(38, 0, 106);

            using (LinearGradientBrush bg = new LinearGradientBrush(page, Color.FromArgb(25, 0, 78), Color.FromArgb(7, 17, 45), LinearGradientMode.Vertical))
            {
                g.FillRectangle(bg, page);
            }

            DrawReportTechPattern(g, page);

            Rectangle header = new Rectangle(0, 0, page.Width, 260);
            using (LinearGradientBrush headerBrush = new LinearGradientBrush(header, Color.FromArgb(48, 0, 129), purpleDark, LinearGradientMode.Horizontal))
            {
                g.FillRectangle(headerBrush, header);
            }

            using (Image logo = LoadLogoImage())
            {
                if (logo != null)
                {
                    Rectangle logoBox = new Rectangle(82, 82, 370, 96);
                    DrawReportRoundRect(g, logoBox, 22, Color.FromArgb(30, 255, 255, 255), Color.FromArgb(90, cyan));
                    g.DrawImage(logo, FitImageRect(logo.Size, new Rectangle(106, 96, 322, 68)));
                }
            }

            using (Font title = new Font("Segoe UI Semibold", 34F, FontStyle.Bold))
            using (Font subtitle = new Font("Segoe UI", 13F, FontStyle.Regular))
            {
                DrawReportText(g, "REPORTE DE DISPONIBILIDAD", title, Color.White, new RectangleF(478, 78, 670, 56), StringAlignment.Far);
                DrawReportText(g, "PING SCAN MONITOR", title, Color.White, new RectangleF(478, 128, 670, 56), StringAlignment.Far);
                DrawReportText(g, "Generado: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture), subtitle, Color.FromArgb(211, 230, 255), new RectangleF(478, 188, 670, 26), StringAlignment.Far);
            }

            Rectangle band = new Rectangle(0, 260, page.Width, 78);
            using (Brush mintBrush = new SolidBrush(mint))
            {
                g.FillRectangle(mintBrush, band);
            }
            using (Font bandFont = new Font("Segoe UI Semibold", 23F, FontStyle.Bold))
            {
                DrawReportText(g, "DASHBOARD DE MONITOREO - ULTIMOS " + _dashboardWindowDays.ToString(CultureInfo.InvariantCulture) + " DIAS", bandFont, Color.FromArgb(8, 18, 32), band, StringAlignment.Center);
            }

            double availability = GetDashboardAvailability(_currentDashboardTotal);
            double onlinePct = _currentDashboardTotal.Samples == 0 ? -1 : (_currentDashboardTotal.Online * 100.0 / _currentDashboardTotal.Samples);
            double offlinePct = _currentDashboardTotal.Samples == 0 ? -1 : (_currentDashboardTotal.Offline * 100.0 / _currentDashboardTotal.Samples);
            DrawReportDonutMetric(g, new Rectangle(155, 386, 245, 245), availability, "DISPONIBILIDAD", mint, Color.White);
            DrawReportDonutMetric(g, new Rectangle(498, 386, 245, 245), onlinePct, "PING EN LINEA", Color.FromArgb(34, 197, 94), Color.White);
            DrawReportDonutMetric(g, new Rectangle(840, 386, 245, 245), offlinePct, "SIN RESPUESTA", Color.FromArgb(255, 86, 116), Color.White);

            DrawReportBand(g, 690, "RESUMEN OPERATIVO", mint);

            Rectangle infoCard = new Rectangle(115, 795, 455, 230);
            Rectangle filterCard = new Rectangle(670, 795, 455, 230);
            DrawReportRoundRect(g, infoCard, 0, Color.FromArgb(80, panel), Color.White);
            DrawReportRoundRect(g, filterCard, 0, Color.FromArgb(80, panel), Color.White);
            using (Font cardTitle = new Font("Segoe UI Semibold", 16F, FontStyle.Bold))
            using (Font labelFont = new Font("Segoe UI", 11F, FontStyle.Regular))
            using (Font valueFont = new Font("Segoe UI Semibold", 13F, FontStyle.Bold))
            {
                DrawReportText(g, "DATOS GENERALES", cardTitle, mint, new RectangleF(infoCard.Left + 28, infoCard.Top + 24, infoCard.Width - 56, 28), StringAlignment.Center);
                DrawReportInfoLine(g, "Periodo", _currentDashboardCutoff.ToString("dd/MM/yyyy HH:mm", CultureInfo.InvariantCulture) + " - " + _currentDashboardNow.ToString("dd/MM/yyyy HH:mm", CultureInfo.InvariantCulture), infoCard.Left + 34, infoCard.Top + 74, infoCard.Width - 68, labelFont, valueFont);
                DrawReportInfoLine(g, "Dispositivos", _currentDashboardTotal.Devices.ToString(CultureInfo.InvariantCulture), infoCard.Left + 34, infoCard.Top + 112, infoCard.Width - 68, labelFont, valueFont);
                DrawReportInfoLine(g, "Muestras", _currentDashboardTotal.Samples.ToString(CultureInfo.InvariantCulture), infoCard.Left + 34, infoCard.Top + 150, infoCard.Width - 68, labelFont, valueFont);

                DrawReportText(g, "FILTROS APLICADOS", cardTitle, mint, new RectangleF(filterCard.Left + 28, filterCard.Top + 24, filterCard.Width - 56, 28), StringAlignment.Center);
                DrawReportInfoLine(g, "Agrupacion", _currentDashboardGroupLabel, filterCard.Left + 34, filterCard.Top + 66, filterCard.Width - 68, labelFont, valueFont);
                DrawReportInfoLine(g, "Tecnologia", _currentTechnologyFilter, filterCard.Left + 34, filterCard.Top + 98, filterCard.Width - 68, labelFont, valueFont);
                DrawReportInfoLine(g, "Ubicacion / sitio", _currentSubcenterFilter, filterCard.Left + 34, filterCard.Top + 130, filterCard.Width - 68, labelFont, valueFont);
                DrawReportInfoLine(g, "Afiliacion", _currentAffiliationFilter, filterCard.Left + 34, filterCard.Top + 162, filterCard.Width - 68, labelFont, valueFont);
                DrawReportInfoLine(g, "IP / Dispositivo", String.IsNullOrWhiteSpace(_currentSearchFilter) ? "Todas" : _currentSearchFilter, filterCard.Left + 34, filterCard.Top + 194, filterCard.Width - 68, labelFont, valueFont);
            }

            DrawReportBand(g, 1080, "DISPONIBILIDAD POR " + (_currentDashboardGroupLabel == null ? "GRUPO" : _currentDashboardGroupLabel.ToUpperInvariant()), mint);
            DrawReportAvailabilityRows(g, new Rectangle(110, 1188, 1020, 360), mint, cyan);

            using (Font footer = new Font("Segoe UI", 14F, FontStyle.Regular))
            {
                DrawReportText(g, "PING SCAN  |  Reporte generado automaticamente por ping_scan", footer, Color.FromArgb(225, 235, 255), new RectangleF(0, 1648, page.Width, 34), StringAlignment.Center);
            }
        }

        private void DrawDashboardReportDetailPage(Graphics g, Rectangle page, List<DashboardStats> rows, int startIndex, int rowsPerPage, int pageNumber, int totalPages)
        {
            Color purpleDark = Color.FromArgb(18, 0, 58);
            Color mint = Color.FromArgb(79, 242, 185);
            Color cyan = Color.FromArgb(0, 229, 255);
            Color panel = Color.FromArgb(18, 37, 76);

            using (LinearGradientBrush bg = new LinearGradientBrush(page, Color.FromArgb(27, 0, 82), Color.FromArgb(5, 18, 42), LinearGradientMode.Vertical))
            {
                g.FillRectangle(bg, page);
            }

            DrawReportTechPattern(g, page);

            Rectangle header = new Rectangle(0, 0, page.Width, 226);
            using (LinearGradientBrush headerBrush = new LinearGradientBrush(header, Color.FromArgb(48, 0, 129), purpleDark, LinearGradientMode.Horizontal))
            {
                g.FillRectangle(headerBrush, header);
            }

            using (Image logo = LoadLogoImage())
            {
                if (logo != null)
                {
                    Rectangle logoBox = new Rectangle(70, 58, 320, 82);
                    DrawReportRoundRect(g, logoBox, 18, Color.FromArgb(30, 255, 255, 255), Color.FromArgb(90, cyan));
                    g.DrawImage(logo, FitImageRect(logo.Size, new Rectangle(92, 70, 276, 58)));
                }
            }

            using (Font title = new Font("Segoe UI Semibold", 31F, FontStyle.Bold))
            using (Font subtitle = new Font("Segoe UI", 13F, FontStyle.Regular))
            {
                DrawReportText(g, "DETALLE DEL DASHBOARD FILTRADO", title, Color.White, new RectangleF(388, 68, 770, 52), StringAlignment.Far);
                DrawReportText(g, "Datos visibles segun tecnologia, afiliacion e IP / dispositivo", subtitle, Color.FromArgb(211, 230, 255), new RectangleF(388, 126, 770, 30), StringAlignment.Far);
            }

            DrawReportBand(g, 226, "TABLA DE DISPONIBILIDAD", mint);

            Rectangle filterArea = new Rectangle(70, 340, 1100, 132);
            using (LinearGradientBrush filterBrush = new LinearGradientBrush(filterArea, Color.FromArgb(205, 13, 35, 71), Color.FromArgb(205, 26, 22, 76), LinearGradientMode.Horizontal))
            {
                using (GraphicsPath path = ReportRoundRect(filterArea, 20))
                {
                    g.FillPath(filterBrush, path);
                }
            }
            using (Pen border = new Pen(Color.FromArgb(90, cyan), 2F))
            using (GraphicsPath path = ReportRoundRect(filterArea, 20))
            {
                g.DrawPath(border, path);
            }

            DrawReportFilterTile(g, "Agrupacion", _currentDashboardGroupLabel, new Rectangle(92, 370, 205, 74), mint);
            DrawReportFilterTile(g, "Tecnologia", _currentTechnologyFilter, new Rectangle(308, 370, 205, 74), cyan);
            DrawReportFilterTile(g, "Ubicacion / sitio", _currentSubcenterFilter, new Rectangle(524, 370, 205, 74), mint);
            DrawReportFilterTile(g, "Afiliacion", _currentAffiliationFilter, new Rectangle(740, 370, 205, 74), cyan);
            DrawReportFilterTile(g, "IP / Dispositivo", String.IsNullOrWhiteSpace(_currentSearchFilter) ? "Todas" : _currentSearchFilter, new Rectangle(956, 370, 205, 74), mint);

            Rectangle table = new Rectangle(70, 530, 1100, 1000);
            DrawReportRoundRect(g, table, 0, Color.FromArgb(214, panel), Color.FromArgb(180, 255, 255, 255));

            int[] widths = new int[] { 270, 90, 100, 95, 115, 130, 145, 155 };
            string[] headers = new string[] { "Grupo", "Disp.", "Muestras", "En linea", "Sin resp.", "Dispon.", "Activo", "Ultima muestra" };
            int x = table.Left;
            int headerY = table.Top;
            int rowHeight = 48;

            using (Brush headerBg = new SolidBrush(Color.FromArgb(79, 242, 185)))
            {
                g.FillRectangle(headerBg, table.Left, table.Top, table.Width, 58);
            }

            using (Font headerFont = new Font("Segoe UI Semibold", 10F, FontStyle.Bold))
            {
                for (int i = 0; i < headers.Length; i++)
                {
                    DrawReportTableText(g, headers[i], headerFont, Color.FromArgb(8, 18, 32), new RectangleF(x + 8, headerY, widths[i] - 16, 58), i == 0 ? StringAlignment.Near : StringAlignment.Center);
                    x += widths[i];
                }
            }

            if (rows == null || rows.Count == 0)
            {
                using (Font emptyFont = new Font("Segoe UI Semibold", 18F, FontStyle.Bold))
                {
                    DrawReportText(g, "No hay datos con los filtros actuales.", emptyFont, Color.White, new RectangleF(table.Left, table.Top + 100, table.Width, 120), StringAlignment.Center);
                }
            }
            else
            {
                int count = Math.Min(rowsPerPage, rows.Count - startIndex);
                for (int i = 0; i < count; i++)
                {
                    DashboardStats stat = rows[startIndex + i];
                    DrawReportDetailRow(g, stat, table.Left, table.Top + 58 + (i * rowHeight), widths, rowHeight, i);
                }
            }

            Rectangle totalCard = new Rectangle(70, 1586, 1100, 80);
            DrawReportRoundRect(g, totalCard, 18, Color.FromArgb(205, 9, 27, 59), Color.FromArgb(90, cyan));
            using (Font totalFont = new Font("Segoe UI Semibold", 13F, FontStyle.Bold))
            using (Font pageFont = new Font("Segoe UI", 12F, FontStyle.Regular))
            {
                double totalAvailability = GetDashboardAvailability(_currentDashboardTotal);
                string totalText = totalAvailability < 0 ? "Disponibilidad general: Sin datos" : "Disponibilidad general: " + totalAvailability.ToString("0.00", CultureInfo.InvariantCulture) + "%";
                DrawReportText(g, totalText + "  |  " + _currentDashboardTotal.Samples.ToString(CultureInfo.InvariantCulture) + " muestras  |  " + _currentDashboardTotal.Devices.ToString(CultureInfo.InvariantCulture) + " dispositivos", totalFont, Color.White, new RectangleF(totalCard.Left + 24, totalCard.Top, 730, totalCard.Height), StringAlignment.Near);
                DrawReportText(g, "Detalle " + pageNumber.ToString(CultureInfo.InvariantCulture) + " de " + totalPages.ToString(CultureInfo.InvariantCulture), pageFont, Color.FromArgb(211, 230, 255), new RectangleF(totalCard.Right - 260, totalCard.Top, 230, totalCard.Height), StringAlignment.Far);
            }
        }

        private void DrawReportFilterTile(Graphics g, string label, string value, Rectangle rect, Color accent)
        {
            DrawReportRoundRect(g, rect, 14, Color.FromArgb(125, 6, 20, 45), Color.FromArgb(80, accent));
            using (Font labelFont = new Font("Segoe UI", 9F, FontStyle.Regular))
            using (Font valueFont = new Font("Segoe UI Semibold", 13F, FontStyle.Bold))
            {
                DrawReportText(g, label, labelFont, Color.FromArgb(201, 225, 255), new RectangleF(rect.Left + 14, rect.Top + 8, rect.Width - 28, 20), StringAlignment.Near);
                DrawReportText(g, String.IsNullOrWhiteSpace(value) ? "Todas" : value, valueFont, Color.White, new RectangleF(rect.Left + 14, rect.Top + 30, rect.Width - 28, 32), StringAlignment.Near);
            }
        }

        private void DrawReportDetailRow(Graphics g, DashboardStats stat, int x, int y, int[] widths, int rowHeight, int rowIndex)
        {
            Color rowColor = rowIndex % 2 == 0 ? Color.FromArgb(72, 8, 39, 76) : Color.FromArgb(96, 13, 57, 89);
            using (Brush rowBrush = new SolidBrush(rowColor))
            {
                g.FillRectangle(rowBrush, x, y, 1100, rowHeight);
            }
            using (Pen line = new Pen(Color.FromArgb(50, 255, 255, 255), 1F))
            {
                g.DrawLine(line, x, y + rowHeight, x + 1100, y + rowHeight);
            }

            double availability = GetDashboardAvailability(stat);
            string availabilityText = availability < 0 ? "S/D" : availability.ToString("0.00", CultureInfo.InvariantCulture) + "%";
            string activeText = availability < 0 ? "S/D" : FormatDuration(TimeSpan.FromHours(DashboardWindowHours() * availability / 100.0));
            string lastSample = stat.HasSample ? stat.LastSample.ToString("dd/MM/yyyy HH:mm", CultureInfo.InvariantCulture) : "-";
            Color availabilityColor = GetReportAvailabilityColor(availability);

            string[] values = new string[]
            {
                stat.Technology,
                stat.Devices.ToString(CultureInfo.InvariantCulture),
                stat.Samples.ToString(CultureInfo.InvariantCulture),
                stat.Online.ToString(CultureInfo.InvariantCulture),
                stat.Offline.ToString(CultureInfo.InvariantCulture),
                availabilityText,
                activeText,
                lastSample
            };

            using (Font rowFont = new Font("Segoe UI", 10F, FontStyle.Regular))
            using (Font boldFont = new Font("Segoe UI Semibold", 10F, FontStyle.Bold))
            {
                int cellX = x;
                for (int i = 0; i < values.Length; i++)
                {
                    Color textColor = i == 5 ? availabilityColor : Color.White;
                    Font font = (i == 0 || i == 5) ? boldFont : rowFont;
                    StringAlignment alignment = i == 0 ? StringAlignment.Near : StringAlignment.Center;
                    DrawReportTableText(g, values[i], font, textColor, new RectangleF(cellX + 8, y, widths[i] - 16, rowHeight), alignment);
                    cellX += widths[i];
                }
            }
        }

        private Color GetReportAvailabilityColor(double availability)
        {
            if (availability < 0)
            {
                return Color.FromArgb(170, 190, 210);
            }
            if (availability >= 98.0)
            {
                return Color.FromArgb(79, 242, 185);
            }
            if (availability >= 90.0)
            {
                return Color.FromArgb(255, 206, 96);
            }

            return Color.FromArgb(255, 86, 116);
        }

        private void DrawReportTableText(Graphics g, string text, Font font, Color color, RectangleF bounds, StringAlignment alignment)
        {
            using (Brush brush = new SolidBrush(color))
            using (StringFormat format = new StringFormat())
            {
                format.Alignment = alignment;
                format.LineAlignment = StringAlignment.Center;
                format.Trimming = StringTrimming.EllipsisCharacter;
                format.FormatFlags = StringFormatFlags.NoWrap;
                g.DrawString(text == null ? "" : text, font, brush, bounds, format);
            }
        }

        private void DrawReportTechPattern(Graphics g, Rectangle page)
        {
            using (Pen pen = new Pen(Color.FromArgb(34, 0, 229, 255), 1F))
            {
                for (int x = 0; x < page.Width; x += 58)
                {
                    g.DrawLine(pen, x, 0, x, page.Height);
                }
                for (int y = 0; y < page.Height; y += 58)
                {
                    g.DrawLine(pen, 0, y, page.Width, y);
                }
            }

            DrawReportDiamond(g, 260, 128, 170, Color.FromArgb(45, 0, 229, 255));
            DrawReportDiamond(g, 990, 120, 220, Color.FromArgb(40, 219, 60, 255));
            DrawReportDiamond(g, 1040, 1510, 260, Color.FromArgb(35, 0, 229, 255));
            DrawReportDiamond(g, 120, 1510, 210, Color.FromArgb(30, 219, 60, 255));
        }

        private void DrawReportDiamond(Graphics g, int centerX, int centerY, int size, Color color)
        {
            Point[] points = new Point[]
            {
                new Point(centerX, centerY - (size / 2)),
                new Point(centerX + (size / 2), centerY),
                new Point(centerX, centerY + (size / 2)),
                new Point(centerX - (size / 2), centerY)
            };
            using (Brush brush = new SolidBrush(color))
            {
                g.FillPolygon(brush, points);
            }
        }

        private void DrawReportBand(Graphics g, int y, string text, Color color)
        {
            Rectangle band = new Rectangle(0, y, 1240, 76);
            using (Brush brush = new SolidBrush(color))
            {
                g.FillRectangle(brush, band);
            }
            using (Font font = new Font("Segoe UI Semibold", 23F, FontStyle.Bold))
            {
                DrawReportText(g, text, font, Color.FromArgb(8, 18, 32), band, StringAlignment.Center);
            }
        }

        private void DrawReportDonutMetric(Graphics g, Rectangle rect, double percent, string label, Color fill, Color track)
        {
            using (Brush trackBrush = new SolidBrush(track))
            {
                g.FillPie(trackBrush, rect, -90, 360);
            }
            if (percent >= 0)
            {
                using (Brush fillBrush = new SolidBrush(fill))
                {
                    g.FillPie(fillBrush, rect, -90, (float)(360.0 * Math.Min(100.0, percent) / 100.0));
                }
            }

            Rectangle hole = rect;
            hole.Inflate(-54, -54);
            using (Brush holeBrush = new SolidBrush(Color.FromArgb(43, 0, 111)))
            {
                g.FillEllipse(holeBrush, hole);
            }

            using (Font valueFont = new Font("Segoe UI Semibold", 28F, FontStyle.Bold))
            using (Font labelFont = new Font("Segoe UI", 13F, FontStyle.Regular))
            {
                string value = percent < 0 ? "S/D" : percent.ToString("0", CultureInfo.InvariantCulture) + "%";
                DrawReportText(g, value, valueFont, Color.White, hole, StringAlignment.Center);
                DrawReportText(g, label, labelFont, Color.White, new RectangleF(rect.Left - 32, rect.Bottom + 18, rect.Width + 64, 48), StringAlignment.Center);
            }
        }

        private void DrawReportInfoLine(Graphics g, string label, string value, int x, int y, int width, Font labelFont, Font valueFont)
        {
            DrawReportText(g, label, labelFont, Color.FromArgb(218, 235, 255), new RectangleF(x, y, width / 2, 28), StringAlignment.Near);
            DrawReportText(g, value, valueFont, Color.White, new RectangleF(x + (width / 2), y, width / 2, 28), StringAlignment.Far);
        }

        private void DrawReportAvailabilityRows(Graphics g, Rectangle rect, Color mint, Color cyan)
        {
            DrawReportRoundRect(g, rect, 0, Color.FromArgb(80, 38, 0, 106), Color.White);
            Rectangle inner = rect;
            inner.Inflate(-34, -28);

            List<DashboardStats> rows = GetDashboardReportRows();

            using (Font headerFont = new Font("Segoe UI Semibold", 16F, FontStyle.Bold))
            using (Font rowFont = new Font("Segoe UI Semibold", 13F, FontStyle.Bold))
            using (Font metaFont = new Font("Segoe UI", 10F, FontStyle.Regular))
            {
                DrawReportText(g, "Grupo", headerFont, mint, new RectangleF(inner.Left, inner.Top, 300, 30), StringAlignment.Near);
                DrawReportText(g, "Disponibilidad", headerFont, mint, new RectangleF(inner.Right - 230, inner.Top, 230, 30), StringAlignment.Far);

                if (rows.Count == 0)
                {
                    DrawReportText(g, "No hay datos con los filtros actuales.", rowFont, Color.White, inner, StringAlignment.Center);
                    return;
                }

                int maxRows = Math.Min(rows.Count, 6);
                int y = inner.Top + 54;
                for (int i = 0; i < maxRows; i++)
                {
                    DashboardStats stat = rows[i];
                    double availability = GetDashboardAvailability(stat);
                    string percentage = availability < 0 ? "Sin datos" : availability.ToString("0.00", CultureInfo.InvariantCulture) + "%";
                    string active = availability < 0 ? "Sin datos" : FormatDuration(TimeSpan.FromHours(DashboardWindowHours() * availability / 100.0)) + " activo";

                    DrawReportText(g, stat.Technology, rowFont, Color.White, new RectangleF(inner.Left, y, 360, 25), StringAlignment.Near);
                    DrawReportText(g, stat.Devices.ToString(CultureInfo.InvariantCulture) + " dispositivos  |  " + stat.Samples.ToString(CultureInfo.InvariantCulture) + " muestras", metaFont, Color.FromArgb(210, 230, 255), new RectangleF(inner.Left, y + 26, 360, 22), StringAlignment.Near);

                    Rectangle bar = new Rectangle(inner.Left + 390, y + 18, inner.Width - 600, 16);
                    DrawReportBar(g, bar, availability < 0 ? 0 : availability, mint, Color.FromArgb(127, 95, 255));
                    DrawReportText(g, percentage, rowFont, cyan, new RectangleF(inner.Right - 210, y - 2, 210, 25), StringAlignment.Far);
                    DrawReportText(g, active, metaFont, Color.FromArgb(210, 230, 255), new RectangleF(inner.Right - 210, y + 26, 210, 22), StringAlignment.Far);

                    y += 48;
                }

                if (rows.Count > maxRows)
                {
                    DrawReportText(g, "Mostrando " + maxRows.ToString(CultureInfo.InvariantCulture) + " de " + rows.Count.ToString(CultureInfo.InvariantCulture) + " grupos filtrados.", metaFont, Color.FromArgb(210, 230, 255), new RectangleF(inner.Left, inner.Bottom - 24, inner.Width, 22), StringAlignment.Center);
                }
            }
        }

        private List<DashboardStats> GetDashboardReportRows()
        {
            List<DashboardStats> rows = new List<DashboardStats>();
            if (_currentDashboardStats == null)
            {
                return rows;
            }

            for (int i = 0; i < _currentDashboardStats.Count; i++)
            {
                DashboardStats stat = _currentDashboardStats[i];
                if (stat.Devices > 0 || stat.Samples > 0)
                {
                    rows.Add(stat);
                }
            }

            return rows;
        }

        private void DrawReportBar(Graphics g, Rectangle rect, double percent, Color start, Color end)
        {
            using (GraphicsPath path = ReportRoundRect(rect, 8))
            using (Brush bg = new SolidBrush(Color.FromArgb(70, 255, 255, 255)))
            {
                g.FillPath(bg, path);
            }

            int fillWidth = (int)Math.Round(rect.Width * Math.Max(0.0, Math.Min(100.0, percent)) / 100.0);
            if (fillWidth > 0)
            {
                Rectangle fill = new Rectangle(rect.Left, rect.Top, fillWidth, rect.Height);
                using (GraphicsPath path = ReportRoundRect(fill, 8))
                using (LinearGradientBrush brush = new LinearGradientBrush(fill, start, end, LinearGradientMode.Horizontal))
                {
                    g.FillPath(brush, path);
                }
            }
        }

        private void DrawReportRoundRect(Graphics g, Rectangle rect, int radius, Color fill, Color border)
        {
            using (GraphicsPath path = radius <= 0 ? RectanglePath(rect) : ReportRoundRect(rect, radius))
            using (Brush brush = new SolidBrush(fill))
            {
                g.FillPath(brush, path);
            }
            using (GraphicsPath path = radius <= 0 ? RectanglePath(rect) : ReportRoundRect(rect, radius))
            using (Pen pen = new Pen(border, 2.2F))
            {
                g.DrawPath(pen, path);
            }
        }

        private GraphicsPath RectanglePath(Rectangle rect)
        {
            GraphicsPath path = new GraphicsPath();
            path.AddRectangle(rect);
            return path;
        }

        private GraphicsPath ReportRoundRect(Rectangle rect, int radius)
        {
            GraphicsPath path = new GraphicsPath();
            radius = Math.Max(1, Math.Min(radius, Math.Min(rect.Width, rect.Height) / 2));
            int diameter = radius * 2;
            Rectangle arc = new Rectangle(rect.Left, rect.Top, diameter, diameter);
            path.AddArc(arc, 180, 90);
            arc.X = rect.Right - diameter;
            path.AddArc(arc, 270, 90);
            arc.Y = rect.Bottom - diameter;
            path.AddArc(arc, 0, 90);
            arc.X = rect.Left;
            path.AddArc(arc, 90, 90);
            path.CloseFigure();
            return path;
        }

        private void DrawReportText(Graphics g, string text, Font font, Color color, RectangleF bounds, StringAlignment alignment)
        {
            using (Brush brush = new SolidBrush(color))
            using (StringFormat format = new StringFormat())
            {
                format.Alignment = alignment;
                format.LineAlignment = StringAlignment.Center;
                format.Trimming = StringTrimming.EllipsisCharacter;
                g.DrawString(text == null ? "" : text, font, brush, bounds, format);
            }
        }

        private Rectangle FitImageRect(Size imageSize, Rectangle bounds)
        {
            if (imageSize.Width <= 0 || imageSize.Height <= 0)
            {
                return bounds;
            }

            float scale = Math.Min(bounds.Width / (float)imageSize.Width, bounds.Height / (float)imageSize.Height);
            int width = (int)Math.Round(imageSize.Width * scale);
            int height = (int)Math.Round(imageSize.Height * scale);
            return new Rectangle(
                bounds.Left + ((bounds.Width - width) / 2),
                bounds.Top + ((bounds.Height - height) / 2),
                width,
                height);
        }

        private void WriteMultiPagePdf(string path, List<byte[]> jpegPages, int imageWidth, int imageHeight)
        {
            if (jpegPages == null || jpegPages.Count == 0)
            {
                throw new InvalidOperationException("No hay paginas para generar el PDF.");
            }

            float pageWidth = imageWidth >= imageHeight ? 842F : 595F;
            float pageHeight = imageWidth >= imageHeight ? 595F : 842F;
            string content = "q\n" + pageWidth.ToString("0.###", CultureInfo.InvariantCulture) + " 0 0 " + pageHeight.ToString("0.###", CultureInfo.InvariantCulture) + " 0 0 cm\n/Im0 Do\nQ\n";
            byte[] contentBytes = Encoding.ASCII.GetBytes(content);
            int pageCount = jpegPages.Count;
            int maxObject = 2 + (pageCount * 3);

            using (FileStream stream = new FileStream(path, FileMode.Create, FileAccess.Write))
            {
                long[] offsets = new long[maxObject + 1];
                WritePdfAscii(stream, "%PDF-1.4\n% ping_scan\n");

                offsets[1] = stream.Position;
                WritePdfAscii(stream, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

                StringBuilder kids = new StringBuilder();
                for (int i = 0; i < pageCount; i++)
                {
                    kids.Append((3 + (i * 3)).ToString(CultureInfo.InvariantCulture));
                    kids.Append(" 0 R ");
                }

                offsets[2] = stream.Position;
                WritePdfAscii(stream, "2 0 obj\n<< /Type /Pages /Kids [" + kids.ToString() + "] /Count " + pageCount.ToString(CultureInfo.InvariantCulture) + " >>\nendobj\n");

                for (int i = 0; i < pageCount; i++)
                {
                    int pageObject = 3 + (i * 3);
                    int imageObject = pageObject + 1;
                    int contentObject = pageObject + 2;
                    byte[] jpegBytes = jpegPages[i];

                    offsets[pageObject] = stream.Position;
                    WritePdfAscii(stream, pageObject.ToString(CultureInfo.InvariantCulture) + " 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 " + pageWidth.ToString("0.###", CultureInfo.InvariantCulture) + " " + pageHeight.ToString("0.###", CultureInfo.InvariantCulture) + "] /Resources << /XObject << /Im0 " + imageObject.ToString(CultureInfo.InvariantCulture) + " 0 R >> >> /Contents " + contentObject.ToString(CultureInfo.InvariantCulture) + " 0 R >>\nendobj\n");

                    offsets[imageObject] = stream.Position;
                    WritePdfAscii(stream, imageObject.ToString(CultureInfo.InvariantCulture) + " 0 obj\n<< /Type /XObject /Subtype /Image /Width " + imageWidth.ToString(CultureInfo.InvariantCulture) + " /Height " + imageHeight.ToString(CultureInfo.InvariantCulture) + " /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length " + jpegBytes.Length.ToString(CultureInfo.InvariantCulture) + " >>\nstream\n");
                    stream.Write(jpegBytes, 0, jpegBytes.Length);
                    WritePdfAscii(stream, "\nendstream\nendobj\n");

                    offsets[contentObject] = stream.Position;
                    WritePdfAscii(stream, contentObject.ToString(CultureInfo.InvariantCulture) + " 0 obj\n<< /Length " + contentBytes.Length.ToString(CultureInfo.InvariantCulture) + " >>\nstream\n");
                    stream.Write(contentBytes, 0, contentBytes.Length);
                    WritePdfAscii(stream, "endstream\nendobj\n");
                }

                long xref = stream.Position;
                WritePdfAscii(stream, "xref\n0 " + (maxObject + 1).ToString(CultureInfo.InvariantCulture) + "\n0000000000 65535 f \n");
                for (int i = 1; i <= maxObject; i++)
                {
                    WritePdfAscii(stream, offsets[i].ToString("0000000000", CultureInfo.InvariantCulture) + " 00000 n \n");
                }
                WritePdfAscii(stream, "trailer\n<< /Size " + (maxObject + 1).ToString(CultureInfo.InvariantCulture) + " /Root 1 0 R >>\nstartxref\n" + xref.ToString(CultureInfo.InvariantCulture) + "\n%%EOF\n");
            }
        }

        private void WritePdfAscii(Stream stream, string text)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(text);
            stream.Write(bytes, 0, bytes.Length);
        }

        private double GetDashboardAvailability(DashboardStats stat)
        {
            if (stat == null || stat.Samples == 0)
            {
                return -1;
            }

            return stat.Online * 100.0 / stat.Samples;
        }

        private double DashboardWindowHours()
        {
            return Math.Max(1, _dashboardWindowDays) * 24.0;
        }

        private void AddDashboardRow(string technology, DashboardStats stat, bool totalRow)
        {
            double availability = stat.Samples == 0 ? -1 : (stat.Online * 100.0 / stat.Samples);
            string availabilityText = availability < 0
                ? "Sin datos"
                : availability.ToString("0.00", CultureInfo.InvariantCulture) + " %";
            string activeText = availability < 0
                ? "Sin datos"
                : FormatDuration(TimeSpan.FromHours(DashboardWindowHours() * availability / 100.0)) + " de " + DashboardWindowHours().ToString("0", CultureInfo.InvariantCulture) + " h";
            string lastSample = stat.HasSample
                ? stat.LastSample.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
                : "";

            int rowIndex = _dashboardGrid.Rows.Add(
                technology,
                stat.Devices.ToString(CultureInfo.InvariantCulture),
                stat.Samples.ToString(CultureInfo.InvariantCulture),
                stat.Online.ToString(CultureInfo.InvariantCulture),
                stat.Offline.ToString(CultureInfo.InvariantCulture),
                availabilityText,
                activeText,
                lastSample);

            DataGridViewRow row = _dashboardGrid.Rows[rowIndex];
            row.Cells["Availability"].Tag = availability;
            ApplyDashboardRowStyle(row, availability, totalRow);
        }

        private string FormatDuration(TimeSpan value)
        {
            int hours = (int)Math.Floor(value.TotalHours);
            int minutes = value.Minutes;
            return hours.ToString(CultureInfo.InvariantCulture)
                + " h "
                + minutes.ToString("00", CultureInfo.InvariantCulture)
                + " min";
        }

        private void ApplyDashboardRowStyle(DataGridViewRow row, double availability, bool totalRow)
        {
            Color back = Surface;
            Color fore = TextMain;

            if (availability >= 95)
            {
                back = SuccessBack;
                fore = Color.FromArgb(209, 250, 229);
            }
            else if (availability >= 85)
            {
                back = WarningBack;
                fore = Color.FromArgb(254, 243, 199);
            }
            else if (availability >= 0)
            {
                back = DangerBack;
                fore = Color.FromArgb(254, 226, 226);
            }
            else
            {
                back = SurfaceAlt;
                fore = TextMuted;
            }

            row.DefaultCellStyle.BackColor = back;
            row.DefaultCellStyle.ForeColor = fore;
            row.DefaultCellStyle.SelectionBackColor = Color.FromArgb(14, 116, 144);
            row.DefaultCellStyle.SelectionForeColor = Color.White;
            if (totalRow && row.DefaultCellStyle.Font == null)
            {
                row.DefaultCellStyle.Font = new Font(_dashboardGrid.Font, FontStyle.Bold);
            }
        }

        private void DashboardCellPainting(object sender, DataGridViewCellPaintingEventArgs e)
        {
            if (e.RowIndex < 0 || e.ColumnIndex < 0 || _dashboardGrid.Columns[e.ColumnIndex].Name != "Availability")
            {
                return;
            }

            e.Handled = true;
            e.PaintBackground(e.ClipBounds, true);

            object tag = _dashboardGrid.Rows[e.RowIndex].Cells[e.ColumnIndex].Tag;
            double availability = tag is double ? (double)tag : -1;
            Rectangle bounds = e.CellBounds;
            Rectangle bar = new Rectangle(bounds.Left + 8, bounds.Top + 8, Math.Max(10, bounds.Width - 16), Math.Max(10, bounds.Height - 16));

            using (Brush baseBrush = new SolidBrush(Color.FromArgb(51, 65, 85)))
            {
                e.Graphics.FillRectangle(baseBrush, bar);
            }

            if (availability >= 0)
            {
                int fillWidth = (int)Math.Round(bar.Width * Math.Min(100.0, Math.Max(0.0, availability)) / 100.0);
                Color fillColor = availability >= 95
                    ? Color.FromArgb(34, 197, 94)
                    : availability >= 85
                        ? Color.FromArgb(245, 158, 11)
                        : Color.FromArgb(239, 68, 68);

                using (Brush fillBrush = new SolidBrush(fillColor))
                {
                    e.Graphics.FillRectangle(fillBrush, new Rectangle(bar.Left, bar.Top, fillWidth, bar.Height));
                }
            }

            using (Pen borderPen = new Pen(Border))
            {
                e.Graphics.DrawRectangle(borderPen, bar);
            }

            string text = Convert.ToString(e.FormattedValue, CultureInfo.InvariantCulture);
            TextRenderer.DrawText(
                e.Graphics,
                text,
                e.CellStyle.Font,
                bounds,
                TextMain,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
        }

        private void DashboardCellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            if (e.RowIndex < 0 || e.RowIndex >= _dashboardGrid.Rows.Count)
            {
                return;
            }

            DataGridViewRow row = _dashboardGrid.Rows[e.RowIndex];
            object tag = row.Cells["Availability"].Tag;
            double availability = tag is double ? (double)tag : -1;
            bool totalRow = Convert.ToString(row.Cells["Technology"].Value, CultureInfo.InvariantCulture) == "TOTAL";
            ApplyDashboardRowStyle(row, availability, totalRow);
        }

        private void LoadDevices()
        {
            if (!File.Exists(_dataPath))
            {
                return;
            }

            XmlDocument doc = new XmlDocument();
            doc.Load(_dataPath);
            XmlNodeList nodes = doc.SelectNodes("/devices/device");
            if (nodes == null)
            {
                return;
            }

            _devices.Clear();
            foreach (XmlNode node in nodes)
            {
                DeviceRecord record = new DeviceRecord();
                record.Name = ReadAttribute(node, "name");
                record.Ip = ReadAttribute(node, "ip");
                record.Type = NormalizeType(ReadAttribute(node, "type"));
                record.Subcenter = NormalizeSubcenter(ReadAttribute(node, "subcenter"));
                record.Affiliation = NormalizeAffiliation(ReadAttribute(node, "affiliation"), record.Name);
                string technology = ReadAttribute(node, "technology");
                if (String.IsNullOrWhiteSpace(technology))
                {
                    technology = ReadAttribute(node, "notes");
                }
                record.Notes = NormalizeTechnologyLabel(technology);

                int failures;
                if (Int32.TryParse(ReadAttribute(node, "failures"), out failures))
                {
                    record.Failures = failures;
                }

                _devices.Add(record);
            }
        }

        private string ReadAttribute(XmlNode node, string name)
        {
            XmlAttribute attribute = node.Attributes == null ? null : node.Attributes[name];
            return attribute == null ? "" : attribute.Value;
        }

        private void SaveDevices()
        {
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            settings.Encoding = Encoding.UTF8;

            using (XmlWriter writer = XmlWriter.Create(_dataPath, settings))
            {
                writer.WriteStartDocument();
                writer.WriteStartElement("devices");
                for (int i = 0; i < _devices.Count; i++)
                {
                    DeviceRecord record = _devices[i];
                    writer.WriteStartElement("device");
                    writer.WriteAttributeString("name", record.Name);
                    writer.WriteAttributeString("ip", record.Ip);
                    writer.WriteAttributeString("type", record.Type);
                    writer.WriteAttributeString("subcenter", GetRecordSubcenter(record));
                    writer.WriteAttributeString("affiliation", GetRecordAffiliation(record));
                    writer.WriteAttributeString("technology", NormalizeTechnologyLabel(record.Notes));
                    writer.WriteAttributeString("notes", NormalizeTechnologyLabel(record.Notes));
                    writer.WriteAttributeString("failures", record.Failures.ToString(CultureInfo.InvariantCulture));
                    writer.WriteEndElement();
                }

                writer.WriteEndElement();
                writer.WriteEndDocument();
            }
        }

        private void ExportCsv()
        {
            using (SaveFileDialog dialog = new SaveFileDialog())
            {
                dialog.Title = "Exportar resultados";
                dialog.Filter = "CSV (*.csv)|*.csv";
                dialog.FileName = "ping-monitor-resultados.csv";
                if (dialog.ShowDialog(this) != DialogResult.OK)
                {
                    return;
                }

                using (StreamWriter writer = new StreamWriter(dialog.FileName, false, Encoding.UTF8))
                {
                    writer.WriteLine("Nombre,IP,Tipo,Ubicacion/Sitio,Afiliacion,Estado,Latencia,Ultima revision,Fallos,Tecnologia");
                    for (int i = 0; i < _devices.Count; i++)
                    {
                        DeviceRecord record = _devices[i];
                        writer.WriteLine(
                            Csv(record.Name) + ","
                            + Csv(record.Ip) + ","
                            + Csv(record.Type) + ","
                            + Csv(GetRecordSubcenter(record)) + ","
                            + Csv(GetRecordAffiliation(record)) + ","
                            + Csv(record.Status) + ","
                            + Csv(record.Latency) + ","
                            + Csv(record.LastCheck) + ","
                            + Csv(record.Failures.ToString(CultureInfo.InvariantCulture)) + ","
                            + Csv(NormalizeTechnologyLabel(record.Notes)));
                    }
                }

                SetStatus("Resultados exportados.");
            }
        }

        private string Csv(string value)
        {
            string text = value == null ? "" : value;
            bool quote = text.Contains(",") || text.Contains("\"") || text.Contains("\r") || text.Contains("\n");
            text = text.Replace("\"", "\"\"");
            return quote ? "\"" + text + "\"" : text;
        }

        private sealed class PingHistoryEntry
        {
            public DateTime CheckedAt;
            public string Ip;
            public string Type;
            public string Subcenter;
            public string Affiliation;
            public bool Success;
            public int LatencyMs;
        }

        private sealed class DashboardStats
        {
            public string Technology;
            public string GroupKind;
            public int Devices;
            public int Samples;
            public int Online;
            public int Offline;
            public bool HasSample;
            public DateTime FirstSample;
            public DateTime LastSample;
        }

        private sealed class DeviceManagementDialog : Form
        {
            private const int MaxVisibleRows = 350;

            private sealed class DeviceSearchEntry
            {
                public DeviceRecord Record;
                public string Key;
            }

            private readonly BindingList<DeviceRecord> _devices;
            private readonly List<string> _technologies;
            private readonly List<string> _subcenters;
            private readonly List<string> _affiliations;
            private readonly bool _englishUi;
            private readonly bool _canDeleteAll;
            private readonly List<DeviceSearchEntry> _searchIndex;
            private readonly System.Windows.Forms.Timer _filterTimer;
            private TextBox _searchText;
            private DataGridView _devicesGrid;
            private Button _importButton;
            private Button _newButton;
            private Button _editButton;
            private Button _deleteButton;
            private Button _deleteAllButton;
            private Label _statusLabel;

            public Func<bool> ImportDevicesRequested { get; set; }
            public Func<bool> DeleteAllDevicesRequested { get; set; }
            public Func<DeviceRecord, bool> AddDeviceRequested { get; set; }
            public Func<DeviceRecord, DeviceRecord, bool> EditDeviceRequested { get; set; }
            public Func<DeviceRecord, bool> DeleteDeviceRequested { get; set; }

            public DeviceManagementDialog(BindingList<DeviceRecord> devices, List<string> technologies, List<string> subcenters, List<string> affiliations, bool englishUi, bool canDeleteAll)
            {
                _devices = devices == null ? new BindingList<DeviceRecord>() : devices;
                _technologies = technologies == null ? new List<string>() : technologies;
                _subcenters = subcenters == null ? new List<string>() : subcenters;
                _affiliations = affiliations == null ? new List<string>() : affiliations;
                _englishUi = englishUi;
                _canDeleteAll = canDeleteAll;
                _searchIndex = new List<DeviceSearchEntry>();
                _filterTimer = new System.Windows.Forms.Timer();
                _filterTimer.Interval = 180;
                _filterTimer.Tick += delegate
                {
                    _filterTimer.Stop();
                    RefreshRows(null);
                };

                Text = UiText.Pick(_englishUi, "Gestionar dispositivos", "Manage devices");
                FormBorderStyle = FormBorderStyle.FixedDialog;
                StartPosition = FormStartPosition.CenterParent;
                ControlBox = false;
                MaximizeBox = false;
                MinimizeBox = false;
                ShowInTaskbar = false;
                BackColor = AppBackground;
                ForeColor = TextMain;
                Font = new Font("Segoe UI", 9F);
                ClientSize = new Size(900, 560);

                BuildSearchIndex();
                BuildInterface();
                RefreshRows(null);
            }

            protected override void OnFormClosed(FormClosedEventArgs e)
            {
                if (_filterTimer != null)
                {
                    _filterTimer.Stop();
                    _filterTimer.Dispose();
                }

                base.OnFormClosed(e);
            }

            private void BuildInterface()
            {
                Panel header = new Panel();
                header.BackColor = Surface;
                TechStyle.AttachSurface(header, Color.FromArgb(13, 31, 58), Color.FromArgb(8, 18, 38), AccentSoft, true);
                header.SetBounds(0, 0, ClientSize.Width, 86);
                header.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
                Controls.Add(header);

                Label title = new Label();
                title.Text = UiText.Pick(_englishUi, "Gestionar dispositivos", "Manage devices");
                title.AutoSize = false;
                title.Font = new Font("Segoe UI Semibold", 16F, FontStyle.Bold);
                title.ForeColor = TextMain;
                title.BackColor = Color.Transparent;
                title.SetBounds(28, 16, 420, 32);
                header.Controls.Add(title);

                Label subtitle = new Label();
                subtitle.Text = UiText.Pick(_englishUi, "Crear, editar y retirar registros del inventario", "Create, edit and retire inventory records");
                subtitle.AutoSize = false;
                subtitle.ForeColor = TextMuted;
                subtitle.BackColor = Color.Transparent;
                subtitle.SetBounds(30, 50, 520, 22);
                header.Controls.Add(subtitle);
                TechStyle.MakeChromeTransparent(header);

                Label searchLabel = new Label();
                searchLabel.Text = UiText.Pick(_englishUi, "Buscar dispositivo o IP", "Search device or IP");
                searchLabel.AutoSize = false;
                searchLabel.ForeColor = TextMuted;
                searchLabel.BackColor = Color.Transparent;
                searchLabel.SetBounds(28, 106, 160, 22);
                Controls.Add(searchLabel);

                _searchText = new TextBox();
                _searchText.BackColor = SurfaceSoft;
                _searchText.ForeColor = TextMain;
                _searchText.BorderStyle = BorderStyle.FixedSingle;
                _searchText.SetBounds(190, 103, 360, 24);
                _searchText.TextChanged += delegate { ScheduleRefreshRows(); };
                Controls.Add(_searchText);

                _statusLabel = new Label();
                _statusLabel.AutoSize = false;
                _statusLabel.ForeColor = TextMuted;
                _statusLabel.BackColor = Color.Transparent;
                _statusLabel.SetBounds(570, 106, 300, 22);
                _statusLabel.TextAlign = ContentAlignment.MiddleRight;
                Controls.Add(_statusLabel);

                _devicesGrid = new DataGridView();
                TechStyle.EnableDoubleBuffer(_devicesGrid);
                _devicesGrid.SetBounds(28, 144, 844, 326);
                _devicesGrid.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
                _devicesGrid.BackgroundColor = AppBackground;
                _devicesGrid.BorderStyle = BorderStyle.None;
                _devicesGrid.AllowUserToAddRows = false;
                _devicesGrid.AllowUserToDeleteRows = false;
                _devicesGrid.AllowUserToResizeRows = false;
                _devicesGrid.ReadOnly = true;
                _devicesGrid.MultiSelect = false;
                _devicesGrid.RowHeadersVisible = false;
                _devicesGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
                _devicesGrid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
                _devicesGrid.EnableHeadersVisualStyles = false;
                _devicesGrid.GridColor = Border;
                _devicesGrid.DefaultCellStyle.BackColor = Surface;
                _devicesGrid.DefaultCellStyle.ForeColor = TextMain;
                _devicesGrid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(14, 116, 144);
                _devicesGrid.DefaultCellStyle.SelectionForeColor = Color.White;
                _devicesGrid.AlternatingRowsDefaultCellStyle.BackColor = SurfaceAlt;
                _devicesGrid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(2, 6, 23);
                _devicesGrid.ColumnHeadersDefaultCellStyle.ForeColor = TextMain;
                _devicesGrid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold);
                _devicesGrid.ColumnHeadersHeight = 32;
                _devicesGrid.RowTemplate.Height = 28;
                _devicesGrid.SelectionChanged += delegate { UpdateButtonState(); };
                _devicesGrid.CellDoubleClick += delegate { EditSelectedDevice(); };
                Controls.Add(_devicesGrid);

                AddGridColumn("Device", UiText.Pick(_englishUi, "Dispositivo", "Device"), 210);
                AddGridColumn("Ip", "IP", 125);
                AddGridColumn("Type", UiText.Pick(_englishUi, "Tipo", "Type"), 95);
                AddGridColumn("Location", UiText.Pick(_englishUi, "Ubicacion / sitio", "Location / site"), 150);
                AddGridColumn("Affiliation", UiText.Pick(_englishUi, "Afiliacion", "Affiliation"), 110);
                AddGridColumn("Technology", UiText.Pick(_englishUi, "Tecnologia", "Technology"), 120);

                _importButton = MakeDialogButton(UiText.Pick(_englishUi, "Importar listado", "Import list"), SurfaceSoft, TextMain);
                _importButton.SetBounds(122, 498, 132, 34);
                _importButton.Click += delegate { ImportDevices(); };
                Controls.Add(_importButton);

                _newButton = MakeDialogButton(UiText.Pick(_englishUi, "Registrar nuevo", "New record"), AccentSoft, Color.FromArgb(2, 6, 23));
                _newButton.SetBounds(264, 498, 132, 34);
                _newButton.Click += delegate { CreateDevice(); };
                Controls.Add(_newButton);

                _editButton = MakeDialogButton(UiText.Pick(_englishUi, "Editar", "Edit"), SurfaceSoft, TextMain);
                _editButton.SetBounds(406, 498, 104, 34);
                _editButton.Click += delegate { EditSelectedDevice(); };
                Controls.Add(_editButton);

                _deleteButton = MakeDialogButton(UiText.Pick(_englishUi, "Eliminar", "Delete"), DangerBack, TextMain);
                _deleteButton.SetBounds(520, 498, 104, 34);
                _deleteButton.Click += delegate { DeleteSelectedDevice(); };
                Controls.Add(_deleteButton);

                _deleteAllButton = MakeDialogButton(UiText.Pick(_englishUi, "Eliminar todo", "Delete all"), DangerBack, TextMain);
                _deleteAllButton.SetBounds(634, 498, 124, 34);
                _deleteAllButton.Enabled = _canDeleteAll;
                _deleteAllButton.Click += delegate { DeleteAllDevices(); };
                Controls.Add(_deleteAllButton);

                Button closeButton = MakeDialogButton(UiText.Pick(_englishUi, "Cerrar", "Close"), SurfaceSoft, TextMain);
                closeButton.SetBounds(768, 498, 104, 34);
                closeButton.DialogResult = DialogResult.OK;
                Controls.Add(closeButton);

                UpdateButtonState();
            }

            private Button MakeDialogButton(string text, Color back, Color fore)
            {
                MaterialButton button = new MaterialButton();
                button.Text = text;
                button.BackColor = back;
                button.ForeColor = fore;
                button.Width = 110;
                button.Height = 32;
                button.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
                return button;
            }

            private void AddGridColumn(string name, string header, int width)
            {
                DataGridViewTextBoxColumn column = new DataGridViewTextBoxColumn();
                column.Name = name;
                column.HeaderText = header;
                column.Width = width;
                column.FillWeight = width;
                column.SortMode = DataGridViewColumnSortMode.NotSortable;
                _devicesGrid.Columns.Add(column);
            }

            private void BuildSearchIndex()
            {
                _searchIndex.Clear();
                for (int i = 0; i < _devices.Count; i++)
                {
                    DeviceRecord record = _devices[i];
                    _searchIndex.Add(new DeviceSearchEntry
                    {
                        Record = record,
                        Key = NormalizeSearch(record == null ? "" : record.Name)
                            + "\n"
                            + NormalizeSearch(record == null ? "" : record.Ip)
                    });
                }
            }

            private void ScheduleRefreshRows()
            {
                if (_filterTimer == null)
                {
                    RefreshRows(null);
                    return;
                }

                _filterTimer.Stop();
                _filterTimer.Start();
            }

            private void RefreshRows(DeviceRecord preferredSelection)
            {
                if (_devicesGrid == null)
                {
                    return;
                }

                DeviceRecord selected = preferredSelection == null ? SelectedDevice() : preferredSelection;
                string filter = NormalizeSearch(_searchText == null ? "" : _searchText.Text);
                int matches = 0;
                int displayed = 0;
                _devicesGrid.SuspendLayout();
                try
                {
                    _devicesGrid.Rows.Clear();

                    for (int i = 0; i < _searchIndex.Count; i++)
                    {
                        DeviceSearchEntry entry = _searchIndex[i];
                        if (!MatchesFilter(entry, filter))
                        {
                            continue;
                        }

                        matches++;
                        if (displayed >= MaxVisibleRows)
                        {
                            continue;
                        }

                        DeviceRecord record = entry.Record;
                        int rowIndex = _devicesGrid.Rows.Add(
                            record.Name,
                            record.Ip,
                            record.Type,
                            record.Subcenter,
                            record.Affiliation,
                            record.Notes);
                        DataGridViewRow row = _devicesGrid.Rows[rowIndex];
                        row.Tag = record;
                        displayed++;
                    }
                }
                finally
                {
                    _devicesGrid.ResumeLayout();
                }

                SelectDevice(selected);
                _statusLabel.Text = displayed == matches
                    ? displayed.ToString(CultureInfo.InvariantCulture) + UiText.Pick(_englishUi, " registros visibles", " visible records")
                    : displayed.ToString(CultureInfo.InvariantCulture)
                        + " / "
                        + matches.ToString(CultureInfo.InvariantCulture)
                        + UiText.Pick(_englishUi, " coincidencias", " matches");
                UpdateButtonState();
            }

            private bool MatchesFilter(DeviceSearchEntry entry, string filter)
            {
                if (entry == null || entry.Record == null)
                {
                    return false;
                }

                if (String.IsNullOrWhiteSpace(filter))
                {
                    return true;
                }

                return entry.Key.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0;
            }

            private string NormalizeSearch(string value)
            {
                return (value == null ? "" : value).Trim().ToLowerInvariant();
            }

            private DeviceRecord SelectedDevice()
            {
                if (_devicesGrid == null || _devicesGrid.CurrentRow == null)
                {
                    return null;
                }

                return _devicesGrid.CurrentRow.Tag as DeviceRecord;
            }

            private void SelectDevice(DeviceRecord record)
            {
                if (record == null || _devicesGrid == null)
                {
                    return;
                }

                for (int i = 0; i < _devicesGrid.Rows.Count; i++)
                {
                    if (Object.ReferenceEquals(_devicesGrid.Rows[i].Tag, record))
                    {
                        _devicesGrid.ClearSelection();
                        _devicesGrid.Rows[i].Selected = true;
                        _devicesGrid.CurrentCell = _devicesGrid.Rows[i].Cells[0];
                        return;
                    }
                }
            }

            private void UpdateButtonState()
            {
                bool hasSelection = SelectedDevice() != null;
                if (_editButton != null)
                {
                    _editButton.Enabled = hasSelection;
                }

                if (_deleteButton != null)
                {
                    _deleteButton.Enabled = hasSelection;
                }
            }

            private void CreateDevice()
            {
                using (DeviceEditorDialog dialog = new DeviceEditorDialog(_technologies, _subcenters, _affiliations, _englishUi))
                {
                    if (dialog.ShowDialog(this) != DialogResult.OK || dialog.Device == null)
                    {
                        return;
                    }

                    if (AddDeviceRequested != null && AddDeviceRequested(dialog.Device))
                    {
                        BuildSearchIndex();
                        RefreshRows(dialog.Device);
                    }
                }
            }

            private void ImportDevices()
            {
                if (ImportDevicesRequested != null && ImportDevicesRequested())
                {
                    BuildSearchIndex();
                    RefreshRows(null);
                }
            }

            private void EditSelectedDevice()
            {
                DeviceRecord selected = SelectedDevice();
                if (selected == null)
                {
                    return;
                }

                using (DeviceEditorDialog dialog = new DeviceEditorDialog(_technologies, _subcenters, _affiliations, _englishUi, selected))
                {
                    if (dialog.ShowDialog(this) != DialogResult.OK || dialog.Device == null)
                    {
                        return;
                    }

                    if (EditDeviceRequested != null && EditDeviceRequested(selected, dialog.Device))
                    {
                        BuildSearchIndex();
                        RefreshRows(selected);
                    }
                }
            }

            private void DeleteSelectedDevice()
            {
                DeviceRecord selected = SelectedDevice();
                if (selected == null)
                {
                    return;
                }

                string name = String.IsNullOrWhiteSpace(selected.Name) ? selected.Ip : selected.Name;
                DialogResult result = MessageBox.Show(
                    UiText.Pick(_englishUi, "Desea eliminar el dispositivo seleccionado?", "Do you want to delete the selected device?")
                        + "\r\n\r\n"
                        + name
                        + " / "
                        + selected.Ip,
                    UiText.Pick(_englishUi, "Eliminar dispositivo", "Delete device"),
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning);
                if (result != DialogResult.Yes)
                {
                    return;
                }

                if (DeleteDeviceRequested != null && DeleteDeviceRequested(selected))
                {
                    BuildSearchIndex();
                    RefreshRows(null);
                }
            }

            private void DeleteAllDevices()
            {
                if (!_canDeleteAll || DeleteAllDevicesRequested == null)
                {
                    return;
                }

                if (DeleteAllDevicesRequested())
                {
                    BuildSearchIndex();
                    RefreshRows(null);
                }
            }
        }

        private sealed class DeviceEditorDialog : Form
        {
            private TextBox _nameText;
            private TextBox _ipText;
            private ComboBox _typeCombo;
            private ComboBox _subcenterCombo;
            private ComboBox _affiliationCombo;
            private ComboBox _technologyCombo;
            private Label _errorLabel;
            private readonly bool _englishUi;
            private readonly DeviceRecord _editingDevice;

            public DeviceRecord Device { get; private set; }

            public DeviceEditorDialog(List<string> technologies, List<string> subcenters, List<string> affiliations, bool englishUi)
                : this(technologies, subcenters, affiliations, englishUi, null)
            {
            }

            public DeviceEditorDialog(List<string> technologies, List<string> subcenters, List<string> affiliations, bool englishUi, DeviceRecord editingDevice)
            {
                _englishUi = englishUi;
                _editingDevice = editingDevice;
                bool editing = _editingDevice != null;
                Text = editing ? UiText.Pick(_englishUi, "Editar dispositivo", "Edit device") : UiText.Pick(_englishUi, "Agregar dispositivo", "Add device");
                FormBorderStyle = FormBorderStyle.FixedDialog;
                StartPosition = FormStartPosition.CenterParent;
                ControlBox = false;
                MaximizeBox = false;
                MinimizeBox = false;
                ShowInTaskbar = false;
                BackColor = AppBackground;
                ForeColor = TextMain;
                Font = new Font("Segoe UI", 9F);
                ClientSize = new Size(560, 374);

                Panel header = new Panel();
                header.BackColor = Surface;
                TechStyle.AttachSurface(header, Color.FromArgb(13, 31, 58), Color.FromArgb(8, 18, 38), AccentSoft, true);
                header.SetBounds(0, 0, ClientSize.Width, 82);
                header.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
                Controls.Add(header);

                Label title = new Label();
                title.Text = editing ? UiText.Pick(_englishUi, "Editar dispositivo", "Edit device") : UiText.Pick(_englishUi, "Nuevo dispositivo", "New device");
                title.AutoSize = false;
                title.Font = new Font("Segoe UI Semibold", 15F, FontStyle.Bold);
                title.ForeColor = TextMain;
                title.BackColor = Color.Transparent;
                title.SetBounds(26, 16, 360, 30);
                header.Controls.Add(title);

                Label subtitle = new Label();
                subtitle.Text = editing ? UiText.Pick(_englishUi, "Actualizacion controlada del registro", "Controlled record update") : UiText.Pick(_englishUi, "Registro para sumar al monitoreo", "Record to add to monitoring");
                subtitle.AutoSize = false;
                subtitle.ForeColor = TextMuted;
                subtitle.BackColor = Color.Transparent;
                subtitle.SetBounds(28, 48, 360, 22);
                header.Controls.Add(subtitle);
                TechStyle.MakeChromeTransparent(header);

                _nameText = AddTextBox(UiText.Pick(_englishUi, "Dispositivo", "Device"), 28, 112, 244);
                _ipText = AddTextBox("IP", 300, 112, 220);
                _typeCombo = AddCombo(UiText.Pick(_englishUi, "Tipo", "Type"), 28, 178, 244, true);
                FillComboValues(_typeCombo, DeviceTypes, null);
                SelectComboText(_typeCombo, "Fija");

                _subcenterCombo = AddCombo(UiText.Pick(_englishUi, "Ubicacion / sitio", "Location / site"), 300, 178, 220, false);
                FillComboValues(_subcenterCombo, null, subcenters);

                _affiliationCombo = AddCombo(UiText.Pick(_englishUi, "Afiliacion", "Affiliation"), 28, 244, 244, false);
                FillComboValues(_affiliationCombo, null, affiliations);

                _technologyCombo = AddCombo(UiText.Pick(_englishUi, "Tecnologia", "Technology"), 300, 244, 220, false);
                FillComboValues(_technologyCombo, null, technologies);
                SelectComboText(_technologyCombo, "PMI");

                _errorLabel = new Label();
                _errorLabel.AutoSize = false;
                _errorLabel.ForeColor = Color.FromArgb(248, 113, 113);
                _errorLabel.BackColor = Color.Transparent;
                _errorLabel.SetBounds(28, 306, 244, 34);
                Controls.Add(_errorLabel);

                MaterialButton saveButton = new MaterialButton();
                saveButton.Text = editing ? UiText.Pick(_englishUi, "Guardar cambios", "Save changes") : UiText.Pick(_englishUi, "Guardar", "Save");
                saveButton.Width = editing ? 132 : 112;
                saveButton.Height = 32;
                saveButton.BackColor = AccentSoft;
                saveButton.ForeColor = Color.FromArgb(2, 6, 23);
                saveButton.SetBounds(editing ? 280 : 300, 316, saveButton.Width, 32);
                saveButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
                saveButton.Click += delegate { SaveDevice(); };
                Controls.Add(saveButton);

                MaterialButton cancelButton = new MaterialButton();
                cancelButton.Text = UiText.Pick(_englishUi, "Cancelar", "Cancel");
                cancelButton.Width = 112;
                cancelButton.Height = 32;
                cancelButton.BackColor = SurfaceSoft;
                cancelButton.ForeColor = TextMain;
                cancelButton.DialogResult = DialogResult.Cancel;
                cancelButton.SetBounds(420, 316, 112, 32);
                cancelButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
                Controls.Add(cancelButton);

                AcceptButton = saveButton;
                CancelButton = cancelButton;

                if (editing)
                {
                    LoadDevice(_editingDevice);
                }
            }

            private void LoadDevice(DeviceRecord record)
            {
                if (record == null)
                {
                    return;
                }

                _nameText.Text = record.Name == null ? "" : record.Name;
                _ipText.Text = record.Ip == null ? "" : record.Ip;
                SelectComboText(_typeCombo, String.IsNullOrWhiteSpace(record.Type) ? "Fija" : record.Type);
                SelectComboText(_subcenterCombo, record.Subcenter == null ? "" : record.Subcenter);
                SelectComboText(_affiliationCombo, record.Affiliation == null ? "" : record.Affiliation);
                SelectComboText(_technologyCombo, record.Notes == null ? "" : record.Notes);
            }

            private TextBox AddTextBox(string label, int x, int y, int width)
            {
                AddFieldLabel(label, x, y - 20, width);
                TextBox textBox = new TextBox();
                textBox.BackColor = SurfaceSoft;
                textBox.ForeColor = TextMain;
                textBox.BorderStyle = BorderStyle.FixedSingle;
                textBox.SetBounds(x, y, width, 24);
                Controls.Add(textBox);
                return textBox;
            }

            private ComboBox AddCombo(string label, int x, int y, int width, bool listOnly)
            {
                AddFieldLabel(label, x, y - 20, width);
                ComboBox combo = new ComboBox();
                combo.DropDownStyle = listOnly ? ComboBoxStyle.DropDownList : ComboBoxStyle.DropDown;
                combo.AutoCompleteMode = listOnly ? AutoCompleteMode.None : AutoCompleteMode.SuggestAppend;
                combo.AutoCompleteSource = AutoCompleteSource.ListItems;
                combo.BackColor = SurfaceSoft;
                combo.ForeColor = TextMain;
                combo.FlatStyle = FlatStyle.Flat;
                combo.SetBounds(x, y, width, 24);
                Controls.Add(combo);
                return combo;
            }

            private Label AddFieldLabel(string text, int x, int y, int width)
            {
                Label label = new Label();
                label.Text = text;
                label.AutoSize = false;
                label.ForeColor = TextMuted;
                label.BackColor = Color.Transparent;
                label.SetBounds(x, y, width, 18);
                Controls.Add(label);
                return label;
            }

            private void FillComboValues(ComboBox combo, string[] fixedValues, List<string> dynamicValues)
            {
                if (fixedValues != null)
                {
                    for (int i = 0; i < fixedValues.Length; i++)
                    {
                        AddComboValue(combo, fixedValues[i]);
                    }
                }

                if (dynamicValues != null)
                {
                    for (int i = 0; i < dynamicValues.Count; i++)
                    {
                        AddComboValue(combo, dynamicValues[i]);
                    }
                }

                if (combo.Items.Count > 0 && combo.SelectedIndex < 0)
                {
                    combo.SelectedIndex = 0;
                }
            }

            private void AddComboValue(ComboBox combo, string value)
            {
                string text = value == null ? "" : value.Trim();
                if (String.IsNullOrWhiteSpace(text)
                    || String.Equals(text, "Todas", StringComparison.OrdinalIgnoreCase)
                    || String.Equals(text, "Todos", StringComparison.OrdinalIgnoreCase)
                    || String.Equals(text, "All", StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                for (int i = 0; i < combo.Items.Count; i++)
                {
                    if (String.Equals(Convert.ToString(combo.Items[i], CultureInfo.InvariantCulture), text, StringComparison.OrdinalIgnoreCase))
                    {
                        return;
                    }
                }

                combo.Items.Add(text);
            }

            private void SelectComboText(ComboBox combo, string value)
            {
                for (int i = 0; i < combo.Items.Count; i++)
                {
                    if (String.Equals(Convert.ToString(combo.Items[i], CultureInfo.InvariantCulture), value, StringComparison.OrdinalIgnoreCase))
                    {
                        combo.SelectedIndex = i;
                        return;
                    }
                }

                if (combo.DropDownStyle == ComboBoxStyle.DropDown)
                {
                    combo.Text = value;
                }
            }

            private void SaveDevice()
            {
                string ip = _ipText.Text == null ? "" : _ipText.Text.Trim();
                if (String.IsNullOrWhiteSpace(ip))
                {
                    ShowError(UiText.Pick(_englishUi, "Capture la IP del dispositivo.", "Enter the device IP."));
                    return;
                }

                IPAddress address;
                if (!IPAddress.TryParse(ip, out address))
                {
                    ShowError(UiText.Pick(_englishUi, "La IP capturada no tiene un formato valido.", "The IP address format is invalid."));
                    return;
                }

                string name = _nameText.Text == null ? "" : _nameText.Text.Trim();
                if (String.IsNullOrWhiteSpace(name))
                {
                    name = ip;
                }

                string type = ComboText(_typeCombo, "Fija");
                string subcenter = ComboText(_subcenterCombo, "");
                string affiliation = ComboText(_affiliationCombo, "");
                string technology = ComboText(_technologyCombo, "");

                DeviceRecord record = new DeviceRecord();
                record.Name = name;
                record.Ip = ip;
                record.Type = String.IsNullOrWhiteSpace(type) ? "Fija" : type;
                record.Subcenter = subcenter;
                record.Affiliation = affiliation;
                record.Notes = technology;
                record.Status = _editingDevice == null || String.IsNullOrWhiteSpace(_editingDevice.Status) ? "Pendiente" : _editingDevice.Status;
                record.Failures = _editingDevice == null ? 0 : Math.Max(0, _editingDevice.Failures);
                record.Latency = _editingDevice == null || _editingDevice.Latency == null ? "" : _editingDevice.Latency;
                record.LastCheck = _editingDevice == null || _editingDevice.LastCheck == null ? "" : _editingDevice.LastCheck;

                Device = record;
                DialogResult = DialogResult.OK;
                Close();
            }

            private string ComboText(ComboBox combo, string fallback)
            {
                string value = combo == null ? "" : combo.Text;
                if (String.IsNullOrWhiteSpace(value) && combo != null && combo.SelectedItem != null)
                {
                    value = combo.SelectedItem.ToString();
                }

                return String.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
            }

            private void ShowError(string message)
            {
                _errorLabel.Text = message;
            }
        }

        private sealed class UserMenuButton : Control
        {
            private static Image _frameImage;
            private bool _hover;
            private bool _pressed;

            public string Username { get; set; }
            public string Role { get; set; }
            public string ProfileImagePath { get; set; }
            public bool ShowCompact { get; set; }

            public UserMenuButton()
            {
                SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.UserPaint | ControlStyles.SupportsTransparentBackColor, true);
                BackColor = Color.Transparent;
                ForeColor = TextMain;
                Cursor = Cursors.Hand;
                TabStop = false;
                AccessibleName = "Menu de usuario";
            }

            protected override void OnMouseEnter(EventArgs e)
            {
                _hover = true;
                Invalidate();
                base.OnMouseEnter(e);
            }

            protected override void OnMouseLeave(EventArgs e)
            {
                _hover = false;
                _pressed = false;
                Invalidate();
                base.OnMouseLeave(e);
            }

            protected override void OnMouseDown(MouseEventArgs mevent)
            {
                _pressed = true;
                Invalidate();
                base.OnMouseDown(mevent);
            }

            protected override void OnMouseUp(MouseEventArgs mevent)
            {
                _pressed = false;
                Invalidate();
                base.OnMouseUp(mevent);
            }

            protected override void OnPaintBackground(PaintEventArgs pevent)
            {
                TechStyle.PaintInheritedBackground(pevent.Graphics, this, Surface);
            }

            protected override void OnPaint(PaintEventArgs e)
            {
                TechStyle.Configure(e.Graphics);
                TechStyle.PaintInheritedBackground(e.Graphics, this, Surface);

                Rectangle rect = ClientRectangle;
                rect.Inflate(-1, -1);

                Image frame = LoadFrameImage();
                if (frame != null && !ShowCompact && Width >= 180)
                {
                    e.Graphics.DrawImage(frame, rect);
                    if (_hover || _pressed)
                    {
                        using (GraphicsPath path = RoundRect(rect, 20))
                        using (Pen hoverPen = new Pen(_pressed ? Color.FromArgb(210, Accent) : Accent, 1.5F))
                        {
                            e.Graphics.DrawPath(hoverPen, path);
                        }
                    }
                }
                else
                {
                    Color top = _pressed
                        ? Color.FromArgb(11, 29, 56)
                        : _hover ? Color.FromArgb(16, 47, 82) : Color.FromArgb(8, 24, 50);
                    Color bottom = _pressed
                        ? Color.FromArgb(6, 18, 38)
                        : _hover ? Color.FromArgb(8, 34, 68) : Color.FromArgb(5, 14, 31);

                    using (GraphicsPath path = RoundRect(rect, 20))
                    using (LinearGradientBrush brush = new LinearGradientBrush(rect, top, bottom, LinearGradientMode.Vertical))
                    {
                        e.Graphics.FillPath(brush, path);
                    }

                    using (GraphicsPath path = RoundRect(rect, 20))
                    using (Pen borderPen = new Pen(_hover ? Accent : Color.FromArgb(42, 111, 150), 1.2F))
                    {
                        e.Graphics.DrawPath(borderPen, path);
                    }

                    if (rect.Width > 96)
                    {
                        using (Pen accentLine = new Pen(Color.FromArgb(170, Accent), 2F))
                        {
                            e.Graphics.DrawLine(accentLine, rect.Left + 54, rect.Bottom - 7, rect.Right - 34, rect.Bottom - 7);
                        }
                    }
                }

                int avatarSize = ShowCompact ? 34 : 35;
                int avatarLeft = ShowCompact ? rect.Left + ((rect.Width - avatarSize) / 2) : rect.Left + 8;
                Rectangle avatar = new Rectangle(avatarLeft, rect.Top + 5, avatarSize, avatarSize);
                AccountVisuals.DrawAvatar(e.Graphics, avatar, Username, ProfileImagePath, false);

                if (!ShowCompact && Width >= 132)
                {
                    string userText = String.IsNullOrWhiteSpace(Username) ? "Usuario" : Username;
                    using (Font nameFont = new Font("Segoe UI Semibold", 9.2F, FontStyle.Bold))
                    using (Font captionFont = new Font("Segoe UI", 7.8F, FontStyle.Regular))
                    {
                        Rectangle nameBounds = new Rectangle(rect.Left + 54, rect.Top + 7, rect.Width - 86, 18);
                        Rectangle captionBounds = new Rectangle(rect.Left + 54, rect.Top + 23, rect.Width - 86, 15);
                        TextRenderer.DrawText(e.Graphics, userText, nameFont, nameBounds, TextMain, TextFormatFlags.EndEllipsis | TextFormatFlags.VerticalCenter | TextFormatFlags.Left);
                        TextRenderer.DrawText(e.Graphics, String.IsNullOrWhiteSpace(Role) ? "Cuenta" : Role, captionFont, captionBounds, TextMuted, TextFormatFlags.EndEllipsis | TextFormatFlags.VerticalCenter | TextFormatFlags.Left);
                    }
                }

                if (!ShowCompact)
                {
                    Point[] arrow = new Point[]
                    {
                        new Point(rect.Right - 22, rect.Top + 18),
                        new Point(rect.Right - 12, rect.Top + 18),
                        new Point(rect.Right - 17, rect.Top + 25)
                    };
                    using (Brush arrowBrush = new SolidBrush(TextMuted))
                    {
                        e.Graphics.FillPolygon(arrowBrush, arrow);
                    }
                }
            }

            private static Image LoadFrameImage()
            {
                if (_frameImage != null)
                {
                    return _frameImage;
                }

                try
                {
                    string path = Path.Combine(Application.StartupPath, "account_button_frame.png");
                    if (File.Exists(path))
                    {
                        using (Image image = Image.FromFile(path))
                        {
                            _frameImage = new Bitmap(image);
                        }
                        return _frameImage;
                    }

                    Assembly assembly = Assembly.GetExecutingAssembly();
                    using (Stream stream = assembly.GetManifestResourceStream("AccountButtonFrame"))
                    {
                        if (stream != null)
                        {
                            using (Image image = Image.FromStream(stream))
                            {
                                _frameImage = new Bitmap(image);
                            }
                        }
                    }
                }
                catch
                {
                    _frameImage = null;
                }

                return _frameImage;
            }

            private Color GetHostBackColor()
            {
                return Parent == null ? Surface : Parent.BackColor;
            }

            private static GraphicsPath RoundRect(Rectangle rect, int radius)
            {
                GraphicsPath path = new GraphicsPath();
                int diameter = radius * 2;
                Rectangle arc = new Rectangle(rect.Left, rect.Top, diameter, diameter);
                path.AddArc(arc, 180, 90);
                arc.X = rect.Right - diameter;
                path.AddArc(arc, 270, 90);
                arc.Y = rect.Bottom - diameter;
                path.AddArc(arc, 0, 90);
                arc.X = rect.Left;
                path.AddArc(arc, 90, 90);
                path.CloseFigure();
                return path;
            }
        }

        private sealed class MaterialButton : Button
        {
            private bool _hover;
            private bool _pressed;

            public MaterialButton()
            {
                SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.OptimizedDoubleBuffer, true);
                FlatStyle = FlatStyle.Flat;
                FlatAppearance.BorderSize = 0;
                Font = new Font("Segoe UI Semibold", 8.5F, FontStyle.Bold);
                Cursor = Cursors.Hand;
            }

            protected override void OnMouseEnter(EventArgs e)
            {
                _hover = true;
                Invalidate();
                base.OnMouseEnter(e);
            }

            protected override void OnMouseLeave(EventArgs e)
            {
                _hover = false;
                _pressed = false;
                Invalidate();
                base.OnMouseLeave(e);
            }

            protected override void OnMouseDown(MouseEventArgs mevent)
            {
                _pressed = true;
                Invalidate();
                base.OnMouseDown(mevent);
            }

            protected override void OnMouseUp(MouseEventArgs mevent)
            {
                _pressed = false;
                Invalidate();
                base.OnMouseUp(mevent);
            }

            protected override void OnPaintBackground(PaintEventArgs pevent)
            {
                TechStyle.PaintInheritedBackground(pevent.Graphics, this, AppBackground);
            }

            protected override void OnPaint(PaintEventArgs e)
            {
                Graphics g = e.Graphics;
                TechStyle.Configure(g);
                TechStyle.PaintInheritedBackground(g, this, AppBackground);

                Rectangle shadowRect = new Rectangle(4, _pressed ? 4 : 5, Width - 8, Height - 8);
                using (GraphicsPath shadowPath = RoundRect(shadowRect, 8))
                using (Brush shadowBrush = new SolidBrush(Color.FromArgb(_hover ? 105 : 70, 0, 0, 0)))
                {
                    g.FillPath(shadowBrush, shadowPath);
                }

                Rectangle body = new Rectangle(2, _pressed ? 4 : 2, Width - 5, Height - 7);
                Color top = _hover ? Lighten(BackColor, 30) : Lighten(BackColor, 18);
                Color bottom = _pressed ? Darken(BackColor, 18) : BackColor;
                using (GraphicsPath path = RoundRect(body, 8))
                using (LinearGradientBrush brush = new LinearGradientBrush(body, top, bottom, LinearGradientMode.Vertical))
                {
                    g.FillPath(brush, path);
                }

                Color border = _hover ? Accent : Color.FromArgb(95, Border);
                using (GraphicsPath path = RoundRect(body, 8))
                using (Pen pen = new Pen(border, _hover ? 1.6F : 1F))
                {
                    g.DrawPath(pen, path);
                }

                if (_hover)
                {
                    Rectangle glow = new Rectangle(body.Left + 1, body.Top + 1, body.Width - 2, body.Height - 2);
                    using (GraphicsPath path = RoundRect(glow, 7))
                    using (Pen pen = new Pen(Color.FromArgb(80, Accent), 1F))
                    {
                        g.DrawPath(pen, path);
                    }
                }

                TextRenderer.DrawText(
                    g,
                    Text,
                    Font,
                    body,
                    ForeColor,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
            }

            private static Color Lighten(Color color, int amount)
            {
                return Color.FromArgb(
                    color.A,
                    Math.Min(255, color.R + amount),
                    Math.Min(255, color.G + amount),
                    Math.Min(255, color.B + amount));
            }

            private static Color Darken(Color color, int amount)
            {
                return Color.FromArgb(
                    color.A,
                    Math.Max(0, color.R - amount),
                    Math.Max(0, color.G - amount),
                    Math.Max(0, color.B - amount));
            }

            private static GraphicsPath RoundRect(Rectangle rect, int radius)
            {
                GraphicsPath path = new GraphicsPath();
                if (rect.Width <= 1 || rect.Height <= 1)
                {
                    path.AddRectangle(rect);
                    return path;
                }

                radius = Math.Max(1, Math.Min(radius, Math.Min(rect.Width, rect.Height) / 2));
                int diameter = radius * 2;
                Rectangle arc = new Rectangle(rect.Location, new Size(diameter, diameter));
                path.AddArc(arc, 180, 90);
                arc.X = rect.Right - diameter;
                path.AddArc(arc, 270, 90);
                arc.Y = rect.Bottom - diameter;
                path.AddArc(arc, 0, 90);
                arc.X = rect.Left;
                path.AddArc(arc, 90, 90);
                path.CloseFigure();
                return path;
            }
        }

        private sealed class LogoCard : Control
        {
            public Image Logo { get; set; }

            public LogoCard()
            {
                SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.OptimizedDoubleBuffer, true);
            }

            protected override void OnPaintBackground(PaintEventArgs pevent)
            {
                TechStyle.PaintInheritedBackground(pevent.Graphics, this, Color.FromArgb(7, 16, 36));
            }

            protected override void OnPaint(PaintEventArgs e)
            {
                Graphics g = e.Graphics;
                TechStyle.Configure(g);
                TechStyle.PaintInheritedBackground(g, this, Color.FromArgb(7, 16, 36));
                Rectangle rect = new Rectangle(0, 0, Width - 1, Height - 1);

                using (GraphicsPath glowPath = RoundRect(new Rectangle(2, 3, Width - 4, Height - 6), 18))
                using (Pen glow = new Pen(Color.FromArgb(92, Accent), 2.2F))
                {
                    g.DrawPath(glow, glowPath);
                }

                using (GraphicsPath path = RoundRect(new Rectangle(1, 1, Width - 3, Height - 3), 18))
                using (Pen pen = new Pen(Color.FromArgb(138, Accent), 1.1F))
                {
                    g.DrawPath(pen, path);
                }

                if (Logo != null)
                {
                    Rectangle imageRect = new Rectangle(4, 3, Width - 8, Height - 6);
                    g.DrawImage(Logo, FitRect(Logo.Size, imageRect));
                }
            }

            private static Rectangle FitRect(Size imageSize, Rectangle bounds)
            {
                if (imageSize.Width <= 0 || imageSize.Height <= 0)
                {
                    return bounds;
                }

                float scale = Math.Min(bounds.Width / (float)imageSize.Width, bounds.Height / (float)imageSize.Height);
                int width = (int)Math.Round(imageSize.Width * scale);
                int height = (int)Math.Round(imageSize.Height * scale);
                return new Rectangle(
                    bounds.Left + ((bounds.Width - width) / 2),
                    bounds.Top + ((bounds.Height - height) / 2),
                    width,
                    height);
            }

            private static GraphicsPath RoundRect(Rectangle rect, int radius)
            {
                GraphicsPath path = new GraphicsPath();
                if (rect.Width <= 1 || rect.Height <= 1)
                {
                    path.AddRectangle(rect);
                    return path;
                }

                radius = Math.Max(1, Math.Min(radius, Math.Min(rect.Width, rect.Height) / 2));
                int diameter = radius * 2;
                Rectangle arc = new Rectangle(rect.Location, new Size(diameter, diameter));
                path.AddArc(arc, 180, 90);
                arc.X = rect.Right - diameter;
                path.AddArc(arc, 270, 90);
                arc.Y = rect.Bottom - diameter;
                path.AddArc(arc, 0, 90);
                arc.X = rect.Left;
                path.AddArc(arc, 90, 90);
                path.CloseFigure();
                return path;
            }
        }

        private sealed class DashboardView : Panel
        {
            private DashboardStats _total;
            private List<DashboardStats> _stats;
            private List<DashboardStats> _subcenterStats;
            private DateTime _cutoff;
            private DateTime _now;
            private string _groupLabel;
            private string _technologyFilter;
            private string _subcenterFilter;
            private string _affiliationFilter;
            private string _searchFilter;
            private bool _englishUi;

            public DashboardView()
            {
                DoubleBuffered = true;
                ResizeRedraw = true;
                _stats = new List<DashboardStats>();
                _subcenterStats = new List<DashboardStats>();
                _total = new DashboardStats();
                _groupLabel = "tecnologia";
                _technologyFilter = "Todas";
                _subcenterFilter = "Todas";
                _affiliationFilter = "Todas";
                _searchFilter = "";
                _englishUi = false;
            }

            public void SetLanguage(bool englishUi)
            {
                _englishUi = englishUi;
                Invalidate();
            }

            public void SetData(DashboardStats total, List<DashboardStats> stats, List<DashboardStats> subcenterStats, DateTime cutoff, DateTime now, string groupLabel, string technologyFilter, string subcenterFilter, string affiliationFilter, string searchFilter)
            {
                _total = total == null ? new DashboardStats() : total;
                _stats = stats == null ? new List<DashboardStats>() : stats;
                _subcenterStats = subcenterStats == null ? new List<DashboardStats>() : subcenterStats;
                _cutoff = cutoff;
                _now = now;
                _groupLabel = String.IsNullOrWhiteSpace(groupLabel) ? "tecnologia" : groupLabel;
                _technologyFilter = String.IsNullOrWhiteSpace(technologyFilter) ? "Todas" : technologyFilter;
                _subcenterFilter = String.IsNullOrWhiteSpace(subcenterFilter) ? "Todas" : subcenterFilter;
                _affiliationFilter = String.IsNullOrWhiteSpace(affiliationFilter) ? "Todas" : affiliationFilter;
                _searchFilter = String.IsNullOrWhiteSpace(searchFilter) ? "" : searchFilter;
                Invalidate();
            }

            protected override void OnPaint(PaintEventArgs e)
            {
                base.OnPaint(e);
                Graphics g = e.Graphics;
                TechStyle.Configure(g);
                DrawTechBackground(g, ClientRectangle);

                Rectangle canvas = ClientRectangle;
                if (canvas.Width < 420 || canvas.Height < 260)
                {
                    DrawText(g, "Dashboard", Font, TextMain, canvas, ContentAlignment.MiddleCenter);
                    return;
                }

                int margin = 22;
                int gap = 20;
                int rightWidth = Math.Max(300, (int)(canvas.Width * 0.30));
                int leftWidth = canvas.Width - rightWidth - (margin * 2) - gap;
                int availableHeight = canvas.Height - (margin * 2);
                if (leftWidth < 420 || availableHeight < 360)
                {
                    leftWidth = canvas.Width - (margin * 2);
                    rightWidth = 0;
                }

                Rectangle availabilityCard = new Rectangle(margin, margin, leftWidth, canvas.Height - (margin * 2));
                DrawAvailabilityCard(g, availabilityCard);

                if (rightWidth > 0)
                {
                    int rightX = margin + leftWidth + gap;
                    int topHeight = Math.Min(320, Math.Max(220, (canvas.Height - (margin * 2) - gap) / 2));
                    Rectangle statusCard = new Rectangle(rightX, margin, rightWidth, topHeight);
                    Rectangle subcenterCard = new Rectangle(rightX, margin + topHeight + gap, rightWidth, canvas.Height - (margin * 2) - gap - topHeight);
                    DrawStatusCard(g, statusCard);
                    DrawSubcenterSummaryCard(g, subcenterCard);
                }
            }

            private string T(string spanish, string english)
            {
                return UiText.Pick(_englishUi, spanish, english);
            }

            private void DrawTechBackground(Graphics g, Rectangle rect)
            {
                if (rect.Width <= 0 || rect.Height <= 0)
                {
                    return;
                }

                using (LinearGradientBrush brush = new LinearGradientBrush(
                    rect,
                    Color.FromArgb(4, 10, 25),
                    Color.FromArgb(8, 32, 58),
                    LinearGradientMode.ForwardDiagonal))
                {
                    g.FillRectangle(brush, rect);
                }

                using (Pen gridPen = new Pen(Color.FromArgb(34, 55, 116, 154), 1F))
                {
                    for (int x = 0; x < rect.Width; x += 42)
                    {
                        g.DrawLine(gridPen, x, 0, x, rect.Height);
                    }

                    for (int y = 0; y < rect.Height; y += 42)
                    {
                        g.DrawLine(gridPen, 0, y, rect.Width, y);
                    }
                }

                DrawFloatingDiamond(g, rect.Width - 240, 44, 118, Color.FromArgb(56, 0, 229, 255));
                DrawFloatingDiamond(g, rect.Width - 410, 20, 88, Color.FromArgb(36, 219, 60, 255));
                DrawFloatingDiamond(g, rect.Width - 115, 132, 70, Color.FromArgb(42, 120, 220, 255));
                DrawFloatingDiamond(g, 125, 58, 84, Color.FromArgb(35, 0, 229, 255));
                DrawFloatingDiamond(g, 260, 22, 128, Color.FromArgb(26, 219, 60, 255));

                Point[] cyanRibbon = new Point[]
                {
                    new Point(rect.Width - 360, 0),
                    new Point(rect.Width, 0),
                    new Point(rect.Width, 120),
                    new Point(rect.Width - 230, 52)
                };
                using (Brush ribbonBrush = new SolidBrush(Color.FromArgb(44, 0, 229, 255)))
                {
                    g.FillPolygon(ribbonBrush, cyanRibbon);
                }

                Point[] magentaRibbon = new Point[]
                {
                    new Point(0, rect.Height - 150),
                    new Point(260, rect.Height),
                    new Point(0, rect.Height)
                };
                using (Brush ribbonBrush = new SolidBrush(Color.FromArgb(36, 219, 60, 255)))
                {
                    g.FillPolygon(ribbonBrush, magentaRibbon);
                }

                using (Pen cyanPen = new Pen(Color.FromArgb(150, 0, 229, 255), 2F))
                using (Pen magentaPen = new Pen(Color.FromArgb(135, 219, 60, 255), 2F))
                {
                    g.DrawLines(cyanPen, new Point[]
                    {
                        new Point(26, rect.Height - 78),
                        new Point(190, rect.Height - 138),
                        new Point(370, rect.Height - 102),
                        new Point(540, rect.Height - 178)
                    });

                    g.DrawLines(magentaPen, new Point[]
                    {
                        new Point(rect.Width - 540, 64),
                        new Point(rect.Width - 370, 128),
                        new Point(rect.Width - 190, 92),
                        new Point(rect.Width - 38, 154)
                    });
                }

                DrawCityLine(g, rect);
            }

            private void DrawFloatingDiamond(Graphics g, int centerX, int centerY, int size, Color color)
            {
                Point[] points = new Point[]
                {
                    new Point(centerX, centerY - (size / 2)),
                    new Point(centerX + (size / 2), centerY),
                    new Point(centerX, centerY + (size / 2)),
                    new Point(centerX - (size / 2), centerY)
                };

                using (Brush brush = new SolidBrush(color))
                {
                    g.FillPolygon(brush, points);
                }

                using (Pen pen = new Pen(Color.FromArgb(Math.Min(190, color.A + 80), color.R, color.G, color.B), 1.2F))
                {
                    g.DrawPolygon(pen, points);
                }
            }

            private void DrawCityLine(Graphics g, Rectangle rect)
            {
                int baseY = rect.Bottom - 24;
                int x = 22;
                int[] heights = new int[] { 72, 128, 92, 160, 116, 82, 148, 104, 172, 96, 132, 74, 118, 154, 88, 136 };
                using (Pen pen = new Pen(Color.FromArgb(150, 0, 229, 255), 1.8F))
                using (Pen glow = new Pen(Color.FromArgb(55, 0, 229, 255), 5F))
                {
                    for (int i = 0; x < rect.Width - 16; i++)
                    {
                        int width = 34 + ((i % 4) * 13);
                        int top = baseY - heights[i % heights.Length];
                        Rectangle building = new Rectangle(x, top, width, heights[i % heights.Length]);
                        DrawBuilding(g, glow, building);
                        DrawBuilding(g, pen, building);
                        x += width + 12;
                    }
                }
            }

            private void DrawBuilding(Graphics g, Pen pen, Rectangle b)
            {
                Point[] points = new Point[]
                {
                    new Point(b.Left, b.Bottom),
                    new Point(b.Left, b.Top + 34),
                    new Point(b.Left + 10, b.Top + 34),
                    new Point(b.Left + 10, b.Top),
                    new Point(b.Left + 18, b.Top),
                    new Point(b.Left + 18, b.Top + 55),
                    new Point(b.Left + (b.Width / 2), b.Top + 55),
                    new Point(b.Left + (b.Width / 2), b.Top + 28),
                    new Point(b.Right - 8, b.Top + 28),
                    new Point(b.Right - 8, b.Bottom),
                    new Point(b.Left, b.Bottom)
                };
                g.DrawLines(pen, points);
            }

            private void DrawAvailabilityCard(Graphics g, Rectangle rect)
            {
                DrawCard(g, rect, Color.FromArgb(12, 24, 52), Color.FromArgb(19, 37, 74));

                Rectangle inner = Inflate(rect, -22, -18);
                using (Font titleFont = new Font("Segoe UI Semibold", 13F, FontStyle.Bold))
                using (Font smallFont = new Font("Segoe UI", 8.5F, FontStyle.Regular))
                {
                    DrawText(g, T("Disponibilidad por ", "Availability by ") + _groupLabel, titleFont, TextMain, new Rectangle(inner.Left, inner.Top, inner.Width, 26), ContentAlignment.MiddleLeft);
                    string filters = T("Filtros: tecnologia ", "Filters: technology ") + _technologyFilter + " / " + T("ubicacion/sitio ", "location/site ") + _subcenterFilter + " / " + T("afiliacion ", "affiliation ") + _affiliationFilter;
                    if (!String.IsNullOrWhiteSpace(_searchFilter))
                    {
                        filters += " / " + T("busqueda ", "search ") + _searchFilter;
                    }

                    DrawText(g, filters, smallFont, TextMuted, new Rectangle(inner.Left, inner.Top + 26, inner.Width, 22), ContentAlignment.MiddleLeft);
                }

                int startY = inner.Top + 64;
                List<DashboardStats> rows = GetVisibleStats();
                if (rows.Count == 0)
                {
                    using (Font emptyFont = new Font("Segoe UI", 10F, FontStyle.Regular))
                    {
                        DrawText(g, T("Cargue dispositivos y ejecute una revision para generar disponibilidad.", "Load devices and run a check to generate availability."), emptyFont, TextMuted, new Rectangle(inner.Left, startY, inner.Width, 80), ContentAlignment.MiddleCenter);
                    }
                    return;
                }

                int maxRows = Math.Max(1, (inner.Bottom - startY - 30) / 52);
                int drawCount = Math.Min(rows.Count, maxRows);
                int footerHeight = rows.Count > drawCount ? 28 : 4;
                int rowHeight = Math.Max(52, Math.Min(72, (inner.Bottom - startY - footerHeight) / drawCount));
                using (Font labelFont = new Font("Segoe UI Semibold", 10F, FontStyle.Bold))
                using (Font metaFont = new Font("Segoe UI", 8.5F, FontStyle.Regular))
                using (Font valueFont = new Font("Segoe UI Semibold", 11F, FontStyle.Bold))
                {
                    for (int i = 0; i < drawCount; i++)
                    {
                        DashboardStats stat = rows[i];
                        int y = startY + (i * rowHeight);
                        Rectangle rowRect = new Rectangle(inner.Left, y, inner.Width, rowHeight - 8);
                        double availability = Availability(stat);
                        Color color = TechnologyColor(stat.Technology);

                        DrawText(g, stat.Technology, labelFont, TextMain, new Rectangle(rowRect.Left, rowRect.Top, 180, 24), ContentAlignment.MiddleLeft);
                        string meta = stat.Devices.ToString(CultureInfo.InvariantCulture) + T(" dispositivos  |  ", " devices  |  ")
                            + stat.Samples.ToString(CultureInfo.InvariantCulture) + T(" muestras", " samples");
                        DrawText(g, meta, metaFont, TextMuted, new Rectangle(rowRect.Left, rowRect.Top + 23, 260, 22), ContentAlignment.MiddleLeft);

                        string value = availability < 0 ? T("Sin datos", "No data") : availability.ToString("0.00", CultureInfo.InvariantCulture) + " %";
                        DrawText(g, value, valueFont, availability < 0 ? TextMuted : color, new Rectangle(rowRect.Right - 96, rowRect.Top, 96, 24), ContentAlignment.MiddleRight);

                        Rectangle barBack = new Rectangle(rowRect.Left + 285, rowRect.Top + 31, Math.Max(80, rowRect.Width - 390), 13);
                        DrawRoundedBar(g, barBack, Color.FromArgb(51, 65, 85), availability < 0 ? 0 : availability, color);

                        string active = availability < 0 ? T("sin muestras", "no samples") : FormatDashboardDuration(TimeSpan.FromHours(WindowHours() * availability / 100.0));
                        DrawText(g, active, metaFont, TextMuted, new Rectangle(rowRect.Right - 120, rowRect.Top + 25, 120, 22), ContentAlignment.MiddleRight);
                    }

                    if (rows.Count > drawCount)
                    {
                        DrawText(g, "+" + (rows.Count - drawCount).ToString(CultureInfo.InvariantCulture) + T(" grupos mas", " more groups"), metaFont, TextMuted, new Rectangle(inner.Left, inner.Bottom - 22, inner.Width, 22), ContentAlignment.MiddleCenter);
                    }
                }
            }

            private void DrawStatusCard(Graphics g, Rectangle rect)
            {
                DrawCard(g, rect, Color.FromArgb(12, 24, 52), Color.FromArgb(23, 34, 79));
                Rectangle inner = Inflate(rect, -20, -18);
                using (Font titleFont = new Font("Segoe UI Semibold", 11F, FontStyle.Bold))
                using (Font valueFont = new Font("Segoe UI Semibold", 18F, FontStyle.Bold))
                using (Font smallFont = new Font("Segoe UI", 8.5F, FontStyle.Regular))
                {
                    DrawText(g, T("Resumen de actividad", "Activity summary"), titleFont, TextMain, new Rectangle(inner.Left, inner.Top, inner.Width, 24), ContentAlignment.MiddleLeft);

                    int donutSize = Math.Min(138, Math.Max(96, inner.Width / 2));
                    Rectangle donut = new Rectangle(inner.Left + 4, inner.Top + 50, donutSize, donutSize);
                    DrawDonut(g, donut);

                    double availability = Availability(_total);
                    string value = availability < 0 ? T("Sin datos", "No data") : availability.ToString("0.00", CultureInfo.InvariantCulture) + "%";
                    DrawText(g, value, valueFont, Accent, new Rectangle(donut.Right + 18, inner.Top + 54, inner.Width - donut.Width - 24, 44), ContentAlignment.MiddleLeft);
                    DrawText(g, T("Disponibilidad general", "Overall availability"), smallFont, TextMuted, new Rectangle(donut.Right + 18, inner.Top + 98, inner.Width - donut.Width - 24, 24), ContentAlignment.MiddleLeft);

                    int y = inner.Top + 140;
                    DrawLegend(g, new Rectangle(donut.Right + 18, y, inner.Width - donut.Width - 24, 22), Color.FromArgb(34, 197, 94), T("En linea", "Online"), _total.Online);
                    DrawLegend(g, new Rectangle(donut.Right + 18, y + 26, inner.Width - donut.Width - 24, 22), Color.FromArgb(239, 68, 68), T("Sin respuesta", "No response"), _total.Offline);
                }
            }

            private void DrawSubcenterSummaryCard(Graphics g, Rectangle rect)
            {
                DrawCard(g, rect, Color.FromArgb(12, 24, 52), Color.FromArgb(18, 45, 75));
                Rectangle inner = Inflate(rect, -20, -18);
                using (Font titleFont = new Font("Segoe UI Semibold", 11F, FontStyle.Bold))
                using (Font smallFont = new Font("Segoe UI", 8.5F, FontStyle.Regular))
                {
                    DrawText(g, T("Resumen por ubicacion / sitio", "Summary by location / site"), titleFont, TextMain, new Rectangle(inner.Left, inner.Top, inner.Width, 24), ContentAlignment.MiddleLeft);
                    DrawText(g, T("Disponibilidad con los filtros actuales", "Availability with current filters"), smallFont, TextMuted, new Rectangle(inner.Left, inner.Top + 24, inner.Width, 22), ContentAlignment.MiddleLeft);
                }

                List<DashboardStats> rows = GetVisibleSubcenterStats();
                int startY = inner.Top + 58;
                if (rows.Count == 0)
                {
                    using (Font emptyFont = new Font("Segoe UI", 9F, FontStyle.Regular))
                    {
                        DrawText(g, T("No hay ubicaciones con muestras para esta ventana.", "No locations have samples in this window."), emptyFont, TextMuted, new Rectangle(inner.Left, startY, inner.Width, 80), ContentAlignment.MiddleCenter);
                    }
                    return;
                }

                int maxRows = Math.Max(1, Math.Min(rows.Count, Math.Max(1, (inner.Bottom - startY - 26) / 46)));
                int rowHeight = Math.Max(42, Math.Min(56, (inner.Bottom - startY - 22) / maxRows));
                using (Font labelFont = new Font("Segoe UI Semibold", 9.3F, FontStyle.Bold))
                using (Font metaFont = new Font("Segoe UI", 8F, FontStyle.Regular))
                using (Font valueFont = new Font("Segoe UI Semibold", 10F, FontStyle.Bold))
                {
                    for (int i = 0; i < maxRows; i++)
                    {
                        DashboardStats stat = rows[i];
                        double availability = Availability(stat);
                        Color color = SubcenterColor(i);
                        int y = startY + (i * rowHeight);

                        DrawText(g, stat.Technology, labelFont, TextMain, new Rectangle(inner.Left, y, inner.Width - 82, 22), ContentAlignment.MiddleLeft);
                        string value = availability < 0 ? T("S/D", "N/A") : availability.ToString("0.00", CultureInfo.InvariantCulture) + "%";
                        DrawText(g, value, valueFont, availability < 0 ? TextMuted : color, new Rectangle(inner.Right - 78, y, 78, 22), ContentAlignment.MiddleRight);

                        Rectangle bar = new Rectangle(inner.Left, y + 27, Math.Max(70, inner.Width - 118), 10);
                        DrawRoundedBar(g, bar, Color.FromArgb(51, 65, 85), availability < 0 ? 0 : availability, color);

                        string meta = stat.Devices.ToString(CultureInfo.InvariantCulture) + T(" disp. | ", " dev. | ") + stat.Samples.ToString(CultureInfo.InvariantCulture) + T(" muestras", " samples");
                        DrawText(g, meta, metaFont, TextMuted, new Rectangle(inner.Right - 112, y + 22, 112, 20), ContentAlignment.MiddleRight);
                    }

                    if (rows.Count > maxRows)
                    {
                        DrawText(g, "+" + (rows.Count - maxRows).ToString(CultureInfo.InvariantCulture) + T(" ubicaciones mas", " more locations"), metaFont, TextMuted, new Rectangle(inner.Left, inner.Bottom - 20, inner.Width, 20), ContentAlignment.MiddleCenter);
                    }
                }
            }

            private void DrawDetailsCard(Graphics g, Rectangle rect)
            {
                DrawCard(g, rect, Color.FromArgb(12, 24, 52), Color.FromArgb(18, 45, 75));
                Rectangle inner = Inflate(rect, -20, -18);
                using (Font titleFont = new Font("Segoe UI Semibold", 11F, FontStyle.Bold))
                using (Font smallFont = new Font("Segoe UI", 8.5F, FontStyle.Regular))
                using (Font valueFont = new Font("Segoe UI Semibold", 10F, FontStyle.Bold))
                {
                    DrawText(g, T("Detalle de ventana", "Window details"), titleFont, TextMain, new Rectangle(inner.Left, inner.Top, inner.Width, 24), ContentAlignment.MiddleLeft);

                    string window = _cutoff.ToString("dd/MM HH:mm", CultureInfo.InvariantCulture)
                        + "  -  "
                        + _now.ToString("dd/MM HH:mm", CultureInfo.InvariantCulture);
                    DrawMetricLine(g, inner.Left, inner.Top + 48, inner.Width, T("Periodo", "Period"), window, smallFont, valueFont);
                    DrawMetricLine(g, inner.Left, inner.Top + 84, inner.Width, T("Dispositivos", "Devices"), _total.Devices.ToString(CultureInfo.InvariantCulture), smallFont, valueFont);
                    DrawMetricLine(g, inner.Left, inner.Top + 120, inner.Width, T("Muestras", "Samples"), _total.Samples.ToString(CultureInfo.InvariantCulture), smallFont, valueFont);

                    string last = LastSampleText();
                    DrawMetricLine(g, inner.Left, inner.Top + 156, inner.Width, T("Ultima muestra", "Last sample"), last, smallFont, valueFont);
                }
            }

            private void DrawMetricLine(Graphics g, int x, int y, int width, string label, string value, Font labelFont, Font valueFont)
            {
                DrawText(g, label, labelFont, TextMuted, new Rectangle(x, y, width / 2, 24), ContentAlignment.MiddleLeft);
                DrawText(g, value, valueFont, TextMain, new Rectangle(x + (width / 2), y, width / 2, 24), ContentAlignment.MiddleRight);
                using (Pen pen = new Pen(Color.FromArgb(40, 55, 78)))
                {
                    g.DrawLine(pen, x, y + 29, x + width, y + 29);
                }
            }

            private void DrawLegend(Graphics g, Rectangle rect, Color color, string label, int value)
            {
                using (Brush brush = new SolidBrush(color))
                {
                    g.FillEllipse(brush, rect.Left, rect.Top + 5, 10, 10);
                }

                using (Font font = new Font("Segoe UI", 8.5F, FontStyle.Regular))
                using (Font valueFont = new Font("Segoe UI Semibold", 9.5F, FontStyle.Bold))
                {
                    DrawText(g, label, font, TextMuted, new Rectangle(rect.Left + 16, rect.Top, rect.Width - 70, rect.Height), ContentAlignment.MiddleLeft);
                    DrawText(g, value.ToString(CultureInfo.InvariantCulture), valueFont, TextMain, new Rectangle(rect.Right - 62, rect.Top, 62, rect.Height), ContentAlignment.MiddleRight);
                }
            }

            private void DrawDonut(Graphics g, Rectangle rect)
            {
                int samples = _total.Samples;
                float onlineAngle = samples == 0 ? 0F : (float)(_total.Online * 360.0 / samples);
                using (Brush baseBrush = new SolidBrush(Color.FromArgb(51, 65, 85)))
                {
                    g.FillPie(baseBrush, rect, -90, 360);
                }

                if (samples > 0)
                {
                    using (Brush onlineBrush = new SolidBrush(Color.FromArgb(34, 197, 94)))
                    using (Brush offlineBrush = new SolidBrush(Color.FromArgb(239, 68, 68)))
                    {
                        g.FillPie(onlineBrush, rect, -90, onlineAngle);
                        g.FillPie(offlineBrush, rect, -90 + onlineAngle, 360 - onlineAngle);
                    }
                }

                Rectangle hole = Inflate(rect, -22, -22);
                using (Brush holeBrush = new SolidBrush(Surface))
                {
                    g.FillEllipse(holeBrush, hole);
                }
            }

            private void DrawRoundedBar(Graphics g, Rectangle rect, Color back, double percent, Color fill)
            {
                RectangleF bounds = TechStyle.Align(rect);
                using (GraphicsPath path = TechStyle.RoundRect(bounds, 7F))
                using (Brush brush = new SolidBrush(back))
                {
                    g.FillPath(brush, path);
                }

                int fillWidth = (int)Math.Round(rect.Width * Math.Max(0.0, Math.Min(100.0, percent)) / 100.0);
                if (fillWidth > 0)
                {
                    Rectangle fillRect = new Rectangle(rect.Left, rect.Top, fillWidth, rect.Height);
                    using (GraphicsPath fillPath = TechStyle.RoundRect(TechStyle.Align(fillRect), 7F))
                    using (LinearGradientBrush fillBrush = new LinearGradientBrush(fillRect, fill, Color.FromArgb(125, 92, 255), LinearGradientMode.Horizontal))
                    {
                        g.FillPath(fillBrush, fillPath);
                    }
                }
            }

            private void DrawCard(Graphics g, Rectangle rect, Color color1, Color color2)
            {
                TechStyle.DrawTechPanel(
                    g,
                    TechStyle.Align(rect),
                    18F,
                    color1,
                    color2,
                    Color.FromArgb(84, 114, 147),
                    Color.FromArgb(48, 0, 229, 255));
            }

            private List<DashboardStats> GetVisibleStats()
            {
                List<DashboardStats> rows = new List<DashboardStats>();
                for (int i = 0; i < _stats.Count; i++)
                {
                    DashboardStats stat = _stats[i];
                    if (stat.Devices > 0 || stat.Samples > 0)
                    {
                        rows.Add(stat);
                    }
                }

                return rows;
            }

            private List<DashboardStats> GetVisibleSubcenterStats()
            {
                List<DashboardStats> rows = new List<DashboardStats>();
                for (int i = 0; i < _subcenterStats.Count; i++)
                {
                    DashboardStats stat = _subcenterStats[i];
                    if (stat.Devices > 0 || stat.Samples > 0)
                    {
                        rows.Add(stat);
                    }
                }

                return rows;
            }

            private double Availability(DashboardStats stat)
            {
                if (stat == null || stat.Samples == 0)
                {
                    return -1;
                }

                return stat.Online * 100.0 / stat.Samples;
            }

            private double WindowHours()
            {
                double hours = (_now - _cutoff).TotalHours;
                return hours <= 0 ? 72.0 : hours;
            }

            private string LastSampleText()
            {
                DateTime last = DateTime.MinValue;
                for (int i = 0; i < _stats.Count; i++)
                {
                    if (_stats[i].HasSample && _stats[i].LastSample > last)
                    {
                        last = _stats[i].LastSample;
                    }
                }

                return last == DateTime.MinValue ? T("Sin datos", "No data") : last.ToString("dd/MM/yyyy HH:mm", CultureInfo.InvariantCulture);
            }

            private string FormatDashboardDuration(TimeSpan value)
            {
                int hours = (int)Math.Floor(value.TotalHours);
                int minutes = value.Minutes;
                return hours.ToString(CultureInfo.InvariantCulture)
                    + " h "
                    + minutes.ToString("00", CultureInfo.InvariantCulture)
                    + T(" min activo", " min active");
            }

            private Color SubcenterColor(int index)
            {
                Color[] colors = new Color[]
                {
                    Color.FromArgb(0, 229, 255),
                    Color.FromArgb(79, 242, 185),
                    Color.FromArgb(127, 95, 255),
                    Color.FromArgb(255, 206, 96),
                    Color.FromArgb(56, 189, 248),
                    Color.FromArgb(244, 114, 182)
                };

                return colors[Math.Abs(index) % colors.Length];
            }

            private Color TechnologyColor(string technology)
            {
                string normalized = technology == null ? "" : technology.ToLowerInvariant();
                if (normalized.Contains("resguardo"))
                {
                    return Color.FromArgb(217, 70, 239);
                }

                if (normalized.Contains("lpr"))
                {
                    return Color.FromArgb(56, 189, 248);
                }

                if (normalized.Contains("arco"))
                {
                    return Color.FromArgb(251, 146, 60);
                }

                if (normalized.Contains("remolque"))
                {
                    return Color.FromArgb(168, 85, 247);
                }

                if (normalized.Contains("radio"))
                {
                    return Color.FromArgb(34, 211, 238);
                }

                if (normalized.Contains("switch"))
                {
                    return Color.FromArgb(250, 204, 21);
                }

                if (normalized.Contains("pmi"))
                {
                    return Color.FromArgb(45, 212, 191);
                }

                return Color.FromArgb(148, 163, 184);
            }

            private void DrawText(Graphics g, string text, Font font, Color color, Rectangle bounds, ContentAlignment alignment)
            {
                TextFormatFlags flags = TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix;
                if (alignment == ContentAlignment.MiddleCenter)
                {
                    flags |= TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter;
                }
                else if (alignment == ContentAlignment.MiddleRight)
                {
                    flags |= TextFormatFlags.Right | TextFormatFlags.VerticalCenter;
                }
                else
                {
                    flags |= TextFormatFlags.Left | TextFormatFlags.VerticalCenter;
                }

                TextRenderer.DrawText(g, text, font, bounds, color, flags);
            }

            private Rectangle Inflate(Rectangle rect, int dx, int dy)
            {
                Rectangle next = rect;
                next.Inflate(dx, dy);
                return next;
            }

            private GraphicsPath RoundRect(Rectangle rect, int radius)
            {
                GraphicsPath path = new GraphicsPath();
                if (rect.Width <= 1 || rect.Height <= 1)
                {
                    path.AddRectangle(rect);
                    return path;
                }

                radius = Math.Max(1, Math.Min(radius, Math.Min(rect.Width, rect.Height) / 2));
                int diameter = radius * 2;
                Rectangle arc = new Rectangle(rect.Location, new Size(diameter, diameter));

                path.AddArc(arc, 180, 90);
                arc.X = rect.Right - diameter;
                path.AddArc(arc, 270, 90);
                arc.Y = rect.Bottom - diameter;
                path.AddArc(arc, 0, 90);
                arc.X = rect.Left;
                path.AddArc(arc, 90, 90);
                path.CloseFigure();
                return path;
            }
        }

        private sealed class PingJob
        {
            public DeviceRecord Record;
            public int Timeout;
        }

        private sealed class PingResult
        {
            public DeviceRecord Record;
            public string Status;
            public string Latency;
            public bool Success;
            public DateTime CheckedAt;
            public string ErrorText;
        }
    }
}

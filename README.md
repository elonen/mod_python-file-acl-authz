# mod_python-file-acl-authz
*Authorize HTTPD user against requested file's ACL.*

A mod_python script that compares already authenticated Apache user with
requested file path's ACL to determine if that user is authorized to read
and/or write that directory.

This was written to allow Apache to serve read/write DAV access to several
Subversion repositories (using mod_svn's SVNParentPath), while
doing Single Sign On (SSO) through Kerberos / Windbind / GSSAPI and authorize
against Active Directory without doing explicit LDAP traversal.

While it's originally intended for use with Apache/SVN combo and Kerberos,
it works just as well with any Apache dir and, and "Auth-type Basic", for example.

## How it works

The script operates by calling `id user.name` to get user's effective groups and
compares them to ACL list of directory Apache is accessing.

For example, if you had...
```
drwxrwx--- 6 www-data acl_proj1_repo   4096 Apr  1 17:11 /mnt/repos/svn/svn-proj1
drwxrwx--- 6 www-data acl_proj2_repo   4096 Apr  1 19:00 /mnt/repos/svn/svn-proj2
```

...with the repoX directories looking like this...

```
drwxr-xr-x 2 www-data www-data 4096 Apr  1 19:00 conf
drwxr-sr-x 6 www-data www-data 4096 Apr  1 19:00 db
-r--r--r-- 1 www-data www-data    2 Apr  1 19:00 format
drwxr-xr-x 2 www-data www-data 4096 Apr  1 19:00 hooks
drwxr-xr-x 2 www-data www-data 4096 Apr  1 19:00 locks
-rw-r--r-- 1 www-data www-data  246 Apr  1 19:00 README.txt
```

...the script would check that authenticated user belongs to acl_proj1_repo
or acl_proj2_repo, and grant access accordingly. Note that *IT ONLY
CHECKS FOR THE ROOT DIRECTORY'S ACL*! The contents of the repository
directories are both owned by www-data (Apache), but this authz script
effectively applies its' permissions to the whole repository.

The script can check for unix group and/or ACL groups, and support both read
and write permissions. E.g. to grant read-only permissions to group
*acl_proj2_ro*, you could `setfacl -m g:grp_readonly_svn_users:r /mnt/repos/svn/svn-proj2`.

## Installation

To use, configure Apache for authentication first, then install mod_python, and add to your Apache configs something like this:

```
  PythonOption acl_authz_debug                  On
  PythonOption acl_authz_path_var               uri
  PythonOption acl_authz_prefix_to_strip        /svn/
  PythonOption acl_authz_acl_dir                /mnt/repos/svn/
  PythonAuthzHandler /mnt/repos/mod_python-file-acl-authz.py
  PythonDebug On
```

Restart Apache. Errors will be written to Apache's error log.

## A side note about SSO

While this script works perfectly fine without any SSO stuff, I supposed it might be of interest to many.
My Apache config for SSO against Active Directory looks basically like this:

``` 
# Authentication   
<LocationMatch "/repos/svn">

  # This used to be GSSAPI instead of mod_kerb, but
  # password fallback didn't work with it
  AuthType Kerberos
  AuthName "Subversion Repositories"
  KrbServiceName HTTP
  KrbMethodNegotiate On
  KrbMethodK5Passwd On
  KrbSaveCredentials Off
  KrbLocalUserMapping On
  KrbVerifyKDC On
  KrbAuthRealms MYDOMAIN.DIRECTORY
  Krb5KeyTab /etc/krb5.keytab
  require valid-user

</LocationMatch>

<Location "/repos/svn">
  # SVN + DAV
  DAV svn
  SVNParentPath /mnt/repos/svn
  SVNListParentPath On

  # Authorization
  PythonOption ACLCheckerRoot /mnt/repos/svn/
  PythonAuthzHandler /mnt/repos/mod_python-file-acl-authz.py
  PythonDebug On
</Location>
```

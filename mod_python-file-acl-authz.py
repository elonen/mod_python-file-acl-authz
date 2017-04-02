import posix1e
import string
import grp
import re
import os
from subprocess import Popen, PIPE
from mod_python import apache

# Written for Python 2.7

def check_acl(filename, username, log):
  '''
  Check which ACLs given user has for given file.

  @param filename		Absolute path to file to read ACL from
  @param username		Username to check ACL against
  @param log		req.log_error
  '''

  # Get ACL and traditional group lists for the file
  file_acl = posix1e.ACL(file=filename)
  stat_info = os.stat(filename)
  unix_group = grp.getgrgid(stat_info.st_gid).gr_name

  # Sanitize username before invoking shell
  valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
  username = ''.join(c for c in username if c in valid_chars)

  # List user's groups with 'id' command
  p = Popen(["id", "-n", "-G", "-z", username], stdin=PIPE, stdout=PIPE, stderr=PIPE)
  output, err = p.communicate(b'')
  user_groups = str(output).split("\0")

  # Walk through file's ACLs and compare to user's
  can_read = False
  can_write = False
  
  for l in [s.strip() for s in str(file_acl).splitlines()]:
    group = None
    perm = ''
    
    # Handle other ("everyone")
    if l[0:7] == 'other::':
      parts = l.split(':')
      perm = parts[2]
      
    # Handle actual group memberships
    elif l[0:6] == 'group:':
      parts = l.split(':')
      group = parts[1]
      
      # Check default unix group in addition to ACLs
      if group == '':
        group = unix_group
      
      if group in user_groups:
        perm = parts[2]
      
    can_write = can_write or ('w' in perm)
    can_read = can_read or ('r' in perm)
  
  return {'r':can_read, 'w':can_write}
    

# Test request against ACL, based on HTTP method, requested file and authenticated user
def authzhandler(req, **kwargs):
    opts = req.get_options()
    debug = ('acl_authz_debug' in opts) and (opts['acl_authz_debug'].lower() in ('yes', 'true', 'on'))

    # Decide wether to use filename or uri for determining
    # filename to check ACLs for
    path_var = 'filename'
    path = req.filename
    if 'acl_authz_path_var' in opts:
      path_var = opts['acl_authz_path_var']
      if path_var not in ('filename', 'uri'):
        req.log_error('auth_against_acl: Config error: acl_authz_path_var must be "filename" or "uri". Was "%s".' % path_var, apache.APLOG_CRIT)
        return apache.HTTP_INTERNAL_SERVER_ERROR
      if path_var == 'uri':
        path = req.uri

    # Check required prefix option
    if 'acl_authz_prefix_to_strip' not in opts:
      req.log_error('auth_against_acl misconfigured! Missing "PythonOption acl_authz_prefix_to_strip".', apache.APLOG_CRIT)
      return apache.HTTP_INTERNAL_SERVER_ERROR
    prefix = opts['acl_authz_prefix_to_strip'].rstrip('/') + '/'

    # Figure out which dir to look into for ACL check
    acl_dir = prefix
    if 'acl_authz_acl_dir' in opts:
      acl_dir = opts['acl_authz_acl_dir']

    if debug:
      req.log_error('auth_against_acl DEBUG: request USER=%s REQ_URI=%s REQ_FILE=%s METHOD=%s"' % (req.user, req.uri, req.filename, req.method), apache.APLOG_CRIT)

    # Get first dir/file after prefix and discard rest
    if path.startswith(prefix):
      path = path[len(prefix):]
      first = re.sub('/.*$', '', path)
      # Reconstruct final filepath
      path = acl_dir + first
    else:
      req.log_error('auth_against_acl: path "%s" not prefixed with "%s". DENYING.' % (path, prefix), apache.APLOG_WARNING)
      return apache.HTTP_FORBIDDEN

    # Check ACL against user and filename
    perms = {}
    try:
      perms = check_acl(path, req.user, req.log_error)
    except IOError as e:
      req.log_error('auth_against_acl ' + str(e) + " - PATH = " + str(path))
      return apache.HTTP_NOT_FOUND
    except Exception as e:
      req.log_error('auth_against_acl raised an Exception:' + str(e))

    if debug:
      req.log_error('auth_against_acl DEBUG: acl on file "%s" for user "%s" = %s' % (path, req.user, str(perms)), apache.APLOG_CRIT)

    # Depending on HTTP method, check either read or write permissions
    read_methods = ('OPTIONS', 'PROPFIND', 'GET', 'REPORT', 'HEAD')
    write_methods = ('MKACTIVITY', 'PROPPATCH', 'PUT', 'POST', 'CHECKOUT', 'MKCOL', 'MOVE', 'COPY', 'DELETE', 'LOCK', 'UNLOCK', 'MERGE', 'PATCH')
    if perms['r'] and req.method in read_methods:
      return apache.OK
    if perms['w'] and req.method in write_methods:
      return apache.OK
    
    if (req.method not in write_methods) and (req.method not in read_methods):
      req.log_error('auth_against_acl UNSUPPORTED METHOD: %s (USER=%s REQ_URI=%s REQ_FILE=%s)' % (req.method, req.user, req.uri, req.filename), apache.APLOG_WARNING)
      return apache.HTTP_METHOD_NOT_ALLOWED

    msg = 'auth_against_acl DENIED: USER=%s PATH=%s METHOD=%s PERMS=%s' % (req.user, path, req.method, str(perms))
    req.log_error(msg, apache.APLOG_WARNING)

    # Ugly hack: posing error message as an invalid XML element was the only way I could
    # persuade Svn client to actually show it:
    if req.method not in ('GET', 'POST'):
      req.write('<?xml version="1.0" encoding="utf-8" ?><%s/>' % (re.sub('[^a-zA-Z0-9_.-]', '_', msg)))

    return apache.HTTP_FORBIDDEN

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

    # Fetch parameters from request
    username = req.user
    method = req.method
    uri = req.uri
    filename = re.sub('^[^/:]*:', '', str(req.filename)) # remove 'dev_svn:' prefix (and the like)

    # Fetch root dir option
    opts = req.get_options()
    if 'ACLCheckerRoot' not in opts:
      req.log_error('auth_against_acl misconfigured! Missing "PythonOption ACLCheckerRoot".', apache.APLOG_CRIT)
      return apache.HTTP_INTERNAL_SERVER_ERROR
    root_dir = opts['ACLCheckerRoot'].rstrip('/') + '/'

    # Get first dir/filename after root_dir and discard rest.
    if filename.startswith(root_dir):
      filename = filename[len(root_dir):]
      first = re.sub('/.*$', '', filename)
      filename = root_dir + first
    else:
      req.log_error('auth_against_acl: filename "%s" not prefixed with root_dir "%s". DENYING.' % (filename, root_dir), apache.APLOG_WARNING)
      return apache.HTTP_UNAUTHORIZED

    # Check ACL against user and filename
    perms = {}
    try:
      perms = check_acl(filename, username, req.log_error)
    except IOError as e:
      req.log_error('auth_against_acl ' + str(e) + " : " + str(filename))
      return apache.HTTP_NOT_FOUND
    except Exception as e:
      req.log_error('auth_against_acl raised an Exception:' + str(e))

    # Depending on HTTP method, check either read or write permissions
    read_methods = ('OPTIONS', 'PROPFIND', 'GET', 'REPORT', 'HEAD')
    write_methods = ('MKACTIVITY', 'PROPPATCH', 'PUT', 'POST', 'CHECKOUT', 'MKCOL', 'MOVE', 'COPY', 'DELETE', 'LOCK', 'UNLOCK', 'MERGE', 'PATCH')
    if perms['r'] and method in read_methods:
      return apache.OK
    if perms['w'] and method in write_methods:
      return apache.OK
    
    if (method not in write_methods) and (method not in read_methods):
      req.log_error('auth_against_acl UNSUPPORTED METHOD: user=%s uri=%s file=%s method=%s perms=%s' % (username, uri, filename, method, str(perms)), apache.APLOG_WARNING)
      return apache.HTTP_METHOD_NOT_ALLOWED
    else:
      req.log_error('auth_against_acl DENIED: user=%s uri=%s file=%s method=%s perms=%s' % (username, uri, filename, method, str(perms)), apache.APLOG_WARNING)

    return apache.HTTP_UNAUTHORIZED

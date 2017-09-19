#
# Emulate what pam_nologin.c does.
#
import pwd

#
# Parse our command line.
#
def parse_args(pamh, argv):
  #
  # Parse the arguments.
  #
  nologin_file = "/etc/nologin"
  retval_when_nofile = pamh.PAM_IGNORE
  for arg in argv[1:]:
    if arg.starts_with("file="):
      nologin_file = arg[5:]
    elif arg == "successok":
      retval_when_nofile = pamh.PAM_SUCCESS
  return nologin_file, retval_when_nofile

#
# Check the /etc/nologin file.
#
def check_nologin(pamh, nologin_file, retval_when_nofile):
  #
  # Get the user name.
  #
  try:
    username = pamh.get_user()
  except pamh.exception:
    username = None
  if username == None:
    return pamh.PAM_USER_UNKNOWN
  #
  # Can we open the file?
  #
  try:
    handle = file(nologin_file, "r")
  except EnvironmentError:
    return retval_when_nofile
  #
  # Print the message.
  #
  try:
    try:
      msg = handle.read()
    except EnvironmentError:
      return pamh.PAM_SYSTEM_ERR
  finally:
    handle.close()
  #
  # Read the user's password entry so we can check if he is root.
  # Root can login regardless.
  #
  try:
    pwent = pwd.getpwnam(username)
  except KeyError:
    retval = pamh.PAM_USER_UNKNOWN
    msg_style = pamh.PAM_ERROR_MSG
  else:
    if pwent[2] == 0:			# Is this root?
      retval = pamh.PAM_SUCCESS
      msg_style = pamh.PAM_TEXT_INFO
    else:
      retval = pamh.PAM_AUTH_ERR
      msg_style = pamh.PAM_ERROR_MSG
  #
  # Display the message
  #
  try:
    pamh.conversation(pamh.Message(msg_style, msg))
  except pamh.exception:
    return pamh.PAM_SYSTEM_ERR
  return retval

#
# Entry points we handle.
#
def pam_sm_authenticate(pamh, flags, argv):
  nologin_file, retval_when_nofile = parse_args(pamh, argv)
  return check_nologin(pamh, nologin_file, retval_when_nofile)
  
def pam_sm_setcred(pamh, flags, argv):
  nologin_file, retval_when_nofile = parse_args(pamh, argv)
  return retval_when_nofile
  
def pam_sm_acct_mgmt(pamh, flags, argv):
  nologin_file, retval_when_nofile = parse_args(pamh, argv)
  return check_nologin(pamh, nologin_file, retval_when_nofile)

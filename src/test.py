#!/usr/bin/python -W default
#
# This is the test script for libpython-pam.  There aren't many stones
# left unturned.
#
# Best run from the Makefile using the target 'test'.  To run manually:
#   sudo ln -s $PWD/test-pam_python.pam /etc/pam.d
#   python test.py
#   sudo rm /etc/pam.d/test-pam_python.pam 
#
import warnings; warnings.simplefilter('default')
import os
import sys

TEST_PAM_MODULE	= "test-pam_python.pam"
TEST_PAM_USER	= "root"

#
# A Fairly straight forward test harness.
#
def pam_sm_end(pamh):
  return test(pam_sm_end, pamh, None, None)
def pam_sm_authenticate(pamh, flags, argv):
  return test(pam_sm_authenticate, pamh, flags, argv)
def pam_sm_setcred(pamh, flags, argv):
  return test(pam_sm_setcred, pamh, flags, argv)
def pam_sm_acct_mgmt(pamh, flags, argv):
  return test(pam_sm_acct_mgmt, pamh, flags, argv)
def pam_sm_open_session(pamh, flags, argv):
  return test(pam_sm_open_session, pamh, flags, argv)
def pam_sm_close_session(pamh, flags, argv):
  return test(pam_sm_close_session, pamh, flags, argv)
def pam_sm_chauthtok(pamh, flags, argv):
  return test(pam_sm_chauthtok, pamh, flags, argv)

def test(who, pamh, flags, argv):
  import test
  if not hasattr(test, "test_function"):# only true if not called via "main"
    return pamh.PAM_SUCCESS		# normally happens only if run by ctest
  test_function = globals()[test.test_function.__name__]
  return test_function(test.test_results, who, pamh, flags, argv)

def run_test(caller):
  import test
  test_name = caller.__name__[4:]
  sys.stdout.write("Testing " + test_name + " ")
  sys.stdout.flush()
  test.test_results = []
  test.test_function = globals()["test_" + test_name]
  caller(test.test_results)
  sys.stdout.write("OK\n")

def pam_conv(auth, query_list, userData=None):
  return query_list

#
# Verify the results match.
#
def assert_results(expected_results, results):
  for i in range(min(len(expected_results), len(results))):
    assert expected_results[i] == results[i], (i, expected_results[i], results[i])
  if len(expected_results) < len(results):
    assert len(expected_results) == len(results), (i, results[len(expected_results)])
  else:
    assert len(expected_results) == len(results), (i, expected_results[len(results)])

#
# Test all the calls happen.
#
def test_basic_calls(results, who, pamh, flags, argv):
  results.append((who.func_name, flags, argv))
  return pamh.PAM_SUCCESS
  
def run_basic_calls(results):
  pam = PAM.pam()
  pam.start(TEST_PAM_MODULE, TEST_PAM_USER, pam_conv)
  pam.authenticate(0)
  pam.acct_mgmt()
  pam.chauthtok()
  pam.open_session()
  pam.close_session()
  del pam
  me = os.path.join(os.getcwd(), __file__)
  expected_results = [
      (pam_sm_authenticate.func_name, 0, [me]),
      (pam_sm_acct_mgmt.func_name, 0, [me, 'arg1', 'arg2']),
      (pam_sm_chauthtok.func_name, 16384, [me]),
      (pam_sm_chauthtok.func_name, 8192, [me]),
      (pam_sm_open_session.func_name, 0, [me]),
      (pam_sm_close_session.func_name, 0, [me]),
      (pam_sm_end.func_name, None, None)]
  assert_results(expected_results, results)

#
# Test all the constants are defined.
#
PAM_CONSTANTS = {
    #
    # Constants defined in _pam_types.h.  The item constants are omitted.
    #
    "PAM_SUCCESS":			0,
    "PAM_OPEN_ERR":			1,
    "PAM_SYMBOL_ERR":			2,
    "PAM_SERVICE_ERR":			3,
    "PAM_SYSTEM_ERR":			4,
    "PAM_BUF_ERR":			5,
    "PAM_PERM_DENIED":			6,
    "PAM_AUTH_ERR":			7,
    "PAM_CRED_INSUFFICIENT":		8,
    "PAM_AUTHINFO_UNAVAIL":		9,
    "PAM_USER_UNKNOWN":			10,
    "PAM_MAXTRIES":			11,
    "PAM_NEW_AUTHTOK_REQD":		12,
    "PAM_ACCT_EXPIRED":			13,
    "PAM_SESSION_ERR":			14,
    "PAM_CRED_UNAVAIL":			15,
    "PAM_CRED_EXPIRED":			16,
    "PAM_CRED_ERR":			17,
    "PAM_NO_MODULE_DATA":		18,
    "PAM_CONV_ERR":			19,
    "PAM_AUTHTOK_ERR":			20,
    "PAM_AUTHTOK_RECOVER_ERR":		21,
    "PAM_AUTHTOK_RECOVERY_ERR":		21,
    "PAM_AUTHTOK_LOCK_BUSY":		22,
    "PAM_AUTHTOK_DISABLE_AGING":	23,
    "PAM_TRY_AGAIN":			24,
    "PAM_IGNORE":			25,
    "PAM_ABORT":			26,
    "PAM_AUTHTOK_EXPIRED":		27,
    "PAM_MODULE_UNKNOWN":		28,
    "PAM_BAD_ITEM":			29,
    "PAM_CONV_AGAIN":			30,
    "PAM_INCOMPLETE":			31,
    "PAM_SERVICE":			1,
    "PAM_USER":				2,
    "PAM_TTY":				3,
    "PAM_RHOST":			4,
    "PAM_CONV":				5,
    "PAM_AUTHTOK":			6,
    "PAM_OLDAUTHTOK":			7,
    "PAM_RUSER":			8,
    "PAM_USER_PROMPT":			9,
    "PAM_FAIL_DELAY":			10,
    "PAM_XDISPLAY":			11,
    "PAM_XAUTHDATA":			12,
    "PAM_AUTHTOK_TYPE":			13,
    "PAM_SILENT":			0x8000,
    "PAM_DISALLOW_NULL_AUTHTOK":	0x0001,
    "PAM_ESTABLISH_CRED":		0x0002,
    "PAM_DELETE_CRED":			0x0004,
    "PAM_REINITIALIZE_CRED":		0x0008,
    "PAM_REFRESH_CRED":			0x0010,
    "PAM_CHANGE_EXPIRED_AUTHTOK":	0x0020,
    "PAM_DATA_SILENT":			0x40000000,
    "PAM_PROMPT_ECHO_OFF":		1,
    "PAM_PROMPT_ECHO_ON":		2,
    "PAM_ERROR_MSG":			3,
    "PAM_TEXT_INFO":			4,
    "PAM_RADIO_TYPE":			5,
    "PAM_BINARY_PROMPT":		7,
    "PAM_MAX_NUM_MSG":			32,
    "PAM_MAX_MSG_SIZE":			512,
    "PAM_MAX_RESP_SIZE":		512,
    "_PAM_RETURN_VALUES":		32,
    #
    # Constants defined in pam_modules.h.  The item constants are omitted.
    #
    "PAM_PRELIM_CHECK":			0x4000,
    "PAM_UPDATE_AUTHTOK":		0x2000,
    "PAM_DATA_REPLACE":			0x20000000,
  }
def test_constants(results, who, pamh, flags, argv):
  results.append(who.func_name)
  if who != pam_sm_authenticate:
    return pamh.PAM_SUCCESS
  pam_constants = dict([
      (var, getattr(pamh,var))
      for var in dir(pamh)
      if var.startswith("PAM_") or var.startswith("_PAM_")])
  results.append(pam_constants)
  try:
    pamh.PAM_SUCCESS = 1
    results.append("Opps, pamh.PAM_SUCCESS = 1 worked!")
  except StandardError, e:
    results.append("except: %s" % e)
  return pamh.PAM_SUCCESS

def run_constants(results):
  pam = PAM.pam()
  pam.start(TEST_PAM_MODULE, TEST_PAM_USER, pam_conv)
  pam.authenticate(0)
  pam.close_session()
  del pam
  assert results[0] == pam_sm_authenticate.func_name, (results[0], pam_sm_authenticate.func_name)
  assert results[2] == "except: attribute 'PAM_SUCCESS' of 'PamHandle_type' objects is not writable", results[2]
  assert results[3] == pam_sm_close_session.func_name, (results[3], pam_sm_close_session.func_name)
  assert results[4] == pam_sm_end.func_name, (results[4], pam_sm_end.func_name)
  consts = results[1]
  for var in PAM_CONSTANTS.keys():
    assert consts.has_key(var), var
    assert consts[var] == PAM_CONSTANTS[var], (var, consts[var], PAM_CONSTANTS[var])
  for var in consts.keys():
    assert PAM_CONSTANTS.has_key(var), var
    assert PAM_CONSTANTS[var] == consts[var], (var, PAM_CONSTANTS[var], consts[var])
  assert len(results) == 5, len(results)

#
# Test the environment calls.
#
def test_environment(results, who, pamh, flags, argv):
  results.append(who.func_name)
  if who != pam_sm_acct_mgmt:
    return pamh.PAM_SUCCESS
  def test_exception(func):
    try:
      func()
      return str(None)
    except Exception, e:
      return e.__class__.__name__ + ": " + str(e)
  #
  # A few things to test here.  First that PamEnv_as_mapping works.
  #
  results.append(len(pamh.env))
  results.append(pamh.env["x1"])
  pamh.env["yy"] = "y"
  results.append(pamh.env["yy"])
  pamh.env["yy"] = "z"
  results.append(pamh.env["yy"])
  def t(): pamh.env["yy"] = 1
  results.append(test_exception(t))
  del pamh.env["yy"]
  results.append(test_exception(lambda: pamh.env["yy"]))
  results.append(test_exception(lambda: pamh.env[1]))
  results.append(test_exception(lambda: pamh.env['a=']))
  results.append(test_exception(lambda: pamh.env['']))
  #
  # Now the dict functions.
  #
  pamh.env["xx"] = "x"
  results.append("not in" in pamh.env)
  results.append("xx" in pamh.env)
  results.append(pamh.env.has_key("not in"))
  results.append(pamh.env.has_key("xx"))
  results.append(test_exception(lambda: pamh.env.__getitem__("not in")))
  results.append(pamh.env.get("not in"))
  results.append(pamh.env.get("not in", "default"))
  results.append(pamh.env.get("xx"))
  results.append(pamh.env.get("xx", "default"))
  del pamh.env["x1"]
  results.append(pamh.env.items())
  results.append(pamh.env.keys())
  results.append(pamh.env.values())
  return pamh.PAM_SUCCESS

def run_environment(results):
  pam = PAM.pam()
  pam.start(TEST_PAM_MODULE, TEST_PAM_USER, pam_conv)
  pam.authenticate(0)
  pam.putenv("x1=1")
  pam.putenv("x2=2")
  pam.putenv("x3=3")
  pam.acct_mgmt()
  pam.close_session()
  del pam
  expected_results = [
      pam_sm_authenticate.func_name, pam_sm_acct_mgmt.func_name,
      3, '1', 'y', 'z',
      'TypeError: PAM environment value must be a string',
      "KeyError: 'yy'",
      'TypeError: PAM environment key must be a string',
      "ValueError: PAM environment key can't contain '='",
      "ValueError: PAM environment key mustn't be 0 length",
      False, True, False, True,
      "KeyError: 'not in'",
      None, 'default', 'x', 'x',
      [('x2', '2'), ('x3', '3'), ('xx', 'x')],
      ['x2', 'x3', 'xx'],
      ['2', '3', 'x'],
      pam_sm_close_session.func_name, pam_sm_end.func_name]
  assert_results(expected_results, results)

#
# Test strerror().
#
def test_strerror(results, who, pamh, flags, argv):
  results.append(who.func_name)
  if who != pam_sm_authenticate:
    return pamh.PAM_SUCCESS
  results.extend([(e, pamh.strerror(e).lower()) for e in (0, 1, 30, 31)])
  return pamh.PAM_SUCCESS

def run_strerror(results):
  pam = PAM.pam()
  pam.start(TEST_PAM_MODULE, TEST_PAM_USER, pam_conv)
  pam.authenticate(0)
  del pam
  expected_results = [
      pam_sm_authenticate.func_name,
      ( 0, 'success'),
      ( 1, 'failed to load module'),
      (30, 'conversation is waiting for event'),
      (31, 'application needs to call libpam again'),
      pam_sm_end.func_name]
  assert_results(expected_results, results)

#
# Test items.
#
def test_items(results, who, pamh, flags, argv):
  results.append(who.func_name)
  if not who in (pam_sm_open_session, pam_sm_close_session):
    return pamh.PAM_SUCCESS
  items = {
	"authtok":	"authtok-module",
	"authtok_type":	"authtok_type-module",
	"oldauthtok":	"oldauthtok-module",
	"rhost":	"rhost-module",
	"ruser":	"ruser-module",
	"tty":		"tty-module",
	"user_prompt":	"user_prompt-module",
	"user":		"user-module",
	"xdisplay":	"xdisplay-module",
      }
  keys = items.keys()
  keys.sort()
  for key in keys:
    results.append((key, getattr(pamh, key)))
    value = items[key]
    if value != None:
      setattr(pamh, key, value)
  try:
    setattr(pamh, "tty", 1)
    results.append("%r = %r" % (key, value))
  except StandardError, e:
    results.append("except: %s" % e)
  results.append(pamh.get_user("a prompt"))
  return pamh.PAM_SUCCESS

def run_items(results):
  pam = PAM.pam()
  pam.start(TEST_PAM_MODULE, TEST_PAM_USER, pam_conv)
  pam.authenticate(0)
  items = {
      2:	"user",
      3:	"tty",
      4:	"rhost",
      8:	"ruser",
      9:	"user_prompt",
      11:	"xdisplay",
      13:	"authtok_type"}
  items_list = items.keys()
  items_list.sort()
  for item in items_list:
    pam.set_item(item, items[item])
  pam.open_session()
  pam.close_session()
  del pam
  expected_results = [
      pam_sm_authenticate.func_name, pam_sm_open_session.func_name,
      ('authtok',	None),
      ('authtok_type',	'authtok_type'),
      ('oldauthtok',	None),
      ('rhost',		'rhost'),
      ('ruser',		'ruser'),
      ('tty',		'tty'),
      ('user',		'user'),
      ('user_prompt',	'user_prompt'),
      ('xdisplay',	'xdisplay'),
      'except: PAM item PAM_TTY must be set to a string',
      'user-module',
      pam_sm_close_session.func_name,
      ('authtok',	'authtok-module'),
      ('authtok_type',	'authtok_type-module'),
      ('oldauthtok',	'oldauthtok-module'),
      ('rhost',		'rhost-module'),
      ('ruser',		'ruser-module'),
      ('tty',		'tty-module'),
      ('user',		'user-module'),
      ('user_prompt',	'user_prompt-module'),
      ('xdisplay',	'xdisplay-module'),
      'except: PAM item PAM_TTY must be set to a string',
      'user-module',
      pam_sm_end.func_name]
  assert_results(expected_results, results)

#
# Test the xauthdata item.
#
def test_xauthdata(results, who, pamh, flags, argv):
  results.append(who.func_name)
  if not who in (pam_sm_open_session, pam_sm_close_session):
    return pamh.PAM_SUCCESS
  xauthdata0 = pamh.XAuthData("name-module", "data-module")
  pamh.xauthdata = xauthdata0
  xauthdata1 = pamh.xauthdata
  results.append('name=%r, data=%r' % (xauthdata1.name, xauthdata1.data))
  try:
    xauthdata2 = pamh.XAuthData(None, "x")
    results.append('pamh.XAuthData(%r, %r)' % (xauthdata2.name, xauthdata2.data))
  except TypeError, e:
    results.append('except: %s' % e)
  try:
    xauthdata2 = pamh.XAuthData("x", 1)
    results.append('pamh.XAuthData(%r, %r)' % (xauthdata2.name, xauthdata2.data))
  except TypeError, e:
    results.append('except: %s' % e)
  class XA: pass
  XA.name = "name-XA"
  XA.data = "data-XA"
  pamh.xauthdata = XA
  xauthdata2 = pamh.xauthdata
  results.append('name=%r, data=%r' % (xauthdata2.name, xauthdata2.data))
  xa = XA()
  xa.name = "name-xa"
  xa.data = "data-xa"
  pamh.xauthdata = xa
  xauthdata4 = pamh.xauthdata
  results.append('name=%r, data=%r' % (xauthdata4.name, xauthdata4.data))
  return pamh.PAM_SUCCESS

def run_xauthdata(results):
  pam = PAM.pam()
  pam.start(TEST_PAM_MODULE, TEST_PAM_USER, pam_conv)
  pam.authenticate(0)
  #
  # The PAM module doesn't support XAUTHDATA, so check what we can from the
  # module only.
  #
  pam.open_session()
  pam.close_session()
  del pam
  expected_results = [
      pam_sm_authenticate.func_name, pam_sm_open_session.func_name,
      ("name='name-module', data='data-module'"),
      'except: XAuthData() argument 1 must be string, not None',
      'except: XAuthData() argument 2 must be string, not int',
      ("name='name-XA', data='data-XA'"),
      ("name='name-xa', data='data-xa'"),
      pam_sm_close_session.func_name,
      ("name='name-module', data='data-module'"),
      'except: XAuthData() argument 1 must be string, not None',
      'except: XAuthData() argument 2 must be string, not int',
      ("name='name-XA', data='data-XA'"),
      ("name='name-xa', data='data-xa'"),
      pam_sm_end.func_name]
  assert_results(expected_results, results)

#
# Test having no pam_sm_end.
#
def test_no_sm_end(results, who, pamh, flags, argv):
  results.append(who.func_name)
  global pam_sm_end
  del pam_sm_end
  return pamh.PAM_SUCCESS

def run_no_sm_end(results):
  pam = PAM.pam()
  pam.start(TEST_PAM_MODULE, TEST_PAM_USER, pam_conv)
  pam.authenticate(0)
  del pam
  expected_results = [pam_sm_authenticate.func_name]
  assert_results(expected_results, results)

#
# Test the conversation mechanism.
#
def test_conv(results, who, pamh, flags, argv):
  results.append(who.func_name)
  if who == pam_sm_end:
    return
  #
  # We must get rid of all references to pamh.Response objects.  This instance
  # of the test.py module is running inside of libpam_python.  That shared
  # library will be unloaded soon.  Should a pamh.Response instance be
  # dealloc'ed after it is unloaded the now non-existant dealloc function will
  # be called, and a SIGSEGV will result.  Normally instances would not leak,
  # but with the trickery we are performing with fake import's here they will
  # leak via the results variable unless we take special action.
  #
  def conv(convs):
    responses = pamh.conversation(convs)
    if type(responses) != type(()):
      return (responses.resp, responses.resp_retcode)
    return [(r.resp, r.resp_retcode) for r in responses]
  if who == pam_sm_authenticate:
    convs = [
	pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "Prompt_echo_off"),
	pamh.Message(pamh.PAM_PROMPT_ECHO_ON, "Prompt_echo_on"),
	pamh.Message(pamh.PAM_ERROR_MSG, "Error_msg"),
	pamh.Message(pamh.PAM_TEXT_INFO, "Text_info")]
  if who == pam_sm_acct_mgmt:
    convs = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "single")
  results.append(conv(convs))
  return pamh.PAM_SUCCESS

def run_conv(results):
  pam = PAM.pam()
  pam.start(TEST_PAM_MODULE, TEST_PAM_USER, pam_conv)
  pam.authenticate(0)
  pam.acct_mgmt()
  del pam
  expected_results = [
      pam_sm_authenticate.func_name,
      [('Prompt_echo_off', 1), ('Prompt_echo_on', 2), ('Error_msg', 3), ('Text_info', 4)],
      pam_sm_acct_mgmt.func_name,
      ('single', 1),
      pam_sm_end.func_name]
  assert_results(expected_results, results)

#
# Test pam error returns.
#
def test_pamerr(results, who, pamh, flags, argv):
  return results[-1]

def run_pamerr(results):
  pam = PAM.pam()
  pam.start(TEST_PAM_MODULE, TEST_PAM_USER, pam_conv)
  for err in range(0, PAM._PAM_RETURN_VALUES):
    results.append(err)
    try:
      pam.authenticate(0)
    except PAM.error, e:
      results[-1] = -e.args[1]
  del pam
  expected_results = [-r for r in range(PAM._PAM_RETURN_VALUES)]
  expected_results[25] = -6
  assert_results(expected_results, results)

#
# Test fail_delay.
#
def test_fail_delay(results, who, pamh, flags, argv):
  pamh.fail_delay(10)
  return pamh.PAM_SUCCESS

def run_fail_delay(results):
  pam = PAM.pam()
  pam.start(TEST_PAM_MODULE, TEST_PAM_USER, pam_conv)
  pam.authenticate(0)
  del pam

#
# Test raising an exception.
#
def test_exceptions(results, who, pamh, flags, argv):
  if who != pam_sm_end:
    return pamh.PAM_SUCCESS
  #
  # Here we have use of a backdoor put into pam_python.c specifically
  # for testing raising exceptions.  Oddly, normally PAM should never
  # return anything other than PAM_SUCCESS to anything pam_python.c
  # calls.
  #
  debug_magic = 0x4567abcd
  results.append(pamh._PAM_RETURN_VALUES)
  for err in range(pamh._PAM_RETURN_VALUES):
    try:
      pamh.strerror(debug_magic + err)
      results.append(err)
    except pamh.exception, e:
      results.append((-e.pam_result,))
  return pamh.PAM_SUCCESS

def run_exceptions(results):
  pam = PAM.pam()
  pam.start(TEST_PAM_MODULE, TEST_PAM_USER, pam_conv)
  pam.authenticate(0)
  del pam
  expected_results = [results[0], 0]
  expected_results += [(-r,) for r in range(1, results[0])]
  assert_results(expected_results, results)

#
# Test absent entry point.
#
def test_absent(results, who, pamh, flags, argv):
  results.append(who.func_name)
  if who != pam_sm_authenticate:
    return pamh.PAM_SUCCESS
  global pam_sm_acct_mgmt; del pam_sm_acct_mgmt
  global pam_sm_setcred; del pam_sm_setcred
  global pam_sm_open_session; del pam_sm_open_session
  global pam_sm_close_session; del pam_sm_close_session
  global pam_sm_chauthtok; del pam_sm_chauthtok
  return pamh.PAM_SUCCESS

def run_absent(results):
  pam = PAM.pam()
  pam.start(TEST_PAM_MODULE, TEST_PAM_USER, pam_conv)
  pam.authenticate(0)
  funcs = (
      pam.acct_mgmt,
      pam.setcred,
      pam.open_session,
      pam.close_session,
      pam.chauthtok
    )
  for func in funcs:
    try:
      func(0)
      exception = None
    except Exception, e:
      exception = e
    results.append((exception.__class__.__name__, str(exception)))
  del pam
  expected_results = [
      'pam_sm_authenticate',
      ('error', "('Symbol not found', 2)"),
      ('error', "('Symbol not found', 2)"),
      ('error', "('Symbol not found', 2)"),
      ('error', "('Symbol not found', 2)"),
      ('error', "('Symbol not found', 2)"),
    ]
  assert_results(expected_results, results)

#
# Entry point.
#
def main(argv):
  run_test(run_basic_calls)
  run_test(run_constants)
  run_test(run_environment)
  run_test(run_strerror)
  run_test(run_items)
  run_test(run_xauthdata)
  run_test(run_no_sm_end)
  run_test(run_conv)
  run_test(run_pamerr)
  run_test(run_fail_delay)
  run_test(run_exceptions)
  run_test(run_absent)

#
# If run from Python run the test suite.  Otherwse we are being used
# as a real PAM module presumable from ctest, so just make every call
# return success.
#
if __name__ == "__main__":
  import PAM
  main(sys.argv)

/*
 * Copyright (c) 2007-2012,2014,2016 Russell Stuart
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * The copyright holders grant you an additional permission under Section 7
 * of the GNU Affero General Public License, version 3, exempting you from
 * the requirement in Section 6 of the GNU General Public License, version 3,
 * to accompany Corresponding Source with Installation Information for the
 * Program or any work based on the Program. You are still required to
 * comply with all other Section 6 requirements to provide Corresponding
 * Source.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#ifndef __APPLE__
#include <security/_pam_macros.h>
#include <security/_pam_types.h>
#else
#include <security/pam_appl.h>
#include <security/pam_constants.h>
#define	_PAM_RETURN_VALUES	30	 // pam_types.h
#endif

#undef	_POSIX_C_SOURCE

#include <Python.h>
#include <dlfcn.h>
#include <signal.h>
#include <structmember.h>
#include <syslog.h>

#ifndef	MODULE_NAME
#define	MODULE_NAME		"libpam_python"
#endif

#ifndef	DEFAULT_SECURITY_DIR
#ifdef __APPLE__
#define DEFAULT_SECURITY_DIR	"/usr/lib/pam/"
#else
#define	DEFAULT_SECURITY_DIR	"/lib/security/"
#endif
#endif

#define	PAMHANDLE_NAME		"PamHandle"

#define	PAMHANDLEEXCEPTION_NAME	"PamException"

#define arr_size(x)	(sizeof(x) / sizeof(*(x)))

const char libpam_python_version[]	= "1.0.3";
const char libpam_python_date[]		= "2014-05-05";

/*
 * Add typedef for Py_ssize_t if it you have an older python.
 */
#if (PY_VERSION_HEX < 0x02050000)
typedef int Py_ssize_t;
#endif

/*
 * The python interpreter's shared library.
 */
static char libpython_so[]	= LIBPYTHON_SO;

/*
 * Initialise Python.  How this should be done changed between versions.
 */
static void initialise_python(void)
{
#if	PY_MAJOR_VERSION*100 + PY_MINOR_VERSION >= 204
  Py_InitializeEx(0);
#else
  size_t		signum;
  struct sigaction	oldsigaction[NSIG];

  for (signum = 0; signum < arr_size(oldsigaction); signum += 1)
    sigaction(signum, 0, &oldsigaction[signum]);
  Py_Initialize();
  for (signum = 0; signum < arr_size(oldsigaction); signum += 1)
    sigaction(signum, &oldsigaction[signum], 0);
#endif
}

/*
 * The Py_XDECREF macro gives warnings.  This function doesn't.
 */
static void py_xdecref(PyObject* object)
{
  Py_XDECREF(object);
}

/*
 * Generic traverse function for heap objects.
 */
static int generic_traverse(PyObject* self, visitproc visitor, void* arg)
{
  PyMemberDef*		member;
  int			member_visible;
  PyObject*		object;
  int			py_result;
  PyObject**		slot;

  member = self->ob_type->tp_members;
  if (member == 0)
    return 0;
  /*
   * Loop for python visible and python non-visible members.
   */
  for (member_visible = 0; member_visible < 2; member_visible += 1)
  {
    for (; member->name != 0; member += 1)
    {
      if (member->type != T_OBJECT && member->type != T_OBJECT_EX)
	continue;
      slot = (PyObject**)((char*)self + member->offset);
      object = *slot;
      if (object == 0)
	continue;
      py_result = visitor(object, arg);
      if (py_result != 0)
	return py_result;
    }
    member += 1;
  }
  return 0;
}

/*
 * Clear all slots in the object.
 */
static void clear_slot(PyObject** slot)
{
  PyObject*		object;

  object = *slot;
  if (object != 0)
  {
    *slot = 0;
    Py_DECREF(object);
  }
}

static int generic_clear(PyObject* self)
{
  PyMemberDef*		member;
  int			member_visible;

  member = self->ob_type->tp_members;
  if (member == 0)
    return 0;
  /*
   * Loop for python visible and python non-visible members.
   */
  for (member_visible = 0; member_visible < 2; member_visible += 1)
  {
    for (; member->name != 0; member += 1)
    {
      if (member->type != T_OBJECT && member->type != T_OBJECT_EX)
	continue;
      clear_slot((PyObject**)((char*)self + member->offset));
    }
    member += 1;
  }
  return 0;
}

/*
 * A dealloc for all our objects.
 */
static void generic_dealloc(PyObject* self)
{
  PyTypeObject*		type = self->ob_type;

  if (PyObject_IS_GC(self))
    PyObject_GC_UnTrack(self);
  if (type->tp_clear != 0)
    type->tp_clear(self);
  type->tp_free(self);
}

/*
 * The PamHandleObject - the object passed to all the python module's entry
 * points.
 */
typedef struct
{
  PyObject_HEAD				/* The Python Object Header */
  void*			dlhandle;	/* dlopen() handle */
  PyObject*		env;		/* pamh.env */
  PyObject*		exception;	/* pamh.exception */
  char*			libpam_version;	/* pamh.libpam_version */
  PyTypeObject*		message;	/* pamh.Message */
  PyObject*		module;		/* The Python Pam Module */
  pam_handle_t*		pamh;		/* The pam handle */
  PyObject*		print_exception;/* traceback.print_exception */
  int			py_initialized;	/* True if Py_initialize() called */
  PyTypeObject*		response;	/* pamh.Response */
  PyObject*		syslogFile;	/* A (the) SyslogFile instance */
  PyTypeObject*		xauthdata;	/* pamh.XAuthData */
} PamHandleObject;

/*
 * Forward declarations.
 */
static int call_python_handler(
    PyObject** result, PamHandleObject* pamHandle,
    PyObject* handler_function, const char* handler_name,
    int flags, int argc, const char** argv);

/*
 * The SyslogfileObject.  It emulates a Python file object (in that it has
 * a write method).  It prints to stuff passed to write() on syslog.
 */
#define	SYSLOGFILE_NAME		"SyslogFile"
typedef struct
{
  PyObject_HEAD				/* The Python Object Header */
  char*			buffer;		/* Line buffer */
  int			size;		/* Size of the buffer in bytes */
} SyslogFileObject;

/*
 * Clear the SyslogFileObject for the garbage collector.
 */
static int SyslogFile_clear(PyObject* self)
{
  SyslogFileObject*	syslogFile = (SyslogFileObject*)self;

  PyMem_Free(syslogFile->buffer);
  syslogFile->buffer = 0;
  syslogFile->size = 0;
  return generic_clear(self);
}

/*
 * Emulate python's file.write(), but write to syslog.
 */
static PyObject* SyslogFile_write(
    PyObject* self, PyObject* args, PyObject* kwds)
{
  SyslogFileObject*	syslogFile = (SyslogFileObject*)self;
  const char*		c;
  const char*		data = 0;
  int			len;
  const char*		newline;
  PyObject*		result = 0;
  static char* kwlist[] = {"data", NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "s:write", kwlist, &data))
    goto error_exit;
  if (syslogFile->buffer == 0)
    len = 0;
  else
    len = strlen(syslogFile->buffer);
  len += strlen(data) + 1;
  if (len > syslogFile->size)
  {
    const int new_size = len * 2;
    syslogFile->buffer = PyMem_Realloc(syslogFile->buffer, new_size);
    if (syslogFile->buffer == 0)
    {
      syslogFile->size = 0;
      goto error_exit;
    }
    if (syslogFile->size == 0)
      syslogFile->buffer[0] = '\0';
    syslogFile->size = new_size;
  }
  strcat(syslogFile->buffer, data);
  for (c = syslogFile->buffer; *c != '\0'; c = newline + 1) {
    newline = strchr(c, '\n');
    if (newline == 0)
      break;
    syslog(LOG_AUTHPRIV|LOG_ERR, "%.*s", (int)(newline - c), c);
  }
  if (c != syslogFile->buffer)
    strcpy(syslogFile->buffer, c);
  result = Py_None;
  Py_INCREF(result);

error_exit:
  return result;
}

/*
 * Emulate python's file.flush(), but write to syslog.
 */
static void SyslogFile_flush(PyObject* self)
{
  SyslogFileObject*	syslogFile = (SyslogFileObject*)self;

  if (syslogFile->buffer != 0 && syslogFile->buffer[0] != '\0')
  {
    syslog(LOG_AUTHPRIV|LOG_ERR, "%s", syslogFile->buffer);
    syslogFile->buffer[0] = '\0';
  }
}

static PyMethodDef SyslogFile_Methods[] =
{
  {
    "write",
    (PyCFunction)SyslogFile_write,
    METH_VARARGS|METH_KEYWORDS,
    0
  },
  {0,0,0,0}		/* Sentinal */
};

/*
 * Open syslog.
 */
static void syslog_open(const char* module_path)
{
  openlog(module_path, LOG_CONS|LOG_PID, LOG_AUTHPRIV);
}

/*
 * Close syslog.
 */
static void syslog_close(void)
{
  closelog();
}

/*
 * Type to translate a Python Exception to a PAM error.
 */
static int syslog_python2pam(PyObject* exception_type)
{
  if (exception_type == PyExc_MemoryError)
    return PAM_BUF_ERR;
  return PAM_SERVICE_ERR;
}

/*
 * Return the modules filename.
 */
static const char* get_module_path(PamHandleObject* pamHandle)
{
  const char* result = PyModule_GetFilename(pamHandle->module);
  if (result != 0)
    return result;
  return MODULE_NAME;
}

/*
 * Print an exception to syslog.
 */
static int syslog_path_exception(const char* module_path, const char* errormsg)
{
  PyObject*	message = 0;
  PyObject*	name = 0;
  PyObject*	ptype = 0;
  PyObject*	ptraceback = 0;
  PyObject*	pvalue = 0;
  int		pam_result = 0;
  PyObject*	stype = 0;
  const char*	str_name = 0;
  const char*	str_message = 0;

  PyErr_Fetch(&ptype, &pvalue, &ptraceback);
  /*
   * We don't have a PamHandleObject, so we can't print a full traceback.
   * Just print the exception in some recognisable form, hopefully.
   */
  syslog_open(module_path);
  if (PyClass_Check(ptype))
    stype = PyObject_GetAttrString(ptype, "__name__");
  else
  {
    stype = ptype;
    Py_INCREF(stype);
  }
  if (stype != 0)
  {
    name = PyObject_Str(stype);
    if (name != 0)
      str_name = PyString_AsString(name);
  }
  if (pvalue != 0)
  {
    message = PyObject_Str(pvalue);
    if (message != 0)
      str_message = PyString_AsString(message);
  }
  if (errormsg != 0 && str_name != 0 && str_message != 0)
  {
    syslog(
        LOG_AUTHPRIV|LOG_ERR, "%s - %s: %s",
	errormsg, str_name, str_message);
  }
  else if (str_name != 0 && str_message != 0)
    syslog(LOG_AUTHPRIV|LOG_ERR, "%s: %s", str_name, str_message);
  else if (errormsg != 0 && str_name != 0)
    syslog(LOG_AUTHPRIV|LOG_ERR, "%s - %s", errormsg, str_name);
  else if (errormsg != 0 && str_message != 0)
    syslog(LOG_AUTHPRIV|LOG_ERR, "%s - %s", errormsg, str_message);
  else if (errormsg != 0)
    syslog(LOG_AUTHPRIV|LOG_ERR, "%s", errormsg);
  else if (str_name != 0)
    syslog(LOG_AUTHPRIV|LOG_ERR, "%s", str_name);
  else if (str_message != 0)
    syslog(LOG_AUTHPRIV|LOG_ERR, "%s", str_message);
  pam_result = syslog_python2pam(ptype);
  py_xdecref(message);
  py_xdecref(name);
  py_xdecref(ptraceback);
  py_xdecref(ptype);
  py_xdecref(pvalue);
  py_xdecref(stype);
  syslog_close();
  return pam_result;
}

/*
 * Print an exception to syslog, once we are initialised.
 */
static int syslog_exception(PamHandleObject* pamHandle, const char* errormsg)
{
  return syslog_path_exception(get_module_path(pamHandle), errormsg);
}

/*
 * Print an message to syslog.
 */
static int syslog_path_vmessage(
    const char* module_path, const char* message, va_list ap)
{
  syslog_open(module_path);
  vsyslog(LOG_AUTHPRIV|LOG_ERR, message, ap);
  syslog_close();
  return PAM_SERVICE_ERR;
}

/*
 * Print an message to syslog.
 */
static int syslog_path_message(
    const char* module_path, const char* message, ...)
{
  va_list	ap;
  int		result;

  va_start(ap, message);
  result = syslog_path_vmessage(module_path, message, ap);
  va_end(ap);
  return result;
}

/*
 * Print an message to syslog, once we are initialised.
 */
static int syslog_message(PamHandleObject* pamHandle, const char* message, ...)
{
  va_list	ap;
  int		result;

  va_start(ap, message);
  result = syslog_path_vmessage(get_module_path(pamHandle), message, ap);
  va_end(ap);
  return result;
}

/*
 * Print a traceback to syslog.
 */
static int syslog_path_traceback(
    const char* module_path, PamHandleObject* pamHandle)
{
  PyObject*	args = 0;
  PyObject*	ptraceback = 0;
  PyObject*	ptype = 0;
  PyObject*	pvalue = 0;
  PyObject*	py_resultobj = 0;
  int		pam_result;

  PyErr_Fetch(&ptype, &pvalue, &ptraceback);
  /*
   * If there isn't a traceback just log the exception.
   */
  if (ptraceback == 0)
  {
    PyErr_Restore(ptype, pvalue, ptraceback);
    return syslog_path_exception(module_path, 0);
  }
  /*
   * Bit messy, this.  The easiest way to print a traceback is to use
   * the traceback module, writing through a dummy file that actually
   * outputs to syslog.
   */
  syslog_open(module_path);
  if (ptype == 0)
  {
    ptype = Py_None;
    Py_INCREF(ptype);
  }
  if (pvalue == 0)
  {
    pvalue = Py_None;
    Py_INCREF(pvalue);
  }
  args = Py_BuildValue(
      "OOOOO", ptype, pvalue, ptraceback, Py_None, pamHandle->syslogFile);
  if (args != 0)
  {
    py_resultobj = PyEval_CallObject(pamHandle->print_exception, args);
    if (py_resultobj != 0)
      SyslogFile_flush(pamHandle->syslogFile);
  }
  pam_result = syslog_python2pam(ptype);
  py_xdecref(args);
  py_xdecref(ptraceback);
  py_xdecref(ptype);
  py_xdecref(pvalue);
  py_xdecref(py_resultobj);
  syslog_close();
  return pam_result;
}

/*
 * Print an message to syslog, once we are initialised.
 */
static int syslog_traceback(PamHandleObject* pamHandle)
{
  return syslog_path_traceback(get_module_path(pamHandle), pamHandle);
}

/*
 * The PamMessage object - used in conversations.
 */
#define	PAMMESSAGE_NAME	"Message"
typedef struct
{
  PyObject_HEAD				/* The Python Object header */
  int			msg_style;	/* struct pam_message.msg_style */
  PyObject*		msg;		/* struct pam_message.msg */
} PamMessageObject;

static char PamMessage_doc[] =
  MODULE_NAME "." PAMHANDLE_NAME "." PAMMESSAGE_NAME "(msg_style, msg)\n"
  "  Constructs an immutable object that can be passed to\n"
  "  " MODULE_NAME "." PAMHANDLE_NAME ".conversation().  The parameters are\n"
  "  assigned to readonly members of the same name.  msg_style determines what\n"
  "  is done (eg prompt for input, write a message), and msg is the prompt or\n"
  "  message.";

static PyMemberDef PamMessage_members[] =
{
  {
    "msg_style",
    T_INT,
    offsetof(PamMessageObject, msg_style),
    READONLY,
    "What to do with the msg member, eg display it or use as a prompt.",
  },
  {
    "msg",
    T_OBJECT_EX,
    offsetof(PamMessageObject, msg),
    READONLY,
    "The text to display to the user",
  },
  {0,0,0,0,0},        	/* End of Python visible members */
  {0,0,0,0,0}		/* Sentinal */
};

static PyObject* PamMessage_new(
    PyTypeObject* type, PyObject* args, PyObject* kwds)
{
  int			err;
  PyObject*		msg = 0;
  int			msg_style = 0;
  PamMessageObject*	pamMessage = 0;
  PyObject*		self = 0;
  static char*		kwlist[] = {"msg_style", "msg", 0};

  err = PyArg_ParseTupleAndKeywords(
      args, kwds, "iO!:Message", kwlist,
      &msg_style, &PyString_Type, &msg);
  if (!err)
    goto error_exit;
  pamMessage = (PamMessageObject*)type->tp_alloc(type, 0);
  if (pamMessage == 0)
    goto error_exit;
  pamMessage->msg_style = msg_style;
  pamMessage->msg = msg;
  Py_INCREF(pamMessage->msg);
  self = (PyObject*)pamMessage;
  pamMessage = 0;

error_exit:
  py_xdecref((PyObject*)pamMessage);
  return self;
}

/*
 * The PamResponse object - used in conversations.
 */
#define	PAMRESPONSE_NAME	"Response"
typedef struct
{
  PyObject_HEAD				/* The Python Object header */
  PyObject*		resp;		/* struct pam_response.resp */
  int			resp_retcode;	/* struct pam_response.resp_retcode */
} PamResponseObject;

static char PamResponse_doc[] =
  MODULE_NAME "." PAMHANDLE_NAME "." PAMRESPONSE_NAME "(resp, resp_retcode)\n"
  "  Constructs an immutable object that is returned by\n"
  "  " MODULE_NAME "." PAMHANDLE_NAME ".conversation().  The parameters are\n"
  "  assigned to readonly members of the same name.  resp is the response from\n"
  "  the user (if one was asked for), and resp_retcode says what it means.";

static PyMemberDef PamResponse_members[] =
{
  {
    "resp",
    T_OBJECT_EX,
    offsetof(PamResponseObject, resp),
    READONLY,
    "The response from the user.",
  },
  {
    "resp_retcode",
    T_INT,
    offsetof(PamResponseObject, resp_retcode),
    READONLY,
    "The type of response.",
  },
  {0,0,0,0,0},        	/* End of Python visible members */
  {0,0,0,0,0}		/* Sentinal */
};

static PyObject* PamResponse_new(
    PyTypeObject* type, PyObject* args, PyObject* kwds)
{
  int			err;
  PyObject*		resp = 0;
  int			resp_retcode = 0;
  PamResponseObject*	pamResponse = 0;
  PyObject*		self = 0;
  static char*		kwlist[] = {"resp", "resp_retcode", 0};

  err = PyArg_ParseTupleAndKeywords(
      args, kwds, "Oi:Response", kwlist,
      &resp, &resp_retcode);
  if (!err)
    goto error_exit;
  if (resp != Py_None && !PyString_Check(resp))
  {
    PyErr_SetString(PyExc_TypeError, "resp must be a string or None");
    goto error_exit;
  }
  pamResponse = (PamResponseObject*)type->tp_alloc(type, 0);
  if (pamResponse == 0)
    goto error_exit;
  pamResponse->resp_retcode = resp_retcode;
  pamResponse->resp = resp;
  Py_INCREF(pamResponse->resp);
  self = (PyObject*)pamResponse;
  pamResponse = 0;

error_exit:
  py_xdecref((PyObject*)pamResponse);
  return self;
}

/*
 * The PamXAuthData object - used by PAM_XAUTHDATA item.
 */
#define	PAMXAUTHDATA_NAME	"XAuthData"
typedef struct
{
  PyObject_HEAD				/* The Python Object header */
  PyObject*		name;		/* struct pam_xauth_data.name */
  PyObject*		data;		/* struct pam_xauth_data.data */
} PamXAuthDataObject;

static char PamXAuthData_doc[] =
  MODULE_NAME "." PAMHANDLE_NAME "." PAMXAUTHDATA_NAME "(name, data)\n"
  "  Constructs an immutable object is returned by and can be passed to\n"
  "  the " MODULE_NAME ".xauthdata property.  The parameters are\n"
  "  assigned to readonly members of the same name.";

static PyMemberDef PamXAuthData_members[] =
{
  {
    "data",
    T_OBJECT_EX,
    offsetof(PamXAuthDataObject, data),
    READONLY,
    "The value of the data item. A string or None.",
  },
  {
    "name",
    T_OBJECT_EX,
    offsetof(PamXAuthDataObject, name),
    READONLY,
    "The name of the data item.  A string or None.",
  },
  {0,0,0,0,0},        	/* End of Python visible members */
  {0,0,0,0,0}		/* Sentinal */
};

static PyObject* PamXAuthData_new(
    PyTypeObject* type, PyObject* args, PyObject* kwds)
{
  int			err;
  PyObject*		name = 0;
  PyObject*		data = 0;
  PamXAuthDataObject*	pamXAuthData = 0;
  PyObject*		self = 0;
  static char*		kwlist[] = {"name", "data", 0};

  err = PyArg_ParseTupleAndKeywords(
      args, kwds, "SS:XAuthData", kwlist,
      &name, &data);
  if (!err)
    goto error_exit;
  pamXAuthData = (PamXAuthDataObject*)type->tp_alloc(type, 0);
  if (pamXAuthData == 0)
    goto error_exit;
  pamXAuthData->name = name;
  Py_INCREF(pamXAuthData->name);
  pamXAuthData->data = data;
  Py_INCREF(pamXAuthData->data);
  self = (PyObject*)pamXAuthData;
  pamXAuthData = 0;

error_exit:
  py_xdecref((PyObject*)pamXAuthData);
  return self;
}

/*
 * Check a PAM return value.  If the function failed raise an exception
 * and return -1.
 */
static int check_pam_result(PamHandleObject* pamHandle, int pam_result)
{
  if (pam_result == PAM_SUCCESS)
    return 0;
  if (!PyErr_Occurred())
  {
    PyObject* ptype;
    PyObject* pvalue;
    PyObject* ptraceback;
    PyObject* error_code = 0;
    const char* error_string = pam_strerror(pamHandle->pamh, pam_result);

    PyErr_SetString(pamHandle->exception, error_string);
    PyErr_Fetch(&ptype, &pvalue, &ptraceback);
    PyErr_NormalizeException(&ptype, &pvalue, &ptraceback);
    error_code = PyInt_FromLong(pam_result);
    if (error_code != NULL)
      PyObject_SetAttrString(pvalue, "pam_result", error_code);
    PyErr_Restore(ptype, pvalue, ptraceback);
    py_xdecref(error_code);
  }
  return -1;
}

/*
 * Python getters / setters are used to manipulate PAM's items.
 */
static PyObject* PamHandle_get_item(PyObject* self, int item_type)
{
  PamHandleObject*	pamHandle = (PamHandleObject*)self;
  const char*		value;
  PyObject*		result = 0;
  int			pam_result;

  pam_result = pam_get_item(pamHandle->pamh, item_type, (const void**)&value);
  if (check_pam_result(pamHandle, pam_result) == -1)
    goto error_exit;
  if (value != 0)
    result = PyString_FromString(value);
  else
  {
    result = Py_None;
    Py_INCREF(result);
  }

error_exit:
  return result;
}

static int PamHandle_set_item(
    PyObject* self, int item_type, char* item_name, PyObject* pyValue)
{
  PamHandleObject*	pamHandle = (PamHandleObject*)self;
  int			pam_result;
  int			result = -1;
  char*			value;
  char			error_message[64];

  if (pyValue == Py_None)
    value = 0;
  else
  {
    value = PyString_AsString(pyValue);
    if (value == 0)
    {
      snprintf(
          error_message, sizeof(error_message),
	  "PAM item %s must be set to a string", item_name);
      PyErr_SetString(PyExc_TypeError, error_message);
      goto error_exit;
    }
    value = strdup(value);
    if (value == 0)
    {
      PyErr_NoMemory();
      goto error_exit;
    }
  }
  pam_result = pam_set_item(pamHandle->pamh, item_type, value);
  if (pam_result == PAM_SUCCESS)
    value = 0;
  result = check_pam_result(pamHandle, pam_result);

error_exit:
  if (value != 0)
    free(value);
  return result;
}

/*
 * The PAM Environment Object & its iterator.
 */
#define	PAMENV_NAME	"PamEnv"
typedef struct
{
  PyObject_HEAD				/* The Python Object header */
  PamHandleObject*	pamHandle;	/* The PamHandle that owns us */
  PyTypeObject*		pamEnvIter_type;/* A class for our iterators */
} PamEnvObject;

static PyMemberDef PamEnv_Members[] =
{
  {0,0,0,0,0},        	/* End of Python visible members */
  {
    "Iter",
    T_OBJECT_EX,
    offsetof(PamEnvObject, pamEnvIter_type),
    READONLY,
    "Iterator class for " PAMENV_NAME
  },
  {0,0,0,0,0}        	/* Sentinel */
};

#define	PAMENVITER_NAME	"PamEnvIter"
typedef struct
{
  PyObject_HEAD
  PamEnvObject*		env;		/* The PamEnvObject we are iterating */
  int			pos;		/* Nest position to return */
  PyObject*		(*get_entry)(const char* entry); /* What to return */
} PamEnvIterObject;

static PyMemberDef PamEnvIter_Members[] =
{
  {0,0,0,0,0},        	/* End of Python visible members */
  {
    "env",
    T_OBJECT_EX,
    offsetof(PamEnvIterObject, env),
    READONLY,
    "Dictionary to iterate"
  },
  {0,0,0,0,0}        	/* Sentinel */
};

/*
 * Create a new iterator for a PamEnv.
 */
static PyObject* PamEnvIter_create(
  PamEnvObject* pamEnv, PyObject* (*get_entry)(const char* entry))
{
  PyTypeObject*		type = pamEnv->pamEnvIter_type;
  PamEnvIterObject*	pamEnvIter;
  PyObject*		result = 0;

  pamEnvIter = (PamEnvIterObject*)type->tp_alloc(type, 0);
  if (pamEnvIter == 0)
    goto error_exit;
  pamEnvIter->env = pamEnv;
  Py_INCREF(pamEnvIter->env);
  pamEnvIter->get_entry = get_entry;
  pamEnvIter->pos = 0;
  result = (PyObject*)pamEnvIter;
  Py_INCREF(result);

error_exit:
  py_xdecref((PyObject*)pamEnvIter);
  return result;
}

/*
 * Return the next object in the iteration.
 */
static PyObject* PamEnvIter_iternext(PyObject* self)
{
  PamEnvIterObject*	pamEnvIter = (PamEnvIterObject*)self;
  char**		env;
  int			i;
  PyObject*		result;

  if (pamEnvIter->env == 0)
    goto error_exit;
  env = pam_getenvlist(pamEnvIter->env->pamHandle->pamh);
  if (env == 0)
    goto error_exit;
  for (i = 0; env[i] != 0 && i < pamEnvIter->pos; i += 1)
    continue;
  if (env[i] == 0)
    goto error_exit;
  result = pamEnvIter->get_entry(env[i]);
  if (result == 0)
    goto error_exit;
  pamEnvIter->pos += 1;
  return result;

error_exit:
  clear_slot((PyObject**)&pamEnvIter->env);
  return 0;
}

/*
 * Return a python object for the key part.
 */
static PyObject* PamEnvIter_key_entry(const char* entry)
{
  const char*		equals;

  equals = strchr(entry, '=');
  if (equals == 0)
    return PyString_FromString(entry);
  return PyString_FromStringAndSize(entry, equals - entry);
}

/*
 * Return a python object for the value part.
 */
static PyObject* PamEnvIter_value_entry(const char* entry)
{
  const char*		equals;

  equals = strchr(entry, '=');
  if (equals == 0)
    return PyString_FromString("");
  return PyString_FromString(equals + 1);
}

/*
 * Return a python object entire item.
 */
static PyObject* PamEnvIter_item_entry(const char* entry)
{
  PyObject*		key = 0;
  PyObject*		result = 0;
  PyObject*		tuple = 0;
  PyObject*		value = 0;

  key = PamEnvIter_key_entry(entry);
  if (key == 0)
    goto error_exit;
  value = PamEnvIter_value_entry(entry);
  if (key == 0)
    goto error_exit;
  tuple = PyTuple_New(2);
  if (tuple == 0)
    goto error_exit;
  if (PyTuple_SetItem(tuple, 0, key) == -1)
    goto error_exit;
  key = 0;			/* was stolen */
  if (PyTuple_SetItem(tuple, 1, value) == -1)
    goto error_exit;
  value = 0;			/* was stolen */
  result = tuple;
  tuple = 0;

error_exit:
  py_xdecref(key);
  py_xdecref(tuple);
  py_xdecref(value);
  return result;
}

/*
 * Create an iterator.
 */
static PyObject* PamEnv_iter(PyObject* self)
{
  PamEnvObject*		pamEnv = (PamEnvObject*)self;

  return PamEnvIter_create(pamEnv, PamEnvIter_key_entry);
}

/*
 * Get the value of a environment key.
 */
static const char* PamEnv_getkey(PyObject* key)
{
  const char*		result;

  if (!PyString_Check(key))
  {
    PyErr_SetString(PyExc_TypeError, "PAM environment key must be a string");
    return 0;
  }
  result = PyString_AS_STRING(key);
  if (*result == '\0')
  {
    PyErr_SetString(
        PyExc_ValueError,
	"PAM environment key mustn't be 0 length");
    return 0;
  }
  if (strchr(result, '=') != 0)
  {
    PyErr_SetString(PyExc_ValueError, "PAM environment key can't contain '='");
    return 0;
  }
  return result;
}

/*
 * Return the length.
 */
static Py_ssize_t PamEnv_mp_length(PyObject* self)
{
  PamEnvObject*		pamEnv = (PamEnvObject*)self;
  char**		env;
  int			length;

  env = pam_getenvlist(pamEnv->pamHandle->pamh);
  if (env == 0)
    return 0;
  for (length = 0; env[length] != 0; length += 1)
    continue;
  return length;
}

/*
 * Lookup a key returning its value.
 */
static PyObject* PamEnv_mp_subscript(PyObject* self, PyObject* key)
{
  PamEnvObject*		pamEnv = (PamEnvObject*)self;
  PyObject*		result = 0;
  const char*		key_str;
  const char*		value;

  key_str = PamEnv_getkey(key);
  if (key_str == 0)
    goto error_exit;
  value = pam_getenv(pamEnv->pamHandle->pamh, key_str);
  if (value == 0)
  {
    PyErr_SetString(PyExc_KeyError, key_str);
    goto error_exit;
  }
  result = PyString_FromString(value);

error_exit:
  return result;
}

/*
 * Assign a value to a key, or delete it.
 */
static int PamEnv_mp_assign(PyObject* self, PyObject* key, PyObject* value)
{
  PamEnvObject*		pamEnv = (PamEnvObject*)self;
  char*			value_str = 0;
  int			result = -1;
  const char*		key_str;
  int			pam_result;

  key_str = PamEnv_getkey(key);
  if (key_str == 0)
    goto error_exit;
  if (value == 0)
    value_str = (char*)key_str;
  else
  {
    if (!PyString_Check(value))
    {
      PyErr_SetString(
          PyExc_TypeError, "PAM environment value must be a string");
      goto error_exit;
    }
    value_str = malloc(PyString_Size(key) + 1 + PyString_Size(value) + 1);
    if (value_str == 0)
    {
      PyErr_NoMemory();
      goto error_exit;
    }
    strcat(strcat(strcpy(value_str, key_str), "="), PyString_AS_STRING(value));
  }
  pam_result = pam_putenv(pamEnv->pamHandle->pamh, value_str);
  if (pam_result != PAM_SUCCESS) // PAM_BAD_ITEM in Linux = PAM_BUF_ERR,PAM_SYSTEM_ERR
  {
    PyErr_SetString(PyExc_KeyError, key_str);
    goto error_exit;
  }
  if (check_pam_result(pamEnv->pamHandle, pam_result) == -1)
    goto error_exit;
  value_str = 0;
  result = 0;

error_exit:
  if (value_str != key_str && value_str != 0)
    free(value_str);
  return result;
}

static PyMappingMethods PamEnv_as_mapping =
{
  PamEnv_mp_length,	/* mp_length */
  PamEnv_mp_subscript,	/* mp_subscript */
  PamEnv_mp_assign,	/* mp_ass_subscript */
};

/*
 * Check if a key is in the environment.
 */
static PyObject* PamEnv_has_key(
    PyObject* self, PyObject* args, PyObject* kwds)
{
  PamEnvObject*		pamEnv = (PamEnvObject*)self;
  PyObject*		key;
  PyObject*		result = 0;
  const char*		key_str;
  const char*		value_str;
  static char*		kwlist[] = {"key", NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:has_key", kwlist, &key))
    goto error_exit;
  key_str = PamEnv_getkey(key);
  if (key_str == 0)
    goto error_exit;
  value_str = pam_getenv(pamEnv->pamHandle->pamh, key_str);
  result = value_str != 0 ? Py_True : Py_False;
  Py_INCREF(result);

error_exit:
  return result;
}

/*
 * Lookup a key and return its value, throwing KeyError if the key
 * doesn't exist.
 */
static PyObject* PamEnv_getitem(
    PyObject* self, PyObject* args, PyObject* kwds)
{
  PyObject*		result = 0;
  PyObject*		key;
  static char*		kwlist[] = {"key", NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:__getitem__", kwlist, &key))
    goto error_exit;
  result = PamEnv_mp_subscript(self, key);

error_exit:
  return result;
}

/*
 * Lookup a key and return its value, returning None or a default if it
 * doesn't exist.
 */
static PyObject* PamEnv_get(
    PyObject* self, PyObject* args, PyObject* kwds)
{
  int			err;
  PamEnvObject*		pamEnv = (PamEnvObject*)self;
  PyObject*		default_value = 0;
  PyObject*		result = 0;
  PyObject*		key;
  const char*		key_str;
  const char*		value_str;
  static char*		kwlist[] = {"key", "default", NULL};

  err = PyArg_ParseTupleAndKeywords(
      args, kwds, "O|O:get", kwlist,
      &key, &default_value);
  if (!err)
    goto error_exit;
  key_str = PamEnv_getkey(key);
  if (key_str == 0)
    goto error_exit;
  value_str = pam_getenv(pamEnv->pamHandle->pamh, key_str);
  if (value_str != 0)
    result = PyString_FromString(value_str);
  else
  {
    result = default_value != 0 ? default_value : Py_None;
    Py_INCREF(result);
  }

error_exit:
  return result;
}

/*
 * Return all objects in the environment as a sequence.
 */
static PyObject* PamEnv_as_sequence(
    PyObject* self, PyObject* (*get_entry)(const char* entry))
{
  PamEnvObject*		pamEnv = (PamEnvObject*)self;
  PyObject*		list = 0;
  PyObject*		result = 0;
  PyObject*		entry = 0;
  char**		env;
  int			i;
  int			length;

  env = pam_getenvlist(pamEnv->pamHandle->pamh);
  if (env == 0)
    length = 0;
  else
  {
    for (length = 0; env[length] != 0; length += 1)
      continue;
  }
  list = PyList_New(length);
  if (list == 0)
    goto error_exit;
  for (i = 0; env[i] != 0; i += 1)
  {
    entry = get_entry(env[i]);
    if (entry == 0)
      goto error_exit;
    if (PyList_SetItem(list, i, entry) == -1)
      goto error_exit;
    entry = 0;			/* was stolen */
  }
  result = list;
  list = 0;

error_exit:
  py_xdecref(list);
  py_xdecref(entry);
  return result;
}

/*
 * Return all (key, value) pairs.
 */
static PyObject* PamEnv_items(
    PyObject* self, PyObject* args, PyObject* kwds)
{
  static char*		kwlist[] = {NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwds, ":items", kwlist))
    return 0;
  return PamEnv_as_sequence(self, PamEnvIter_item_entry);
}

/*
 * An iterator for all (key, value) pairs.
 */
static PyObject* PamEnv_iteritems(
    PyObject* self, PyObject* args, PyObject* kwds)
{
  PamEnvObject*		pamEnv = (PamEnvObject*)self;
  static char*		kwlist[] = {NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwds, ":iteritems", kwlist))
    return 0;
  return PamEnvIter_create(pamEnv, PamEnvIter_item_entry);
}

/*
 * An iterator for the keys.
 */
static PyObject* PamEnv_iterkeys(
    PyObject* self, PyObject* args, PyObject* kwds)
{
  PamEnvObject*		pamEnv = (PamEnvObject*)self;
  static char*		kwlist[] = {NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwds, ":iterkeys", kwlist))
    return 0;
  return PamEnvIter_create(pamEnv, PamEnvIter_key_entry);
}

/*
 * An iterator for the values.
 */
static PyObject* PamEnv_itervalues(
    PyObject* self, PyObject* args, PyObject* kwds)
{
  PamEnvObject*		pamEnv = (PamEnvObject*)self;
  static char*		kwlist[] = {NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwds, ":itervalues", kwlist))
    return 0;
  return PamEnvIter_create(pamEnv, PamEnvIter_value_entry);
}

/*
 * Return all keys.
 */
static PyObject* PamEnv_keys(
    PyObject* self, PyObject* args, PyObject* kwds)
{
  static char*		kwlist[] = {NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwds, ":keys", kwlist))
    return 0;
  return PamEnv_as_sequence(self, PamEnvIter_key_entry);
}

/*
 * Return all (key, value) pairs.
 */
static PyObject* PamEnv_values(
    PyObject* self, PyObject* args, PyObject* kwds)
{
  static char*		kwlist[] = {NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwds, ":values", kwlist))
    return 0;
  return PamEnv_as_sequence(self, PamEnvIter_value_entry);
}

static PyMethodDef PamEnv_Methods[] =
{
  {"__contains__",  (PyCFunction)PamEnv_has_key,METH_VARARGS|METH_KEYWORDS, 0},
  {"__getitem__",   (PyCFunction)PamEnv_getitem,METH_VARARGS|METH_KEYWORDS, 0},
  {"get",	    (PyCFunction)PamEnv_get,	METH_VARARGS|METH_KEYWORDS, 0},
  {"has_key",	    (PyCFunction)PamEnv_has_key,METH_VARARGS|METH_KEYWORDS, 0},
  {"items",	    (PyCFunction)PamEnv_items,	METH_VARARGS|METH_KEYWORDS, 0},
  {"iteritems",	    (PyCFunction)PamEnv_iteritems,METH_VARARGS|METH_KEYWORDS, 0},
  {"iterkeys",	    (PyCFunction)PamEnv_iterkeys,METH_VARARGS|METH_KEYWORDS, 0},
  {"itervalues",    (PyCFunction)PamEnv_itervalues,METH_VARARGS|METH_KEYWORDS, 0},
  {"keys",	    (PyCFunction)PamEnv_keys,	METH_VARARGS|METH_KEYWORDS, 0},
  {"values",	    (PyCFunction)PamEnv_values,	METH_VARARGS|METH_KEYWORDS, 0},
  {0,0,0,0}        	/* Sentinel */
};

/*
 * Python Getter's for the constants.
 */
#define	DECLARE_CONSTANT_GET_VALUE(x, v) \
  static PyObject* PamHandle_Constant_ ## x(PyObject* object, void* closure) { \
    object = object; \
    closure = closure; \
    return PyLong_FromLong(v); \
  }

#define	DECLARE_CONSTANT_GET(x)	\
  static PyObject* PamHandle_Constant_ ## x(PyObject* object, void* closure) { \
    object = object; \
    closure = closure; \
    return PyLong_FromLong(x); \
  }

#ifdef	HAVE_PAM_FAIL_DELAY
DECLARE_CONSTANT_GET_VALUE(HAVE_PAM_FAIL_DELAY, 1)
#else
DECLARE_CONSTANT_GET_VALUE(HAVE_PAM_FAIL_DELAY, 0)
#endif
DECLARE_CONSTANT_GET(PAM_ABORT)
DECLARE_CONSTANT_GET(PAM_ACCT_EXPIRED)
DECLARE_CONSTANT_GET(PAM_AUTH_ERR)
DECLARE_CONSTANT_GET(PAM_AUTHINFO_UNAVAIL)
DECLARE_CONSTANT_GET(PAM_AUTHTOK)
DECLARE_CONSTANT_GET(PAM_AUTHTOK_DISABLE_AGING)
DECLARE_CONSTANT_GET(PAM_AUTHTOK_ERR)
DECLARE_CONSTANT_GET(PAM_AUTHTOK_EXPIRED)
DECLARE_CONSTANT_GET(PAM_AUTHTOK_LOCK_BUSY)
#ifdef	PAM_AUTHTOK_RECOVERY_ERR
DECLARE_CONSTANT_GET(PAM_AUTHTOK_RECOVERY_ERR)
#endif
#ifdef	PAM_AUTHTOK_RECOVER_ERR
DECLARE_CONSTANT_GET(PAM_AUTHTOK_RECOVER_ERR)
#endif
#ifdef	PAM_AUTHTOK_TYPE
DECLARE_CONSTANT_GET(PAM_AUTHTOK_TYPE)
#endif
#ifdef PAM_BAD_ITEM
DECLARE_CONSTANT_GET(PAM_BAD_ITEM)
#endif
#ifdef PAM_BINARY_PROMPT
DECLARE_CONSTANT_GET(PAM_BINARY_PROMPT)
#endif
DECLARE_CONSTANT_GET(PAM_BUF_ERR)
DECLARE_CONSTANT_GET(PAM_CHANGE_EXPIRED_AUTHTOK)
DECLARE_CONSTANT_GET(PAM_CONV)
#ifdef PAM_CONV_AGAIN
DECLARE_CONSTANT_GET(PAM_CONV_AGAIN)
#endif
DECLARE_CONSTANT_GET(PAM_CONV_ERR)
DECLARE_CONSTANT_GET(PAM_CRED_ERR)
DECLARE_CONSTANT_GET(PAM_CRED_EXPIRED)
DECLARE_CONSTANT_GET(PAM_CRED_INSUFFICIENT)
DECLARE_CONSTANT_GET(PAM_CRED_UNAVAIL)
#ifdef PAM_DATA_REPLACE
DECLARE_CONSTANT_GET(PAM_DATA_REPLACE)
#endif
#ifdef PAM_DATA_SILENT
DECLARE_CONSTANT_GET(PAM_DATA_SILENT)
#endif
DECLARE_CONSTANT_GET(PAM_DELETE_CRED)
DECLARE_CONSTANT_GET(PAM_DISALLOW_NULL_AUTHTOK)
DECLARE_CONSTANT_GET(PAM_ERROR_MSG)
DECLARE_CONSTANT_GET(PAM_ESTABLISH_CRED)
#ifdef PAM_FAIL_DELAY
DECLARE_CONSTANT_GET(PAM_FAIL_DELAY)
#endif
DECLARE_CONSTANT_GET(PAM_IGNORE)
#ifdef PAM_INCOMPLETE
DECLARE_CONSTANT_GET(PAM_INCOMPLETE)
#endif
DECLARE_CONSTANT_GET(PAM_MAX_MSG_SIZE)
DECLARE_CONSTANT_GET(PAM_MAX_NUM_MSG)
DECLARE_CONSTANT_GET(PAM_MAX_RESP_SIZE)
DECLARE_CONSTANT_GET(PAM_MAXTRIES)
DECLARE_CONSTANT_GET(PAM_MODULE_UNKNOWN)
DECLARE_CONSTANT_GET(PAM_NEW_AUTHTOK_REQD)
DECLARE_CONSTANT_GET(PAM_NO_MODULE_DATA)
DECLARE_CONSTANT_GET(PAM_OLDAUTHTOK)
DECLARE_CONSTANT_GET(PAM_OPEN_ERR)
DECLARE_CONSTANT_GET(PAM_PERM_DENIED)
DECLARE_CONSTANT_GET(PAM_PRELIM_CHECK)
DECLARE_CONSTANT_GET(PAM_PROMPT_ECHO_OFF)
DECLARE_CONSTANT_GET(PAM_PROMPT_ECHO_ON)
#ifdef PAM_RADIO_TYPE
DECLARE_CONSTANT_GET(PAM_RADIO_TYPE)
#endif
DECLARE_CONSTANT_GET(PAM_REFRESH_CRED)
DECLARE_CONSTANT_GET(PAM_REINITIALIZE_CRED)
DECLARE_CONSTANT_GET(_PAM_RETURN_VALUES)
DECLARE_CONSTANT_GET(PAM_RHOST)
DECLARE_CONSTANT_GET(PAM_RUSER)
DECLARE_CONSTANT_GET(PAM_SERVICE)
DECLARE_CONSTANT_GET(PAM_SERVICE_ERR)
DECLARE_CONSTANT_GET(PAM_SESSION_ERR)
DECLARE_CONSTANT_GET(PAM_SILENT)
DECLARE_CONSTANT_GET(PAM_SUCCESS)
DECLARE_CONSTANT_GET(PAM_SYMBOL_ERR)
DECLARE_CONSTANT_GET(PAM_SYSTEM_ERR)
DECLARE_CONSTANT_GET(PAM_TEXT_INFO)
DECLARE_CONSTANT_GET(PAM_TRY_AGAIN)
DECLARE_CONSTANT_GET(PAM_TTY)
DECLARE_CONSTANT_GET(PAM_UPDATE_AUTHTOK)
DECLARE_CONSTANT_GET(PAM_USER)
DECLARE_CONSTANT_GET(PAM_USER_PROMPT)
DECLARE_CONSTANT_GET(PAM_USER_UNKNOWN)
#ifdef	PAM_XAUTHDATA
DECLARE_CONSTANT_GET(PAM_XAUTHDATA)
#endif
#ifdef	PAM_XDISPLAY
DECLARE_CONSTANT_GET(PAM_XDISPLAY)
#endif

#define	CONSTANT_GETSET(x) {#x,    PamHandle_Constant_ ## x, 0, 0, 0}

#define	MAKE_GETSET_ITEM(t) \
  static PyObject* PamHandle_get_##t(PyObject* self, void* closure) \
  { \
    closure = closure; \
    return PamHandle_get_item(self, PAM_##t); \
  } \
  static int PamHandle_set_##t(PyObject* self, PyObject* pyValue, void* closure) \
  { \
    closure = closure; \
    return PamHandle_set_item(self, PAM_##t, "PAM_" #t, pyValue); \
  }

MAKE_GETSET_ITEM(AUTHTOK)
#ifdef	PAM_AUTHTOK_TYPE
MAKE_GETSET_ITEM(AUTHTOK_TYPE)
#endif
MAKE_GETSET_ITEM(OLDAUTHTOK)
MAKE_GETSET_ITEM(RHOST)
MAKE_GETSET_ITEM(RUSER)
MAKE_GETSET_ITEM(SERVICE)
MAKE_GETSET_ITEM(TTY)
MAKE_GETSET_ITEM(USER)
MAKE_GETSET_ITEM(USER_PROMPT)
#ifdef	PAM_XDISPLAY
MAKE_GETSET_ITEM(XDISPLAY)
#endif

#ifdef	PAM_XAUTHDATA
/*
 * The PAM_XAUTHDATA item doesn't take strings like the rest of them.
 * It wants a pam_xauth_data structure.
 */
static PyObject* PamHandle_get_XAUTHDATA(PyObject* self, void* closure)
{
  PamHandleObject*	pamHandle = (PamHandleObject*)self;
  PyObject*		newargs = 0;
  PyObject*		result = 0;
  int			pam_result;
  struct pam_xauth_data* xauth_data = 0;

  closure = closure;
  pam_result = pam_get_item(
      pamHandle->pamh, PAM_XAUTHDATA, (const void**)&xauth_data);
  if (check_pam_result(pamHandle, pam_result) == -1)
    goto error_exit;
  if (xauth_data == 0)
  {
    result = Py_None;
    Py_INCREF(result);
  }
  else
  {
    newargs = Py_BuildValue(
        "s#s#",
	xauth_data->name, xauth_data->namelen,
	xauth_data->data, xauth_data->datalen);
    if (newargs == 0)
      goto error_exit;
    result = pamHandle->xauthdata->tp_new(pamHandle->xauthdata, newargs, 0);
    if (result == 0)
      goto error_exit;
  }

error_exit:
  py_xdecref(newargs);
  return result;
}

static int PamHandle_set_XAUTHDATA(
    PyObject* self, PyObject* pyValue, void* closure)
{
  PamHandleObject*	pamHandle = (PamHandleObject*)self;
  PyObject*		name = 0;
  PyObject*		data = 0;
  int			result = -1;
  const char*		data_str;
  const char*		name_str;
  int			pam_result;
  struct pam_xauth_data	xauth_data;

  closure = closure;
  xauth_data.name = 0;
  xauth_data.data = 0;
  /*
   * Get the name.
   */
  name = PyObject_GetAttrString(pyValue, "name");
  if (name == 0)
    goto error_exit;
  name_str = PyString_AsString(name);
  if (name_str == 0)
  {
    PyErr_SetString(PyExc_TypeError, "xauthdata.name must be a string");
    goto error_exit;
  }
  xauth_data.name = strdup(name_str);
  if (xauth_data.name == 0)
  {
    PyErr_NoMemory();
    goto error_exit;
  }
  xauth_data.namelen = PyString_GET_SIZE(name);
  /*
   * Get the data.
   */
  data = PyObject_GetAttrString(pyValue, "data");
  if (data == 0)
    goto error_exit;
  data_str = PyString_AsString(data);
  if (data_str == 0)
  {
    PyErr_SetString(PyExc_TypeError, "xauthdata.data must be a string");
    goto error_exit;
  }
  xauth_data.data = strdup(data_str);
  if (xauth_data.data == 0)
  {
    PyErr_NoMemory();
    goto error_exit;
  }
  xauth_data.datalen = PyString_GET_SIZE(data);
  /*
   * Set the item.  If that worked PAM will have swallowed the strings inside
   * of it, so we must not free them.
   */
  pam_result = pam_set_item(pamHandle->pamh, PAM_XAUTHDATA, &xauth_data);
  if (pam_result == PAM_SUCCESS)
  {
    xauth_data.name = 0;
    xauth_data.data = 0;
  }
  result = check_pam_result(pamHandle, pam_result);

error_exit:
  py_xdecref(data);
  py_xdecref(name);
  if (xauth_data.name != 0)
    free(xauth_data.name);
  if (xauth_data.data != 0)
    free(xauth_data.data);
  return result;
}
#endif

/*
 * Getters and setters.
 */
static PyGetSetDef PamHandle_Getset[] =
{
  /*
   * Items.
   */
  {"authtok",     PamHandle_get_AUTHTOK,     PamHandle_set_AUTHTOK,     "Authentication token", 0},
#ifdef	PAM_AUTHTOK_TYPE
  {"authtok_type",PamHandle_get_AUTHTOK_TYPE,PamHandle_set_AUTHTOK_TYPE,"XXX in the \"New XXX password:\" prompt", 0},
#endif
  {"oldauthtok",  PamHandle_get_OLDAUTHTOK,  PamHandle_set_OLDAUTHTOK,  "Old authentication token", 0},
  {"rhost",       PamHandle_get_RHOST,       PamHandle_set_RHOST,       "Requesting host name", 0},
  {"ruser",       PamHandle_get_RUSER,       PamHandle_set_RUSER,       "Requesting user name", 0},
  {"service",     PamHandle_get_SERVICE,     PamHandle_set_SERVICE,     "Service (pam stack) name", 0},
  {"tty",         PamHandle_get_TTY,         PamHandle_set_TTY,         "Terminal name", 0},
  {"user",        PamHandle_get_USER,        PamHandle_set_USER,        "Authorized user name", 0},
  {"user_prompt", PamHandle_get_USER_PROMPT, PamHandle_set_USER_PROMPT, "Prompt asking for users name", 0},
#ifdef	PAM_XAUTHDATA
  {"xauthdata",	  PamHandle_get_XAUTHDATA,   PamHandle_set_XAUTHDATA,   "The name of the X display ($DISPLAY)", 0},
#endif
#ifdef	PAM_XDISPLAY
  {"xdisplay",	  PamHandle_get_XDISPLAY,    PamHandle_set_XDISPLAY,    "The name of the X display ($DISPLAY)", 0},
#endif
  /*
   * Constants.
   */
  CONSTANT_GETSET(HAVE_PAM_FAIL_DELAY),
  CONSTANT_GETSET(PAM_ABORT),
  CONSTANT_GETSET(PAM_ACCT_EXPIRED),
  CONSTANT_GETSET(PAM_AUTH_ERR),
  CONSTANT_GETSET(PAM_AUTHINFO_UNAVAIL),
  CONSTANT_GETSET(PAM_AUTHTOK),
  CONSTANT_GETSET(PAM_AUTHTOK_DISABLE_AGING),
  CONSTANT_GETSET(PAM_AUTHTOK_ERR),
  CONSTANT_GETSET(PAM_AUTHTOK_EXPIRED),
  CONSTANT_GETSET(PAM_AUTHTOK_LOCK_BUSY),
#ifdef	PAM_AUTHTOK_RECOVERY_ERR
  CONSTANT_GETSET(PAM_AUTHTOK_RECOVERY_ERR),
#endif
#ifdef 	PAM_AUTHTOK_RECOVER_ERR
  CONSTANT_GETSET(PAM_AUTHTOK_RECOVER_ERR),
#endif
#ifdef	PAM_AUTHTOK_TYPE
  CONSTANT_GETSET(PAM_AUTHTOK_TYPE),
#endif
#ifdef PAM_BAD_ITEM
  CONSTANT_GETSET(PAM_BAD_ITEM),
#endif
#ifdef PAM_BINARY_PROMPT
  CONSTANT_GETSET(PAM_BINARY_PROMPT),
#endif
  CONSTANT_GETSET(PAM_BUF_ERR),
  CONSTANT_GETSET(PAM_CHANGE_EXPIRED_AUTHTOK),
  CONSTANT_GETSET(PAM_CONV),
#ifdef PAM_CONV_AGAIN
  CONSTANT_GETSET(PAM_CONV_AGAIN),
#endif
  CONSTANT_GETSET(PAM_CONV_ERR),
  CONSTANT_GETSET(PAM_CRED_ERR),
  CONSTANT_GETSET(PAM_CRED_EXPIRED),
  CONSTANT_GETSET(PAM_CRED_INSUFFICIENT),
  CONSTANT_GETSET(PAM_CRED_UNAVAIL),
#ifdef PAM_DATA_REPLACE
  CONSTANT_GETSET(PAM_DATA_REPLACE),
#endif
#ifdef PAM_DATA_SILENT
  CONSTANT_GETSET(PAM_DATA_SILENT),
#endif
  CONSTANT_GETSET(PAM_DELETE_CRED),
  CONSTANT_GETSET(PAM_DISALLOW_NULL_AUTHTOK),
  CONSTANT_GETSET(PAM_ERROR_MSG),
  CONSTANT_GETSET(PAM_ESTABLISH_CRED),
#ifdef PAM_FAIL_DELAY
  CONSTANT_GETSET(PAM_FAIL_DELAY),
#endif
  CONSTANT_GETSET(PAM_IGNORE),
#ifdef PAM_INCOMPLETE
  CONSTANT_GETSET(PAM_INCOMPLETE),
#endif
  CONSTANT_GETSET(PAM_MAX_MSG_SIZE),
  CONSTANT_GETSET(PAM_MAX_NUM_MSG),
  CONSTANT_GETSET(PAM_MAX_RESP_SIZE),
  CONSTANT_GETSET(PAM_MAXTRIES),
  CONSTANT_GETSET(PAM_MODULE_UNKNOWN),
  CONSTANT_GETSET(PAM_NEW_AUTHTOK_REQD),
  CONSTANT_GETSET(PAM_NO_MODULE_DATA),
  CONSTANT_GETSET(PAM_OLDAUTHTOK),
  CONSTANT_GETSET(PAM_OPEN_ERR),
  CONSTANT_GETSET(PAM_PERM_DENIED),
  CONSTANT_GETSET(PAM_PRELIM_CHECK),
  CONSTANT_GETSET(PAM_PROMPT_ECHO_OFF),
  CONSTANT_GETSET(PAM_PROMPT_ECHO_ON),
#ifdef PAM_RADIO_TYPE
  CONSTANT_GETSET(PAM_RADIO_TYPE),
#endif
  CONSTANT_GETSET(PAM_REFRESH_CRED),
  CONSTANT_GETSET(PAM_REINITIALIZE_CRED),
  CONSTANT_GETSET(_PAM_RETURN_VALUES),
  CONSTANT_GETSET(PAM_RHOST),
  CONSTANT_GETSET(PAM_RUSER),
  CONSTANT_GETSET(PAM_SERVICE),
  CONSTANT_GETSET(PAM_SERVICE_ERR),
  CONSTANT_GETSET(PAM_SESSION_ERR),
  CONSTANT_GETSET(PAM_SILENT),
  CONSTANT_GETSET(PAM_SUCCESS),
  CONSTANT_GETSET(PAM_SYMBOL_ERR),
  CONSTANT_GETSET(PAM_SYSTEM_ERR),
  CONSTANT_GETSET(PAM_TEXT_INFO),
  CONSTANT_GETSET(PAM_TRY_AGAIN),
  CONSTANT_GETSET(PAM_TTY),
  CONSTANT_GETSET(PAM_UPDATE_AUTHTOK),
  CONSTANT_GETSET(PAM_USER),
  CONSTANT_GETSET(PAM_USER_PROMPT),
  CONSTANT_GETSET(PAM_USER_UNKNOWN),
#ifdef  PAM_XAUTHDATA
  CONSTANT_GETSET(PAM_XAUTHDATA),
#endif
#ifdef	PAM_XDISPLAY
  CONSTANT_GETSET(PAM_XDISPLAY),
#endif
  {0,0,0,0,0}        	/* Sentinel */
};

/*
 * Convert a PamHandleObject.Message style object to a pam_message structure.
 */
static int PamHandle_conversation_2message(
    struct pam_message* message, PyObject* object)
{
  PyObject*		msg = 0;
  PyObject*		msg_style = 0;
  int			result = -1;

  msg_style = PyObject_GetAttrString(object, "msg_style");
  if (msg_style == 0)
    goto error_exit;
  if (!PyInt_Check(msg_style) && !PyLong_Check(msg_style))
  {
    PyErr_SetString(PyExc_TypeError, "message.msg_style must be an int");
    goto error_exit;
  }
  message->msg_style = PyInt_AsLong(msg_style);
  msg = PyObject_GetAttrString(object, "msg");
  if (msg == 0)
    goto error_exit;
  message->msg = PyString_AsString(msg);
  if (message->msg == 0)
  {
    PyErr_SetString(PyExc_TypeError, "message.msg must be a string");
    goto error_exit;
  }
  result = 0;

error_exit:
  py_xdecref(msg);
  py_xdecref(msg_style);
  return result;
}

/*
 * Convert a pam_response structure to a PamHandleObject.Response object.
 */
static PyObject* PamHandle_conversation_2response(
    PamHandleObject* pamHandle, struct pam_response* pam_response)
{
  PyObject*		newargs;
  PyObject*  		result = 0;

  newargs = Py_BuildValue("si", pam_response->resp, pam_response->resp_retcode);
  if (newargs == 0)
    goto error_exit;
  result = pamHandle->response->tp_new(pamHandle->response, newargs, 0);
  if (result == 0)
    goto error_exit;

error_exit:
  py_xdecref(newargs);
  return result;
}

/*
 * Run a PAM "conversation".
 */
static PyObject* PamHandle_conversation(
    PyObject* self, PyObject* args, PyObject* kwds)
{
  int			err;
  PamHandleObject*	pamHandle = (PamHandleObject*)self;
  PyObject*		prompts = 0;
  PyObject*		result_tuple = 0;
  struct pam_message*	message_array = 0;
  struct pam_message**	message_vector = 0;
  struct pam_response*	response_array = 0;
  PyObject*		result = 0;
  PyObject*		response = 0;
  const struct pam_conv*conv;
  int			prompt_count;
  int			i;
  int			pam_result;
  int			prompts_is_sequence;
  int			py_result;
  static char*		kwlist[] = {"prompts", NULL};

  err = PyArg_ParseTupleAndKeywords(
      args, kwds, "O:conversation", kwlist,
      &prompts);
  if (!err)
    goto error_exit;
  pam_result = pam_get_item(pamHandle->pamh, PAM_CONV, (const void**)&conv);
  if (check_pam_result(pamHandle, pam_result) == -1)
    goto error_exit;
  prompts_is_sequence = PySequence_Check(prompts);
  if (!prompts_is_sequence)
    prompt_count = 1;
  else
  {
    prompt_count = PySequence_Size(prompts);
    if (prompt_count == 0)
    {
      result = prompts;
      Py_INCREF(result);
      goto error_exit;
    }
  }
  message_array = PyMem_Malloc(prompt_count * sizeof(*message_array));
  if (message_array == 0)
  {
    PyErr_NoMemory();
    goto error_exit;
  }
  if (!prompts_is_sequence)
  {
    py_result = PamHandle_conversation_2message(message_array, prompts);
    if (py_result == -1)
      goto error_exit;
  }
  else
  {
    for (i = 0; i < prompt_count; i += 1)
    {
      PyObject* message = PySequence_ITEM(prompts, i);
      if (message == 0)
        goto error_exit;
      py_result = PamHandle_conversation_2message(&message_array[i], message);
      Py_DECREF(message);
      if (py_result == -1)
        goto error_exit;
    }
  }
  message_vector = PyMem_Malloc(prompt_count * sizeof(*message_vector));
  if (message_vector == 0)
  {
    PyErr_NoMemory();
    goto error_exit;
  }
  for (i = 0; i < prompt_count; i += 1)
    message_vector[i] = &message_array[i];
  pam_result = conv->conv(
    prompt_count, (const struct pam_message**)message_vector,
    &response_array, conv->appdata_ptr);
  if (check_pam_result(pamHandle, pam_result) == -1)
    goto error_exit;
  if (!prompts_is_sequence)
    result = PamHandle_conversation_2response(pamHandle, response_array);
  else
  {
    result_tuple = PyTuple_New(prompt_count);
    if (result_tuple == 0)
      goto error_exit;
    for (i = 0; i < prompt_count; i += 1)
    {
      response = PamHandle_conversation_2response(
          pamHandle, &response_array[i]);
      if (response == 0)
        goto error_exit;
      if (PyTuple_SetItem(result_tuple, i, response) == -1)
	goto error_exit;
      response = 0;			/* was stolen */
    }
    result = result_tuple;
    result_tuple = 0;
  }

error_exit:
  py_xdecref(response);
  py_xdecref(result_tuple);
  PyMem_Free(message_array);
  PyMem_Free(message_vector);
  if (response_array != 0)
   free(response_array);
  return result;
}

/*
 * Set the fail delay.
 */
static PyObject* PamHandle_fail_delay(
    PyObject* self, PyObject* args, PyObject* kwds)
{
  int			err;
  int			micro_sec = 0;
  int			pam_result;
  PyObject*		result = 0;
  static char*		kwlist[] = {"micro_sec", NULL};

  err = PyArg_ParseTupleAndKeywords(
      args, kwds, "i:fail_delay", kwlist,
      &micro_sec);
  if (!err)
    goto error_exit;
#ifndef HAVE_PAM_FAIL_DELAY
  (void)self;
#else
  {
    PamHandleObject*	pamHandle = (PamHandleObject*)self;
    pam_result = pam_fail_delay(pamHandle->pamh, micro_sec);
    if (check_pam_result(pamHandle, pam_result) == -1)
      goto error_exit;
  }
#endif
  result = Py_None;
  Py_INCREF(result);

error_exit:
  return result;
}

/*
 * Get the user's name, promping if it isn't known.
 */
static PyObject* PamHandle_get_user(
    PyObject* self, PyObject* args, PyObject* kwds)
{
  PamHandleObject*	pamHandle = (PamHandleObject*)self;
  char*			prompt = 0;
  PyObject*		result = 0;
  int			pam_result;
  const char*		user = 0;
  static char*		kwlist[] = {"prompt", NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|z:get_user", kwlist, &prompt))
    goto error_exit;
  pam_result = pam_get_user(pamHandle->pamh, &user, prompt);
  if (check_pam_result(pamHandle, pam_result) == -1)
    goto error_exit;
  if (user != 0)
    result = PyString_FromString(user);
  else
  {
    result = Py_None;
    Py_INCREF(result);
  }
  if (result == 0)
    goto error_exit;

error_exit:
  return result;
}

/*
 * Set a PAM environment variable.
 */
static PyObject* PamHandle_strerror(
    PyObject* self, PyObject* args, PyObject* kwds)
{
  PamHandleObject*	pamHandle = (PamHandleObject*)self;
  const char*		err;
  int			errnum;
  PyObject*		result = 0;
  const int		debug_magic = 0x4567abcd;
  static char*		kwlist[] = {"errnum", NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "i:strerror", kwlist, &errnum))
    goto error_exit;
  /*
   * A kludge so we can test exceptions.
   */
  if (errnum >= debug_magic && errnum < debug_magic + _PAM_RETURN_VALUES)
  {
    if (check_pam_result(pamHandle, errnum - debug_magic) == -1)
      goto error_exit;
  }
  err = pam_strerror(pamHandle->pamh, errnum);
  if (err == 0)
  {
    result = Py_None;
    Py_INCREF(result);
  }
  else
  {
    result = PyString_FromString(err);
    if (result == 0)
      goto error_exit;
  }

error_exit:
  return result;
}

static PyMethodDef PamHandle_Methods[] =
{
  {
    "conversation",
    (PyCFunction)PamHandle_conversation,
    METH_VARARGS|METH_KEYWORDS,
    MODULE_NAME "." PAMHANDLE_NAME "." "conversation(prompts)\n"
    "  Ask the application to issue the prompts to the user and return the\n"
    "  users responses.  The 'prompts' can be one, or a list of\n"
    "  " MODULE_NAME "." PAMHANDLE_NAME "." PAMMESSAGE_NAME " objects.  The return value is one,\n"
    "  or an array of " MODULE_NAME "." PAMHANDLE_NAME "." PAMRESPONSE_NAME " objects."
  },
  {
    "fail_delay",
    (PyCFunction)PamHandle_fail_delay,
    METH_VARARGS|METH_KEYWORDS,
    MODULE_NAME "." PAMHANDLE_NAME "." "fail_delay(micro_sec)\n"
    "  Sets the amount of time a failed authenticate attempt should delay for\n"
    "  in micro seconds.  This amount reset to 0 after every authenticate\n"
    "  attempt."
  },
  {
    "get_user",
    (PyCFunction)PamHandle_get_user,
    METH_VARARGS|METH_KEYWORDS,
    MODULE_NAME "." PAMHANDLE_NAME "." "getuser([prompt])\n"
    "  If " PAMHANDLE_NAME ".user isn't None return it, otherwise ask the\n"
    "  application to display the string 'prompt' and enter the user name.  The\n"
    "  user name (a string) is returned.  It will be None if it isn't known."
  },
  {
    "strerror",
    (PyCFunction)PamHandle_strerror,
    METH_VARARGS|METH_KEYWORDS,
    MODULE_NAME "." PAMHANDLE_NAME "." "strerror(errnum)\n"
    "  Return a string describing the pam error errnum."
  },
  {0,0,0,0}        	/* Sentinel */
};

static PyMemberDef PamHandle_Members[] =
{
  {
    "env",
    T_OBJECT_EX,
    offsetof(PamHandleObject, env),
    READONLY,
    "The PAM environment mapping."
  },
  {
    "exception",
    T_OBJECT_EX,
    offsetof(PamHandleObject, exception),
    READONLY,
    "Exception raised when a call to PAM fails."
  },
  {
    "libpam_version",
    T_STRING,
    offsetof(PamHandleObject, libpam_version),
    READONLY,
    "The runtime PAM version."
  },
  {
    "Message",
    T_OBJECT,
    offsetof(PamHandleObject, message),
    READONLY,
    "Message class that can be passed to " MODULE_NAME "." PAMHANDLE_NAME ".conversation()"
  },
  {
    "module",
    T_OBJECT,
    offsetof(PamHandleObject, module),
    READONLY,
    "The user module (ie you!)"
  },
  {
    "pamh",
    T_LONG,
    offsetof(PamHandleObject, pamh),
    READONLY,
    "The PAM handle."
  },
  {
    "py_initialized",
    T_INT,
    offsetof(PamHandleObject, py_initialized),
    READONLY,
    "True if Py_Initialize was called."
  },
  {
    "Response",
    T_OBJECT,
    offsetof(PamHandleObject, response),
    READONLY,
    "Response class returned by " MODULE_NAME "." PAMHANDLE_NAME ".conversation()"
  },
  {
    "XAuthData",
    T_OBJECT,
    offsetof(PamHandleObject, xauthdata),
    READONLY,
    "XAuthData class used by " MODULE_NAME "." PAMHANDLE_NAME ".xauthdata"
  },
  {0,0,0,0,0},        	/* End of Python visible members */
  {
    "syslogFile",
    T_OBJECT,
    offsetof(PamHandleObject, syslogFile),
    READONLY,
    "File like object that writes to syslog"
  },
  {0,0,0,0,0}		/* Sentinal */
};

static char PamHandle_Doc[] =
  MODULE_NAME "." PAMHANDLE_NAME "\n"
  "  A an instance of this class makes the PAM API available to the Python\n"
  "  module.  It is the first argument to every method PAM calls in the module.";

static int	pypam_initialize_count = 0;

static void cleanup_pamHandle(pam_handle_t* pamh, void* data, int error_status)
{
  PamHandleObject*	pamHandle = (PamHandleObject*)data;
  void*			dlhandle = pamHandle->dlhandle;
  PyObject*		py_resultobj = 0;
  PyObject*		handler_function = 0;
  int			py_initialized;
  static const char*	handler_name = "pam_sm_end";

  (void)pamh;
  (void)error_status;
  handler_function =
      PyObject_GetAttrString(pamHandle->module, (char*)handler_name);
  if (handler_function == 0)
    PyErr_Restore(0, 0, 0);
  else
  {
    call_python_handler(
        &py_resultobj, pamHandle, handler_function,
	handler_name, 0, 0, 0);
  }
  py_xdecref(py_resultobj);
  py_xdecref(handler_function);
  py_initialized = pamHandle->py_initialized;
  Py_DECREF(pamHandle);
  if (py_initialized)
  {
    pypam_initialize_count -= 1;
    if (pypam_initialize_count == 0)
      Py_Finalize();
  }
  dlclose(dlhandle);
}

/*
 * Find the module, and load it if we haven't see it before.  Returns
 * PAM_SUCCESS if it worked, the PAM error code otherwise.
 */
static int load_user_module(
    PyObject** user_module, PamHandleObject* pamHandle,
    const char* module_path)
{
  PyObject*	builtins = 0;
  PyObject*	module_dict = 0;
  FILE*		module_fp = 0;
  char*		user_module_name = 0;
  PyObject*	py_resultobj = 0;
  char*		dot;
  int		pam_result;
  int		py_result;

  /*
   * Open the file.
   */
  module_fp = fopen(module_path, "r");
  if (module_fp == 0)
  {
    syslog_path_message(
        module_path, "Can not open module: %s",
	strerror(errno));
    pam_result = PAM_OPEN_ERR;
    goto error_exit;
  }
  /*
   * Create the new module.
   */
  user_module_name = strrchr(module_path, '/');
  if (user_module_name == 0)
    user_module_name = strdup(module_path);
  else
    user_module_name = strdup(user_module_name + 1);
  if (user_module_name == 0)
  {
    syslog_path_message(MODULE_NAME, "out of memory");
    pam_result = PAM_BUF_ERR;
    goto error_exit;
  }
  dot = strrchr(user_module_name, '.');
  if (dot != 0 || strcmp(dot, ".py") == 0)
    *dot = '\0';
  *user_module = PyModule_New(user_module_name);
  if (*user_module == 0)
  {
    pam_result = syslog_path_exception(
        module_path,
	"PyModule_New(pamh.module.__file__) failed");
    goto error_exit;
  }
  py_result =
      PyModule_AddStringConstant(*user_module, "__file__", (char*)module_path);
  if (py_result == -1)
  {
    pam_result = syslog_path_exception(
        module_path,
	"PyModule_AddStringConstant(pamh.module, '__file__', module_path) failed");
    goto error_exit;
  }
  /*
   * Add __builtins__.
   */
  if (!PyObject_HasAttrString(*user_module , "__builtins__"))
  {
    builtins = PyEval_GetBuiltins();
    Py_INCREF(builtins);	/* is stolen */
    if (PyModule_AddObject(*user_module, "__builtins__", builtins) == -1)
    {
      pam_result = syslog_path_exception(
          module_path,
	  "PyModule_AddObject(pamh.module, '__builtins__', builtins) failed");
      goto error_exit;
    }
    builtins = 0;		/* was borrowed */
  }
  /*
   * Call it.
   */
  module_dict = PyModule_GetDict(*user_module);
  py_resultobj = PyRun_FileExFlags(
      module_fp, module_path, Py_file_input, module_dict, module_dict, 1, 0);
  module_fp = 0;		/* it was closed */
  module_dict = 0;		/* was borrowed */
  /*
   * If that didn't work there was an exception.  Errk!
   */
  if (py_resultobj == 0)
  {
    pam_result = syslog_path_traceback(module_path, pamHandle);
    goto error_exit;
  }
  pam_result = PAM_SUCCESS;

error_exit:
  py_xdecref(builtins);
  py_xdecref(module_dict);
  if (module_fp != 0)
    fclose(module_fp);
  if (user_module_name != 0)
    free(user_module_name);
  py_xdecref(py_resultobj);
  return pam_result;
}

/*
 * Create a new Python type on the heap.  This differs from creating a static
 * type in non-obvious ways.
 */
static PyTypeObject* newHeapType(
  PyObject*		module,		/* Module declaring type (required) */
  const char*		name,		/* tp_name (required) */
  int			basicsize,	/* tp_basicsize (required) */
  char*			doc, 		/* tp_doc (optional) */
  inquiry		clear,		/* tp_clear (optional) */
  struct PyMethodDef*	methods,	/* tp_methods (optional) */
  struct PyMemberDef*	members,	/* tp_members (optional) */
  struct PyGetSetDef*	getset,		/* tp_getset (optional) */
  newfunc		new		/* tp_new (optional) */
)
{
  PyObject*		pyName = 0;
  PyTypeObject*		result = 0;
  PyTypeObject*		type = 0;

  pyName = PyString_FromString(name);
  if (pyName == 0)
    goto error_exit;
  type = (PyTypeObject*)PyType_Type.tp_alloc(&PyType_Type, 0);
  if (type == 0)
    goto error_exit;
  type->tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_HEAPTYPE|Py_TPFLAGS_HAVE_GC;
  type->tp_basicsize = basicsize;
  type->tp_dealloc = generic_dealloc;
  if (doc != 0)
  {
    char *doc_string = PyMem_Malloc(strlen(doc)+1);
    if (doc_string == 0)
    {
      PyErr_NoMemory();
      goto error_exit;
    }
    strcpy(doc_string, doc);
    type->tp_doc = doc_string;
  }
  type->tp_traverse = generic_traverse;
  type->tp_clear = clear != 0 ? clear : generic_clear;
  type->tp_methods = methods;
  type->tp_members = members;
  type->tp_getset = getset;
  type->tp_name = PyString_AsString(pyName);
#if PY_VERSION_HEX < 0x02050000
  ((PyHeapTypeObject*)type)->name = pyName;
#else
  ((PyHeapTypeObject*)type)->ht_name = pyName;
#endif
  pyName = 0;
  PyType_Ready(type);
  type->tp_new = new;
  if (PyDict_SetItemString(type->tp_dict, "__module__", module) == -1)
    goto error_exit;
  result = type;
  type = 0;

error_exit:
  py_xdecref(pyName);
  py_xdecref((PyObject*)type);
  return result;
}

/*
 * Create a type and return an instance of that type.  The newly created
 * type object is discarded.
 */
static PyObject* newSingletonObject(
  PyObject*		module,		/* Module declaring type (required) */
  const char*		name,		/* tp_name (required) */
  int			basicsize,	/* tp_basicsize (required) */
  char*			doc, 		/* tp_doc (optional) */
  inquiry		clear,		/* tp_clear (optional) */
  struct PyMethodDef*	methods,	/* tp_methods (optional) */
  struct PyMemberDef*	members,	/* tp_members (optional) */
  struct PyGetSetDef*	getset		/* tp_getset (optional) */
)
{
  PyObject*		result = 0;
  PyTypeObject*  	type = 0;

  type = newHeapType(
      module, name, basicsize, doc, clear, methods, members, getset, 0);
  if (type != 0)
    result = type->tp_alloc(type, 0);
  py_xdecref((PyObject*)type);
  return result;
}

/*
 * Find the PamHandle object used by the pamh instance, creating one if it
 * doesn't exist.  Returns a pam_result, which will be PAM_SUCCESS if it
 * works.
 */
static int get_pamHandle(
  PamHandleObject** result, pam_handle_t* pamh, const char** argv)
{
  void*			dlhandle = 0;
  int			do_initialize;
  char*			module_dir;
  char*			module_path = 0;
  char*			module_data_name = 0;
  PyObject*		user_module = 0;
  PamEnvObject*		pamEnv = 0;
  PamHandleObject*	pamHandle = 0;
  PyObject*		pamHandle_module = 0;
  SyslogFileObject*	syslogFile = 0;
  PyObject*		tracebackModule = 0;
  int			pam_result;

  /*
   * Figure out where the module lives.
   */
  if (argv == 0 || argv[0] == 0)
  {
    syslog_path_message(MODULE_NAME, "python module name not supplied");
    pam_result = PAM_MODULE_UNKNOWN;
    goto error_exit;
  }
  if (argv[0][0] == '/')
    module_dir = "";
  else
    module_dir = DEFAULT_SECURITY_DIR;
  module_path = malloc(strlen(module_dir) + strlen(argv[0]) + 1);
  if (module_path == 0)
  {
    syslog_path_message(MODULE_NAME, "out of memory");
    pam_result = PAM_BUF_ERR;
    goto error_exit;
  }
  strcat(strcpy(module_path, module_dir), argv[0]);
  /*
   * See if we already exist.
   */
  module_data_name = malloc(strlen(MODULE_NAME) + 1 + strlen(module_path) + 1);
  if (module_data_name == 0)
  {
    syslog_path_message(MODULE_NAME, "out of memory");
    pam_result = PAM_BUF_ERR;
    goto error_exit;
  }
  strcat(strcat(strcpy(module_data_name, MODULE_NAME), "."), module_path);
  pam_result = pam_get_data(pamh, module_data_name, (void*)result);
  if (pam_result == PAM_SUCCESS)
  {
    (*result)->pamh = pamh;
    Py_INCREF(*result);
    goto error_exit;
  }
  /*
   * Initialize Python if required.
   */
  dlhandle = dlopen(libpython_so, RTLD_NOW|RTLD_GLOBAL);
  if (dlhandle == 0)
  {
    pam_result = syslog_path_message(
        module_path,
	"Can't load python library %s: %s", libpython_so, dlerror());
    goto error_exit;
  }
  do_initialize = pypam_initialize_count > 0 || !Py_IsInitialized();
  if (do_initialize)
  {
    if (pypam_initialize_count == 0)
      initialise_python();
    pypam_initialize_count += 1;
  }
  /*
   * Create a throw away module because heap types need one, apparently.
   */
  pamHandle_module = PyModule_New((char*)module_data_name);
  if (pamHandle_module == 0)
  {
    pam_result = syslog_path_exception(
	module_path,
	"PyModule_New(module_data_name) failed");
    goto error_exit;
  }
  /*
   * Create the type we use for our object.
   */
  pamHandle = (PamHandleObject*)newSingletonObject(
      pamHandle_module,			/* __module__ */
      PAMHANDLE_NAME "_type",		/* tp_name */
      sizeof(PamHandleObject),		/* tp_basicsize */
      PamHandle_Doc,			/* tp_doc */
      0,				/* tp_clear */
      PamHandle_Methods,		/* tp_methods */
      PamHandle_Members,		/* tp_members */
      PamHandle_Getset);		/* tp_getset */
  if (pamHandle == 0)
  {
    pam_result = syslog_path_exception(module_path, "Can't create pamh Object");
    goto error_exit;
  }
  if (PyObject_IS_GC((PyObject*)pamHandle))
    PyObject_GC_UnTrack(pamHandle);	/* No refs are visible to python */
  pamHandle->dlhandle = dlhandle;
  dlhandle = 0;
  pamHandle->libpam_version =
      __STRING(__LINUX_PAM__) "." __STRING(__LINUX_PAM_MINOR__);
  pamHandle->pamh = pamh;
  pamHandle->py_initialized = do_initialize;
  pamHandle->exception = PyErr_NewException(
    PAMHANDLE_NAME "." PAMHANDLEEXCEPTION_NAME, PyExc_StandardError, NULL);
  if (pamHandle->exception == NULL)
    goto error_exit;
  /*
   * Create the object we use to handle the PAM environment.
   */
  pamEnv = (PamEnvObject*)newSingletonObject(
      pamHandle_module,			/* __module__ */
      PAMENV_NAME "_type",		/* tp_name */
      sizeof(PamEnvObject),		/* tp_basicsize */
      0,				/* tp_doc */
      0,				/* tp_clear */
      PamEnv_Methods,			/* tp_methods */
      PamEnv_Members,			/* tp_members */
      0);				/* tp_getset */
  if (pamEnv == 0)
  {
    pam_result = syslog_path_exception(module_path, "Can't create pamh.env");
    goto error_exit;
  }
  pamEnv->ob_type->tp_as_mapping = &PamEnv_as_mapping;
  pamEnv->ob_type->tp_iter = PamEnv_iter;
  pamEnv->pamHandle = pamHandle;
  pamEnv->pamEnvIter_type = newHeapType(
      pamHandle_module,			/* __module__ */
      PAMENVITER_NAME "_type",		/* tp_name */
      sizeof(PamEnvIterObject),		/* tp_basicsize */
      0,				/* tp_doc */
      0,				/* tp_clear */
      0,				/* tp_methods */
      PamEnvIter_Members,		/* tp_members */
      0,				/* tp_getset */
      0);				/* tp_new */
  if (pamEnv->pamEnvIter_type == 0)
    goto error_exit;
  if (PyObject_IS_GC((PyObject*)pamEnv->pamEnvIter_type))
  {
    /*
     * No refs are visible to python.
     */
    PyObject_GC_UnTrack(pamEnv->pamEnvIter_type);
  }
  pamEnv->pamEnvIter_type->tp_iter = PyObject_SelfIter;
  pamEnv->pamEnvIter_type->tp_iternext = PamEnvIter_iternext;
  pamHandle->env = (PyObject*)pamEnv;
  pamEnv = 0;
  /*
   * Create the type for the PamMessageObject.
   */
  pamHandle->message = newHeapType(
      pamHandle_module,			/* __module__ */
      PAMMESSAGE_NAME "_type",		/* tp_name */
      sizeof(PamMessageObject),		/* tp_basicsize */
      PamMessage_doc,			/* tp_doc */
      0,				/* tp_clear */
      0,				/* tp_methods */
      PamMessage_members,		/* tp_members */
      0,				/* tp_getset */
      PamMessage_new);			/* tp_new */
  if (pamHandle->message == 0)
  {
    pam_result = syslog_path_exception(
        module_path, "Can't create pamh.Message");
    goto error_exit;
  }
  /*
   * Create the type for the PamResponseObject.
   */
  pamHandle->response = newHeapType(
      pamHandle_module,			/* __module__ */
      PAMRESPONSE_NAME "_type",		/* tp_name */
      sizeof(PamResponseObject),	/* tp_basicsize */
      PamResponse_doc,			/* tp_doc */
      0,				/* tp_clear */
      0,				/* tp_methods */
      PamResponse_members,		/* tp_members */
      0,				/* tp_getset */
      PamResponse_new);			/* tp_new */
  if (pamHandle->response == 0)
  {
    pam_result = syslog_path_exception(
        module_path,
	"Can't create pamh.Response");
    goto error_exit;
  }
  /*
   * Create the Syslogfile Type & Object.
   */
  syslogFile = (SyslogFileObject*)newSingletonObject(
      pamHandle_module,			/* __module__ */
      SYSLOGFILE_NAME "_type",		/* tp_name */
      sizeof(SyslogFileObject),		/* tp_basicsize */
      0,				/* tp_doc */
      SyslogFile_clear,			/* tp_clear */
      SyslogFile_Methods,		/* tp_methods */
      0,				/* tp_members */
      0);				/* tp_getset */
  if (syslogFile == 0)
  {
    pam_result = syslog_path_exception(
        module_path,
	"Can't create pamh.syslogFile");
    goto error_exit;
  }
  syslogFile->buffer = 0;
  syslogFile->size = 0;
  pamHandle->syslogFile = (PyObject*)syslogFile;
  syslogFile = 0;
  /*
   * The traceback object.
   */
  tracebackModule = PyImport_ImportModule("traceback");
  if (tracebackModule == 0)
  {
    pam_result = syslog_path_exception(
        module_path,
	"PyImport_ImportModule('traceback') failed");
    goto error_exit;
  }
  pamHandle->print_exception =
    PyObject_GetAttrString(tracebackModule, "print_exception");
  if (pamHandle->print_exception == 0)
  {
    pam_result = syslog_path_exception(
        module_path,
	"PyObject_GetAttrString(traceback, 'print_exception') failed");
    goto error_exit;
  }
  Py_INCREF(pamHandle->print_exception); /* Borrowed reference */
  /*
   * Create the type for the PamXAuthDataObject.
   */
  pamHandle->xauthdata = newHeapType(
      pamHandle_module,			/* __module__ */
      PAMXAUTHDATA_NAME "_type",	/* tp_name */
      sizeof(PamXAuthDataObject),	/* tp_basicsize */
      PamXAuthData_doc,			/* tp_doc */
      0,				/* tp_clear */
      0,				/* tp_methods */
      PamXAuthData_members,		/* tp_members */
      0,				/* tp_getset */
      PamXAuthData_new);		/* tp_new */
  if (pamHandle->xauthdata == 0)
  {
    pam_result = syslog_path_exception(
        module_path, "Can't create pamh.XAuthData");
    goto error_exit;
  }
  /*
   * Now we have error reporting set up import the module.
   */
  pam_result = load_user_module(&user_module, pamHandle, module_path);
  if (pam_result != PAM_SUCCESS)
    goto error_exit;
  pamHandle->module = user_module;
  Py_INCREF(pamHandle->module);
  /*
   * That worked.  Save a reference to it.
   */
  Py_INCREF(pamHandle);
  pam_set_data(pamh, module_data_name, pamHandle, cleanup_pamHandle);
  *result = pamHandle;
  pamHandle = 0;

error_exit:
  if (module_path != 0)
    free(module_path);
  if (module_data_name != 0)
    free(module_data_name);
  py_xdecref(user_module);
  py_xdecref((PyObject*)pamEnv);
  py_xdecref((PyObject*)pamHandle);
  py_xdecref(pamHandle_module);
  py_xdecref((PyObject*)syslogFile);
  py_xdecref(tracebackModule);
  return pam_result;
}

/*
 * Call the python handler.
 */
static int call_python_handler(
    PyObject** result, PamHandleObject* pamHandle,
    PyObject* handler_function, const char* handler_name,
    int flags, int argc, const char** argv)
{
  PyObject*		arg_object = 0;
  PyObject*		argv_object = 0;
  PyObject*		flags_object = 0;
  PyObject*		handler_args = 0;
  PyObject*		py_resultobj = 0;
  int			i;
  int			pam_result;

  if (!PyCallable_Check(handler_function))
  {
    pam_result =
        syslog_message(pamHandle, "%s isn't a function.", handler_name);
    goto error_exit;
  }
  /*
   * Set up the arguments for the python function.  If we aren't passed
   * argv then this is pam_sm_end() and it is only given pamh.
   */
  if (argv == 0)
    handler_args = Py_BuildValue("(O)", pamHandle);
  else
  {
    flags_object = PyInt_FromLong(flags);
    if (flags_object == 0)
    {
      pam_result = syslog_exception(pamHandle, "PyInt_FromLong(flags) failed");
      goto error_exit;
    }
    argv_object = PyList_New(argc);
    if (argv_object == 0)
    {
      pam_result = syslog_exception(pamHandle, "PyList_New(argc) failed");
      goto error_exit;
    }
    for (i = 0; i < argc; i += 1)
    {
      arg_object = PyString_FromString(argv[i]);
      if (arg_object == 0)
      {
	pam_result = syslog_exception(
	    pamHandle,
	    "PyString_FromString(argv[i]) failed");
	goto error_exit;
      }
      PyList_SET_ITEM(argv_object, i, arg_object);
      arg_object = 0;		/* It was pinched by SET_ITEM */
    }
    handler_args =
	Py_BuildValue("OOO", pamHandle, flags_object, argv_object);
  }
  if (handler_args == 0)
  {
    pam_result = syslog_exception(
        pamHandle,
	"handler_args = Py_BuildValue(...) failed");
    goto error_exit;
  }
  /*
   * Call the Python handler function.
   */
  py_resultobj = PyEval_CallObject(handler_function, handler_args);
  /*
   * Did it throw an exception?
   */
  if (py_resultobj == 0)
  {
    pam_result = syslog_traceback(pamHandle);
    goto error_exit;
  }
  *result = py_resultobj;
  py_resultobj = 0;
  pam_result = PAM_SUCCESS;

error_exit:
  py_xdecref(arg_object);
  py_xdecref(argv_object);
  py_xdecref(flags_object);
  py_xdecref(handler_args);
  py_xdecref(py_resultobj);
  return pam_result;
}

/*
 * Calls the Python method that will handle PAM's request to the module.
 */
static int call_handler(
  const char* handler_name, pam_handle_t* pamh,
  int flags, int argc, const char** argv)
{
  PyObject*		handler_function = 0;
  PamHandleObject*	pamHandle = 0;
  PyObject*		py_resultobj = 0;
  int			pam_result;

  /*
   * Initialise Python, and get a copy of our object.
   */
  pam_result = get_pamHandle(&pamHandle, pamh, argv);
  if (pam_result != PAM_SUCCESS)
    goto error_exit;
  /*
   * See if the function we have to call has been defined.
   */
  handler_function =
      PyObject_GetAttrString(pamHandle->module, (char*)handler_name);
  if (handler_function == 0)
  {
    syslog_message(pamHandle, "%s() isn't defined.", handler_name);
    pam_result = PAM_SYMBOL_ERR;
    goto error_exit;
  }
  pam_result = call_python_handler(
      &py_resultobj, pamHandle, handler_function, handler_name,
      flags, argc, argv);
  if (pam_result != PAM_SUCCESS)
    goto error_exit;
  /*
   * It must return an integer.
   */
  if (!PyInt_Check(py_resultobj) && !PyLong_Check(py_resultobj))
  {
    pam_result = syslog_message(
	pamHandle,
	"%s() did not return an integer.", handler_name);
    goto error_exit;
  }
  pam_result = PyInt_AsLong(py_resultobj);

error_exit:
  py_xdecref(handler_function);
  py_xdecref((PyObject*)pamHandle);
  py_xdecref(py_resultobj);
  return pam_result;
}


PAM_EXTERN int pam_sm_authenticate(
  pam_handle_t* pamh, int flags, int argc, const char** argv)
{
  return call_handler("pam_sm_authenticate", pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(
  pam_handle_t* pamh, int flags, int argc, const char** argv)
{
  return call_handler("pam_sm_setcred", pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_acct_mgmt(
  pam_handle_t* pamh, int flags, int argc, const char** argv)
{
  return call_handler("pam_sm_acct_mgmt", pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_open_session(
  pam_handle_t* pamh, int flags, int argc, const char** argv)
{
  return call_handler("pam_sm_open_session", pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_close_session(
  pam_handle_t* pamh, int flags, int argc, const char** argv)
{
  return call_handler("pam_sm_close_session", pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_chauthtok(
  pam_handle_t* pamh, int flags, int argc, const char** argv)
{
  return call_handler("pam_sm_chauthtok", pamh, flags, argc, argv);
}

**************
|pam_python|
**************

.. toctree::
   :maxdepth: 2

.. topic:: Abstract

   |Pam_python| is a PAM module that runs the Python interpreter, and so
   allows PAM modules to be written in Python.

:Author: Russell Stuart <russell-pampython@stuart.id.au>


.. _intro:

Introduction
============

The |pam_python| PAM module runs the Python source file (aka Python PAM
module) it is given in the Python interpreter, making the PAM module API
available to it. This document describes the how the PAM Module API is exposed
to the Python PAM module. It does not describe how to use the API. You must read
the |PMWG|_ to learn how to do that. To re-iterate: this
document does not tell you how to write PAM modules, it only tells you how to
access the PAM module API from Python.

Writing PAM modules from Python incurs a large performance penalty and requires
Python to be installed, so it is not the best option for writing modules that
will be used widely. On the other hand memory allocation / corruption problems
can not be caused by bad Python code, and a Python module is generally shorter
and easier to write than its C equivalent. This makes it ideal for the system
administrator who just wants to make use of the the PAM API for his own ends
while minimising the risk of introducing memory corruption problems into every
program using PAM.


.. _configuring:

Configuring PAM
===============

Tell PAM to use a Python PAM module in the usual way: add a rule to your PAM
configuration. The PAM administrators manual gives the syntax of a rule as::

   service type control module-path module-arguments

The first three parameters are the same for all PAM modules and so aren't any
different for |pam_python|. The *module-path* is the path to pam_python.so.
Like all paths PAM modules it is relative to the default PAM module directory so
is usually just the string ``pam_python.so``. The first *module-argument* is the
path to the Python PAM module. If it doesn't start with a / it is relative to
the ``/lib/security``. All *module-arguments*, including the path name to the
Python PAM module are passed to it.


.. _module:

Python PAM modules
==================

When a PAM handle created by the applications call to PAM's :samp:`pam_start()`
function first uses a Python PAM module, |pam_python| invokes it using Python's
``execfile`` function.   The following variables are passed to the invoked
module in its global namespace:


.. data:: __builtins__

   The usual Python ``__builtins__``.


.. data:: __file__

   The absolute path name to the Python PAM module.

As described in the |PMWG|, PAM interacts with your module by calling methods
you provide in it. Each ``type`` in the PAM configuration rules results in one
or more methods being called. The Python PAM module must define the methods that
will be called by each rule ``type`` it can be used with. Those methods are:


.. function:: pam_sm_acct_mgmt(pamh, flags, args)

   The service module's implementation of PAM's :manpage:`pam_acct_mgmt(3)` interface.


.. function:: pam_sm_authenticate(pamh, flags, args)

   The service module's implementation of PAM's :manpage:`pam_authenticate(3)`
   interface.


.. function:: pam_sm_close_session(pamh, flags, args)

   The service module's implementation of PAM's :manpage:`pam_close_session(3)`
   interface.


.. function:: pam_sm_chauthtok(pamh, flags, args)

   The service module's implementation of PAM's :manpage:`pam_chauthtok(3)` interface.


.. function:: pam_sm_open_session(pamh, flags, args)

   The service module's implementation of PAM's :manpage:`pam_open_session(3)`
   interface.


.. function:: pam_sm_setcred(pamh, flags, args)

   The service module's implementation of PAM's :manpage:`pam_setcred(3)` interface.

The arguments and return value of all these methods are the same. The *pamh*
parameter is an instance of the :class:`PamHandle` class. It is used to interact
with PAM and is described in the next section. The remaining arguments are as
described in the |PMWG|. All functions must return an integer,
eg :const:`pamh.PAM_SUCCESS`. The valid return codes for each function are
defined |PMWG|.   If the Python method isn't present
|pam_python| will return :const:`pamh.PAM_SYMBOL_ERR` to PAM; if the method
doesn't return an integer or throws an exception :const:`pamh.PAM_SERVICE_ERR`
is returned.

There is one other method that in the Python PAM module
that may be called by |pam_python|.
It is optional:


.. function:: pam_sm_end(pamh)

   If present this will be called when the application calls PAM's
   :manpage:`pam_end(3)` function.
   If not present nothing happens.
   The parameter *pamh* is the :class:`PamHandle` object.
   The return value is ignored.


.. _pamhandle:

The PamHandle Class
===================

An instance of this class is automatically created for a Python PAM module when
it is first referenced, (ie when it is ``execfile``'ed). It is the first
argument to every Python method called by PAM. It is destroyed automatically
when PAM's :c:func:`pam_end` is called, right after the ``execfile``'ed
module is destroyed. If any method fails, or any access to a member fails a
:exc:`PamHandle.exception` exception will be thrown. It contains the following
members:


.. data:: PAM_???

   All the :const:`PAM_???` constants defined in the PAM include files 
   version 1.1.1 are available. They are all read-only :class:`int`'s.


.. data:: authtok

   The :const:`PAM_AUTHTOK` PAM item. Reading this results in a call
   to the |pam-lib-func| :samp:`pam_get_item(PAM_AUTHTOK)`, writing it
   results in a call :samp:`pam_set_item(PAM_AUTHTOK, value)`. Its
   value will be either a :class:`string` or :const:`None` for the C
   value :c:macro:`NULL`.


.. data:: authtok_type

   The :const:`PAM_AUTHTOK_TYPE` PAM item. Reading this results in a call
   to the |pam-lib-func| :samp:`pam_get_item(PAM_AUTHTOK_TYPE)`, writing it
   results in a call :samp:`pam_set_item(PAM_AUTHTOK_TYPE, value)`. Its
   value will be either a :class:`string` or :const:`None` for the C
   value :c:macro:`NULL`.
   New in version 1.0.0.
   Only present if the version of PAM |pam_python| is compiled with supports it.


.. data:: env

   This is a mapping representing the PAM environment. |pam_python| implements
   accesses and changes to it via the |pam-lib-func| :samp:`pam_getenv()`,
   :samp:`pam_putenv()` and :samp:`pam_getenvlist()`. The PAM environment
   only supports :class:`string` keys and values, and the keys may not be
   blank nor contain '='.


.. data:: exception

   The exception raised by methods defined here if they fail. It is a
   subclass of :class:`StandardError`. Instances contain the member
   :const:`pam_result`, which is the error code returned by PAM. The
   description is the PAM error message.


.. data:: libpam_version

   The version of PAM |pam_python| was compiled with. This is a
   :class:`string`. In version 0.1.0 of |pam_python| and prior this was an
   :class:`int` holding the version of PAM library loaded. Newer versions of
   PAM no longer export that value.


.. data:: pamh

   The PAM handle, as read-only :class:`int`. Possibly useful during debugging.


.. data:: py_initialized

   A read-only :class:`int`.
   If the Python interpreter was initialised
   before the |pam_python| module was created this is 0.
   Otherwise it is 1, meaning |pam_python| has called :c:func:`Py_Initialize`
   and will call :c:func:`Py_Finalize`
   when the last |pam_python| module is destroyed.


.. data:: oldauthtok

   The :const:`PAM_OLDAUTHTOK` PAM item. Reading this results in a call
   to the |pam-lib-func| :samp:`pam_get_item(PAM_OLDAUTHTOK)`,
   writing it results in a call :samp:`pam_set_item(PAM_OLDAUTHTOK, value)`.
   Its value will be either a :class:`string` or :const:`None` for the
   C value :c:macro:`NULL`.


.. data:: rhost

   The :const:`PAM_RHOST` PAM item. Reading this results in a call
   to the |pam-lib-func| :samp:`pam_get_item(PAM_RHOST)`,
   writing it results in a call :samp:`pam_set_item(PAM_RHOST, value)`.
   Its value will be either a :class:`string`
   or :const:`None` for the C value :c:macro:`NULL`.


.. data:: ruser

   The :const:`PAM_RUSER` PAM item. Reading this results in a call
   to the |pam-lib-func| :samp:`pam_get_item(PAM_RUSER)`,
   writing it results in a call :samp:`pam_set_item(PAM_RUSER, value)`.
   Its value will be either a :class:`string`
   or :const:`None` for the C value :c:macro:`NULL`.


.. data:: service

   The :const:`PAM_SERVICE` PAM item. Reading this results in a call
   to the |pam-lib-func| :samp:`pam_get_item(PAM_SERVICE)`,
   writing it results in a call :samp:`pam_set_item(PAM_SERVICE, value)`.
   Its value will be either a :class:`string`
   or :const:`None` for the C value :c:macro:`NULL`.


.. data:: tty

   The :const:`PAM_TTY` PAM item. Reading this results in a call
   to the |pam-lib-func| :samp:`pam_get_item(PAM_TTY)`,
   writing it results in a call :samp:`pam_set_item(PAM_TTY, value)`.
   Its value will be either a :class:`string`
   or :const:`None` for the C value :c:macro:`NULL`.


.. data:: user

   The :const:`PAM_USER` PAM item. Reading this results in a call
   to the |pam-lib-func| :samp:`pam_get_item(PAM_USER)`,
   writing it results in a call :samp:`pam_set_item(PAM_USER, value)`.
   Its value will be either a :class:`string`
   or :const:`None` for the C value :c:macro:`NULL`.


.. data:: user_prompt

   The :const:`PAM_USER_PROMPT` PAM item. Reading this results in a call
   to the |pam-lib-func| :samp:`pam_get_item(PAM_USER_PROMPT)`,
   writing it results in a call :samp:`pam_set_item(PAM_USER_PROMPT, value)`.
   Its value will be either a :class:`string`
   or :const:`None` for the C value :c:macro:`NULL`.


.. data:: xauthdata

   The :const:`PAM_XAUTHDATA` PAM item. Reading this results in a call
   to the |pam-lib-func| :samp:`pam_get_item(PAM_XAUTHDATA)`,
   writing it results in a call :samp:`pam_set_item(PAM_XAUTHDATA, value)`.
   Its value is a :class:`XAuthData` instance.  When setting its value you
   don't have to use an actual :class:`XAuthData` instance,
   any class that contains a :class:`string` member :attr:`name`
   and a :class:`string` member :attr:`data` will do.
   New in version 1.0.0.
   Only present if the version of PAM |pam_python| is compiled with supports it.


.. data:: xdisplay

   The :const:`PAM_XDISPLAY` PAM item. Reading this results in a call
   to the |pam-lib-func| :samp:`pam_get_item(PAM_XDISPLAY)`,
   writing it results in a call :samp:`pam_set_item(PAM_XDISPLAY, value)`.
   Its value will be either a :class:`string`
   or :const:`None` for the C value :c:macro:`NULL`.
   New in version 1.0.0.
   Only present if the version of PAM |pam_python| is compiled with supports it.

The following methods are available:


.. method:: PamHandle.Message(msg_style,msg)

   Creates an instance of the :class:`Message` class.
   The arguments become the instance members of the same name.
   This class is used to represent the C API's ``struct pam_message`` type.
   An instance has two members corresponding
   to the C structure members of the same name:
   :attr:`msg_style` an :class:`int`
   and :attr:`data` a :class:`string`.
   Instances are immutable.
   Instances of this class can be passed to the :meth:`conversation` method.


.. method:: PamHandle.Response(resp,ret_code)

   Creates an instance of the :class:`Response` class.
   The arguments become the instance members of the same name.
   This class is used to represent the C API's ``struct pam_response`` type.
   An instance has two members
   corresponding to the C structure members of the same name:
   :attr:`resp` a :class:`string`
   and :attr:`ret_code` an :class:`int`.
   Instances are immutable.
   Instances of this class are returned by the :meth:`conversation` method.


.. method:: PamHandle.XAuthData(name,data)

   Creates an instance of the :class:`XAuthData` class.
   The arguments become the instance members of the same name.
   This class is used to represent the C API's ``struct pam_xauth_data`` type.
   An instance has two members
   corresponding to the C structure members of the same name:
   :attr:`name` a :class:`string` and :attr:`data` also a :class:`string`.
   Instances are immutable.
   The :data:`xauthdata` member returns instances of this class and
   can be set to an instance of this class.


.. method:: PamHandle.conversation(prompts)

   Calls the function defined by the PAM :c:macro:`PAM_CONV` item.
   The *prompts* argument is a :class:`Message` object
   or a :class:`list` of them.
   You don't have to pass an actual :class:`Message` object,
   any class that contains a :class:`string` member :attr:`msg`
   and a :class:`int` member :attr:`msg_style` will do.
   These members are used to initialise the ``struct pam_message``
   members of the same name. It returns either a single :class:`Response`
   object if a single :class:`Message` was passed,
   or a :class:`list` of them of the same length as the :class:`list` passed.
   These :class:`Response` objects contain the data the user entered.


.. method:: PamHandle.fail_delay(delay)

   This results in a call to the |pam-lib-func| :samp:`pam_fail_delay()`,
   which sets the maximum random delay after an authentication failure
   to *delay* milliseconds.


.. method:: PamHandle.get_user([prompt])

   This results in a call to the |pam-lib-func| :samp:`pam_get_user()`,
   which returns the current user name (a :class:`string`)
   or :const:`None` if :samp:`pam_get_user()` returns :c:macro:`NULL`.
   If not known it asks the PAM application for the user name,
   giving it the :class:`string` *prompt* parameter
   to prompt the user to enter it.


.. method:: PamHandle.strerror(errnum)

   This results in a call to the |pam-lib-func| :samp:`pam_strerror()`,
   which returns a :class:`string` description of the :class:`int`
   PAM return value *errnum*.

There is no interface provided for the |pam-lib-func|\s :samp:`pam_get_data()`
and :samp:`pam_set_data()`. There are two reasons for this.
Firstly those two methods are provided so C code can have private storage
local to the PAM handle.  A Python PAM Module can use own module name space
to do the same job, and it's easier to do so. But more importantly it's
safer because there is no type-safe way of providing access to the facility
from Python.


.. _diagnostics:

Diagnostics, Debugging, Bugs
============================

The way |pam_python| operates will be foreign to most Python programmers.
It embeds Python into existing programs, primarily ones written in C.
This means things like debugging and diagnostics
are done differently to a normal Python program.


.. _return-values:

Diagnostics
-----------

If |pam_python| returns something other than :const:`PAM_SUCCESS` to PAM a
message will be written to the ``syslog`` ``LOG_AUTHPRIV`` facility. The only
exception to this is when |pam_python| is passing on the return value from
a Python :meth:`pam_sm_...` entry point - nothing is logged in that case.
So, if your Python PAM Module is failing in mysterious ways
check the log file your system is configured to write
``LOG_AUTHPRIV`` entries to.
Usually this is :file:`/var/log/syslog` or :file:`/var/log/auth.log`.
The diagnostic or traceback Python would normally print to :attr:`sys.stderr`
will be in there.

The PAM result codes returned directly by |pam_python| are:


.. data:: PAM_BUF_ERR

   Memory allocation failed.


.. data:: PAM_MODULE_UNKNOWN

   The Python PAM module name wasn't supplied.


.. data:: PAM_OPEN_ERR

   The Python PAM module could not be opened.


.. data:: PAM_SERVICE_ERR

   A Python exception was thrown, unless it was because of a memory allocation
   failure.


.. data:: PAM_SYMBOL_ERR

   A :meth:`pam_sm_...` called by PAM wasn't defined by the Python PAM module.


.. _debugging:

Debugging
---------

If you have Python bindings for the PAM Application library then you can write
test units in Python and use Pythons :mod:`pdb` module debug a Python PAM
module. This is how |pam_python| was developed.

I used `PyPAM <http://www.pangalactic.org/PyPAM/>`_ for the Python Application
library bindings. Distributions often package it as ``python-pam``. To set
breakpoints in :mod:`pdb` either wait until PAM has loaded your module, or
:keyword:`import` it before you start debugging.


.. _bugs:

Bugs
----

There are several design decisions you may stumble across when using
|pam_python|. One is that the Python PAM module is isolated from the rest
of the Python environment. This differs from a :keyword:`import`'ed Python module,
where regardless of how many times a module is imported there is only one copy
that shares the one global name space.
For example, if you :keyword:`import` your Python PAM module
and then debug it as suggested above then there will be 2
copies of your Python PAM module in memory -
the imported one and the one PAM is using.
If the PAM module sets a global variable you won't see it in the
:keyword:`import`'ed one. Indeed, obtaining any sort of handle to the module
PAM is using is near impossible. This means the debugger can inspect variables
in the module only when a breakpoint has one of the modules functions in its
backtrace.

There are a few of reasons for this. Firstly, the |PMWG| says
this is the way it should be, so |pam_python| encourages it. Secondly, if a
PAM application is using a Python PAM Module it's important the PAM module
remains as near to invisible as possible to avoid conflicts. Finally, and most
importantly, references to objects constructed by the Python PAM module must
never leak. This is because the destructors to those objects are C functions
that live in |pam_python|, and those destructors are called when all
references to the objects are gone. When the application calls |pam-lib-func|
:samp:`pam_end()` function |pam_python| is unloaded, and with it goes the
destructor code. Should a reference to an object defined by |pam_python| exist
after :samp:`pam_end()` returns the call to destructor
will result in a jump to a non-existent address causing a ``SIGSEGV``.

Another potential trap is the initialisation and finalisation of the Python
interpreter itself. Calling the interpreter's finalisation routine while it is
in use would I imagine be a big no-no. If |pam_python| has to initialise
the interpreter (by calling :c:func:`Py_Initialize`) then it will call its
finaliser :c:func:`Py_Finalize` when the last Python PAM module is destroyed.
This is heuristic works in most scenarios. One example where is won't work is a
sequence like::
  
  start-python-pam-module;
  application-initialises-interpreter;
  stop-python-pam-module;
  application-stops-interpreter.
  
The above is doomed to fail.


.. _example:

An example
==========

This is one of the examples provided by the package:


.. include:: pam_permit.py
   :literal:

Assuming it and ``pam_python.so`` are in the directory ``/lib/security`` adding
these rules to ``/etc/pam.conf`` would run it::

   login account   requisite   pam_python.so pam_accept.py
   login auth      requisite   pam_python.so pam_accept.py
   login password  requisite   pam_python.so pam_accept.py
   login session   requisite   pam_python.so pam_accept.py

.. |PMWG| replace:: PAM Module Writers Guide

.. _PMWG: http://www.linux-pam.org/Linux-PAM-html/

.. |pam_python| replace:: `pam_python`

.. |pam-lib-func| replace:: PAM library function

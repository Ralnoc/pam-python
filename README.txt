pam_python
==========

  pam_python is a PAM module that runs the Python interpreter
  and so allows PAM modules to be written in Python.

  There is extensive documentation shipped as reStructured
  text.  The build system renders this in the standard Python
  HTML documentation style.

  All documentation is readable online at the home page:
    http://pam-pathon.sourceforge.net/


Dependencies
------------

  Python >= 2.6, http://www.python.org
  pam >= 0.76, http://pam.sourceforge.net/


Building and Installing
-----------------------

  The build dependencies are:
    - Python2 development system, http://www.python.org
    - A POSIX system (make, unix shell, sed, etc).
    - The PAM development libraries,
      http://pam.sourceforge.net

  In addition the unit test requires:
    - sudo, http://www.sudo.ws/
    - An account with root privileges.

  To build the re-distributable, in the directory containing
  this file run:
    make

  To install, in the directory containing this file run:
    make install

  To run the test suite, in the directory containing this file run:
    make test


License
-------

  Copyright (c) 2007-2014,2016 Russell Stuart.

  This program is free software: you can redistribute it and/or modify it
  under the terms of the GNU Affero General Public License as published by
  the Free Software Foundation, either version 3 of the License, or (at your
  option) any later version.

  The copyright holders grant you an additional permission under Section 7
  of the GNU Affero General Public License, version 3, exempting you from
  the requirement in Section 6 of the GNU General Public License, version 3,
  to accompany Corresponding Source with Installation Information for the
  Program or any work based on the Program. You are still required to
  comply with all other Section 6 requirements to provide Corresponding
  Source.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.


--
Russell Stuart
2014-May-29

============
crypto-email
============

.. raw:: html

  <p align="center">
    <br> 🚧 &nbsp;&nbsp;&nbsp;<b>Work-In-Progress</b>
  </p>
  
Send and receive encrypted emails.

.. contents:: **Contents**
   :depth: 3
   :local:
   :backlinks: top
   
Python dependencies
===================
- **Platform:** macOS and Linux
- **Python:**  3.7+

Install package
===============
To install the ``monitoring`` package:

.. code-block:: bash

   pip install git+https://github.com/raul23/mac-monitoring#egg=mac-monitoring

Uninstall package
=================
To uninstall only the ``monitoring`` package:

.. code-block:: bash
 
   monitor -u
   
**NOTE:** the config files and reports will still be left in the ``~/mac-monitoring`` directory

|

If you want to also remove all config files and reports, use also the ``--all`` flag:

.. code-block:: bash
 
   monitor -u --all

**NOTE:** the ``--all`` flag will also remove the whole ``~/mac-monitoring`` directory along 
with all files in it (e.g. config files)

Scripts
=======
``serviced.py``
---------------
description
"""""""""""
options
"""""""

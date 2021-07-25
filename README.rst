==============
mac-monitoring
==============

.. raw:: html

  <p align="center">
    <br> 🚧 &nbsp;&nbsp;&nbsp;<b>Work-In-Progress</b>
  </p>
  
The main objective is to build a monitoring program for macOS that will check for
anomalies in your system (e.g. failed login attempts) and alert you of any 
suspicious activities within your system. It will be able to save the reports 
locally and/or send them through encrypted emails to a specified email account.

`:warning:`

  **Disclaimer**

  This repository is for educational and informational purposes only. The
  author, raul23, assumes no responsibility for the use of this repository,
  code or any information contained therein. The user is solely responsible for
  any action he/she takes with this repository, code and information contained
  in it.

  Do not abuse this material. Be responsible.

.. contents:: **Contents**
   :depth: 3
   :local:
   :backlinks: top
   
Python dependencies
===================
- **Platform:** macOS
- **Python:**  3.7

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

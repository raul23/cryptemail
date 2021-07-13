==============
mac-monitoring
==============

.. raw:: html

  <p align="center">
    <br> 🚧 &nbsp;&nbsp;&nbsp;<b>Work-In-Progress</b>
  </p>
  
The main objective is to build a monitoring program for Mac that will
check for anomalies in your system (e.g. failed login attempts and potential
keyloggers or spyware installed) and alert you for any suspicious activities 
within your system. It will be able to save the reports locally and/or send 
them through encrypted emails to one of your email accounts.

You will be able to control the program remotely through ``ssh``.

`:warning:`

  **Disclaimer**

  This repository is for educational and informational purposes 
  only. The author, raul23, assumes no responsibility for the use 
  of this repository, code or any information contained therein. 
  The user is solely responsible for any action he/she takes with 
  this repository, code and information contained in it.

  Do not abuse this material. Be responsible.

.. contents:: **Contents**
   :depth: 3
   :local:
   :backlinks: top

Install package
===============
To install ``monitoring`` package:

.. code-block:: bash

   pip install git+https://github.com/raul23/mac-monitoring#egg=mac-monitoring

Uninstall package
=================
To uninstall ``monitoring`` package:

.. code-block:: bash

   pip uninstall mac-monitoring

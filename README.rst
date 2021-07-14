==============
mac-monitoring
==============

.. raw:: html

  <p align="center">
    <br> 🚧 &nbsp;&nbsp;&nbsp;<b>Work-In-Progress</b>
  </p>
  
The main objective is to build a monitoring program for Mac that will check for
anomalies in your system (e.g. failed login attempts and potential keyloggers
or spyware installed) and alert you of any suspicious activities within your
system. It will be able to save the reports locally and/or send them through
encrypted emails to a specified email account.

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
   
`:information_source:`

   When uninstalling the ``monitoring`` package, you might be informed
   that the configuration files *logging.py* and *config.py* won't be
   removed by *pip*. You can remove those files manually by noting their paths
   returned by *pip*. Or you can leave them so your saved settings can be
   re-used the next time you re-install the package.

   **Example:** uninstall the package and remove the config files

   .. code-block:: console
   
      $ pip uninstall pyebooktools
      Found existing installation: mac-monitoring 0.1.0a1
      Uninstalling mac-monitoring-0.1.0a1:
        Would remove:
          /Users/test/miniconda3/envs/monitor37/bin/monitor
          /Users/test/miniconda3/envs/monitor37/lib/python3.7/site-packages/mac_monitoring-0.1.0a1.dist-info/*
          /Users/test/miniconda3/envs/monitor37/lib/python3.7/site-packages/monitoring/*
        Would not remove (might be manually added):
          /Users/test/miniconda3/envs/monitor37/lib/python3.7/site-packages/monitoring/configs/config.py
          /Users/test/miniconda3/envs/monitor37/lib/python3.7/site-packages/monitoring/configs/logging.py
      Proceed (y/n)? y
        Successfully uninstalled mac-monitoring-0.1.0a1
      $ rm -r /Users/test/miniconda3/envs/monitor37/lib/python3.7/site-packages/monitoring/
   

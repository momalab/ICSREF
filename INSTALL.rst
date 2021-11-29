``ICSREF`` is developed in Python 2.7. To install it on a fresh Ubuntu 16.04 LTS system you can follow these steps:

Install the system dependencies:
--------------------------------
  
.. code-block:: none

    sudo apt install git python-pip libcapstone3 python-dev libffi-dev build-essential virtualenvwrapper graphviz libgraphviz-dev graphviz-dev pkg-config

Install radare2 v3.1.3
---------------

.. code-block:: none
    
    wget https://github.com/radareorg/radare2/archive/refs/tags/3.1.3.zip
    unzip 3.1.3.zip && cd radare2-3.1.3
    ./sys/install.sh && cd ..

Download the ICSREF repo
------------------------

.. code-block:: none

   git clone https://github.com/momalab/ICSREF.git && cd ICSREF

Create a virtual environment (in a fresh shell)
-----------------------------------------------

.. code-block:: none

    mkvirtualenv icsref

Install the python package dependencies
---------------------------------------

To ensure stability, local wheels of the dependencies are included in the ``wheelhouse`` directory:

.. code-block:: none

    pip install --no-index --find-links=wheelhouse -r requirements.txt

Create bash alias
-----------------

.. code-block:: none

    echo -e "\n# ICSREF alias\nalias icsref='workon icsref && python `pwd`/icsref/icsref.py'\n" >> ~/.bash_aliases && source ~/.bashrc

Run
---

You are ready to go! You can now run ``icsref`` in a fresh shell. You should see something like this:

.. code-block:: none
    
    me@example:$ icsref

    ICS Reverse Engineering Framework
        _______________ ____  ____________
       /  _/ ____/ ___// __ \/ ____/ ____/
       / // /    \__ \/ /_/ / __/ / /_    
     _/ // /___ ___/ / _, _/ /___/ __/    
    /___/\____//____/_/ |_/_____/_/       
                               
    author: Tasos Keliris (@koukouviou)
    Type <help> if you need a nudge
    reversing@icsref:$ 


Check the tutorial in the preview_ for usage examples.

.. _preview: README.rst#preview


Known to work
=============

``ICSREF`` has been tested:

* on Intel x86_64 CPUs running the Ubuntu 18.04 LTS operating system

* on ARM, on a Nexus 5 LG phone running Ubuntu Touch 15.04 (the only caveat is that the ``-malign-double`` compiler flag must be removed when installing pyvex)

Regardless, since the framework is built with python, using it with different architectures and operating systems should be trivial. 

**Make sure to switch to the icsref virtual environment for using ICSREF with** ``workon icsref``, **and** ``deactivate`` **the virtual environment once you are done.**

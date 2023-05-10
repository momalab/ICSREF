# ICSREF Installation
ICSREF is written in Python 2.7. To run it on a fresh installation of Ubuntu 22.04 LTS you can follow these instructions.

1. Make sure apt is up to date: ```sudo apt update```
2. Install Python 2.7: ```sudo apt install python2.7```
3. Download and install pip for Python 2.7: ```curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py && sudo python2.7 get-pip.py```
4. Install package dependencies: ```sudo apt install git libcapstone-dev python2.7-dev python2-setuptools-whl libffi-dev build-essential graphviz libgraphviz-dev graphviz-dev pkg-config unzip virtualenv```
5. Download radare2 v3.1.3: ```wget https://github.com/radareorg/radare2/archive/refs/tags/3.1.3.zip && unzip 3.1.3.zip```
6. Install radare2: ```radare2-3.1.3/sys/install.sh```
7. Download ICSREF: ```git clone https://github.com/momalab/ICSREF.git```
8. Create virtual environment for ICSREF: ```virtualenv --python=$(which python2.7) venv-icsref```
9. Activate virtual environment: ```source venv-icsref/bin/activate```
10. Install ICSREF requirements: ```pip2.7 install --no-index --find-links=wheelhouse -r ICSREF/requirements.txt```
11. Start ICSREF: ```python2.7 ICSREF/icsref/icsref.py```

Make sure to use activate the ICSREF python virtual environment before using ICSREF, and deactivate it after use.

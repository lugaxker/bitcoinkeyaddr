#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
if sys.version_info < (3, 5):
    sys.exit("Error: Must be using Python 3.5 or higher")

import imp
imp.load_module('bitcoinkeyaddr', *imp.find_module('lib'))
imp.load_module('bitcoinkeyaddr_gui', *imp.find_module('gui'))

from PyQt5.QtWidgets import QApplication
from bitcoinkeyaddr_gui.mainwindow import *

if __name__ == '__main__':
    app = QApplication(sys.argv)
    bka = BitcoinkeyaddrWindow()
    sys.exit(app.exec_())

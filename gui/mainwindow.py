#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt5.QtCore import Qt
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from bitcoinkeyaddr.address import Address, wifkey_to_address
from bitcoinkeyaddr.keys import EllipticCurveKey, point_to_ser

class BitcoinkeyaddrWindow(QMainWindow):
    
    def __init__(self):
        super().__init__()
        
        self.tabs = QTabWidget(self)
        
        self.tabs.addTab(self.create_keytoaddr_tab(), QIcon('icons/right_black_arrow.png'), "Clé privée vers adresse")
        self.tabs.addTab(self.create_converter_tab(), QIcon('icons/electron_converter.png'), "Convertisseur d'adresses")
        
        self.tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setCentralWidget(self.tabs)
        
        self.tabs.show()
        
        self.setGeometry(100, 100, 600, 200)
        self.setWindowTitle('Clé et adresse Bitcoin')
        self.setWindowIcon(QIcon('icons/bitcoincash_logo.png'))
        
        self.show()
        
    def create_keytoaddr_tab(self):
        wifkeyLabel = QLabel('Clé privée (WIF)')
        wifkeyLabel.setAlignment(Qt.AlignCenter)
        legaddrLabel = QLabel('Adresse legacy')
        legaddrLabel.setAlignment(Qt.AlignCenter)
        cashaddrLabel = QLabel('Adresse cash')
        cashaddrLabel.setAlignment(Qt.AlignCenter)

        wifkeyEdit = QLineEdit()
        legaddrEdit = QLineEdit()
        cashaddrEdit = QLineEdit()
        legaddrEdit.setReadOnly(True)
        cashaddrEdit.setReadOnly(True)
        
        wifkeyEdit.setText("5JHpKWaBtKSe2vmRq1Jai622s18BLJcSCWXcXVKothR3eQY63wb")
        
        computeButton = QPushButton("Calculer")
        clearButton = QPushButton("Effacer")
        
        def keytoaddr():
            try:
                newaddr = wifkey_to_address( wifkeyEdit.text().strip() )
            except:
                newaddr = None
            if newaddr:
                legaddrEdit.setText(newaddr.to_legacy())
                cashaddrEdit.setText(newaddr.to_full_cash())
            else:
                legaddrEdit.setText('')
                cashaddrEdit.setText('')
        
        def clearfields():
            wifkeyEdit.setText("")
            legaddrEdit.setText("")
            cashaddrEdit.setText("")
        
        computeButton.clicked.connect(keytoaddr)
        clearButton.clicked.connect(clearfields)

        w = QWidget()
        grid = QGridLayout()
        grid.setSpacing(20)

        grid.addWidget(wifkeyLabel, 0, 0)
        grid.addWidget(wifkeyEdit, 0, 1, 1, 3)
        grid.addWidget(legaddrLabel, 1, 0)
        grid.addWidget(legaddrEdit, 1, 1, 1, 3)
        grid.addWidget(cashaddrLabel, 2, 0)
        grid.addWidget(cashaddrEdit, 2, 1, 1, 3)
        
        grid.addWidget(computeButton, 3, 0, 1, 3)
        grid.addWidget(clearButton, 3, 3, 1, 1)
        
        w.setLayout(grid)
        
        return w
        
    def create_converter_tab(self):
        legaddrLabel = QLabel('Adresse legacy')
        legaddrLabel.setAlignment(Qt.AlignCenter)
        cashaddrLabel = QLabel('Adresse cash')
        cashaddrLabel.setAlignment(Qt.AlignCenter)
        
        legaddrEdit = QLineEdit()
        cashaddrEdit = QLineEdit()
        legaddrEdit.setText("16pAvqgprTxWG9E7McxGNxqKZeEeuWMFhf")
        
        legtocashButton = QPushButton(QIcon('icons/down_red_arrow.png'),"Convertir en adresse cash")
        cashtolegButton = QPushButton(QIcon('icons/up_red_arrow.png'),"Convertir en adresse legacy")
        clearButton = QPushButton("Effacer")
        
        def convert_legtocash():
            try:
                addr = Address.from_legacy_string( legaddrEdit.text().strip() )
            except:
                addr = None
            if addr:
                cashaddrEdit.setText(addr.to_full_cash())
        
        def convert_cashtoleg():
            try:
                addr = Address.from_cash_string( cashaddrEdit.text().strip() )
            except:
                addr = None
            if addr:
                legaddrEdit.setText(addr.to_legacy())
        
        def clearfields():
            legaddrEdit.setText("")
            cashaddrEdit.setText("")
        
        
        legtocashButton.clicked.connect(convert_legtocash)
        cashtolegButton.clicked.connect(convert_cashtoleg)
        clearButton.clicked.connect(clearfields)
        
        w = QWidget()
        grid = QGridLayout()
        grid.setSpacing(20)

        grid.addWidget(legaddrLabel, 0, 1)
        grid.addWidget(legaddrEdit, 1, 0, 1, 3)
        
        
        grid.addWidget(legtocashButton, 2, 0, 1, 1)
        grid.addWidget(clearButton, 2, 1, 1, 1)
        grid.addWidget(cashtolegButton, 2, 2, 1, 1)
        
        grid.addWidget(cashaddrLabel, 4, 1)
        grid.addWidget(cashaddrEdit, 3, 0, 1, 3)
        
        
        w.setLayout(grid)
        
        return w
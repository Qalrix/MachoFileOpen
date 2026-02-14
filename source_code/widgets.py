import re
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

class HexViewer(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont('Courier New', 10))
        
    def setData(self, data):
        if not data:
            return
            
        hex_text = []
        
        # Generate hex dump with ASCII
        for i in range(0, len(data), 16):
            # Address
            hex_text.append(f"{i:08x}: ")
            
            # Hex bytes
            hex_bytes = data[i:i+16]
            hex_part = ' '.join(f"{b:02x}" for b in hex_bytes)
            hex_text.append(f"{hex_part:<48} ")
            
            # ASCII representation
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in hex_bytes)
            hex_text.append(f"|{ascii_part}|\n")
            
        self.setText(''.join(hex_text))

class StringViewer(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        
        # Search box
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search strings...")
        self.search_input.textChanged.connect(self.filterStrings)
        search_layout.addWidget(self.search_input)
        
        # Language filter
        search_layout.addWidget(QLabel("Language:"))
        self.lang_filter = QComboBox()
        self.lang_filter.addItems(["All", "C", "C++", "Objective-C", "ASCII", "UTF-8"])
        self.lang_filter.currentTextChanged.connect(self.filterStrings)
        search_layout.addWidget(self.lang_filter)
        
        search_layout.addStretch()
        layout.addLayout(search_layout)
        
        # String table
        self.string_table = QTableWidget()
        self.string_table.setColumnCount(4)
        self.string_table.setHorizontalHeaderLabels(['Offset', 'String', 'Length', 'Type'])
        self.string_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.string_table)
        
    def setStrings(self, strings):
        self.strings_data = strings
        self.displayStrings(strings)
        
    def displayStrings(self, strings):
        self.string_table.setRowCount(len(strings))
        
        for i, string_info in enumerate(strings):
            offset_item = QTableWidgetItem(string_info.get('offset', ''))
            string_item = QTableWidgetItem(string_info.get('string', ''))
            length_item = QTableWidgetItem(str(len(string_info.get('string', ''))))
            type_item = QTableWidgetItem(self._detect_string_type(string_info.get('string', '')))
            
            self.string_table.setItem(i, 0, offset_item)
            self.string_table.setItem(i, 1, string_item)
            self.string_table.setItem(i, 2, length_item)
            self.string_table.setItem(i, 3, type_item)
            
    def filterStrings(self):
        if not hasattr(self, 'strings_data'):
            return
            
        search_text = self.search_input.text().lower()
        lang_filter = self.lang_filter.currentText()
        
        filtered = []
        for s in self.strings_data:
            string_val = s.get('string', '')
            string_type = self._detect_string_type(string_val)
            
            # Apply filters
            if search_text and search_text not in string_val.lower():
                continue
                
            if lang_filter != "All" and lang_filter != string_type and lang_filter != "ASCII":
                continue
                
            filtered.append(s)
            
        self.displayStrings(filtered)
        
    def _detect_string_type(self, s: str) -> str:
        """Detect the type/language of a string"""
        if any(c in s for c in ['@interface', '@implementation', 'NS', 'UI', 'objc']):
            return "Objective-C"
        elif any(c in s for c in ['std::', 'class', 'template', 'virtual']):
            return "C++"
        elif any(c in s for c in ['#include', 'struct', 'malloc']):
            return "C"
        elif all(ord(c) < 128 for c in s):
            return "ASCII"
        else:
            return "UTF-8"

class ObjCClassViewer(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        
        layout.addWidget(QLabel("Objective-C Classes:"))
        
        # Class tree
        self.class_tree = QTreeWidget()
        self.class_tree.setHeaderLabels(['Class Name', 'Inheritance', 'Protocols', 'Method Count'])
        self.class_tree.itemClicked.connect(self.onClassSelected)
        layout.addWidget(self.class_tree)
        
    def setClasses(self, classes):
        self.class_tree.clear()
        
        for cls in classes:
            item = QTreeWidgetItem(self.class_tree)
            item.setText(0, cls.get('name', ''))
            item.setText(1, cls.get('inheritance', 'NSObject'))
            item.setText(2, ', '.join(cls.get('protocols', [])))
            item.setText(3, str(len(cls.get('methods', []))))
            
            # Store full class data
            item.setData(0, Qt.UserRole, cls)
            
    def onClassSelected(self, item, column):
        # Emit signal to show class details
        class_data = item.data(0, Qt.UserRole)
        # Update method viewer with class methods
        pass

class MethodViewer(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        
        layout.addWidget(QLabel("Methods/Selectors:"))
        
        # Method table
        self.method_table = QTableWidget()
        self.method_table.setColumnCount(3)
        self.method_table.setHorizontalHeaderLabels(['Type', 'Signature', 'Offset'])
        self.method_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.method_table)
        
    def setMethods(self, methods):
        self.method_table.setRowCount(len(methods))
        
        for i, method in enumerate(methods):
            type_item = QTableWidgetItem(method.get('type', ''))
            sig_item = QTableWidgetItem(method.get('signature', ''))
            offset_item = QTableWidgetItem(method.get('offset', ''))
            
            self.method_table.setItem(i, 0, type_item)
            self.method_table.setItem(i, 1, sig_item)
            self.method_table.setItem(i, 2, offset_item)

class ProtocolViewer(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        
        layout.addWidget(QLabel("Protocols:"))
        
        # Protocol tree
        self.protocol_tree = QTreeWidget()
        self.protocol_tree.setHeaderLabels(['Protocol Name', 'Methods', 'Offset'])
        layout.addWidget(self.protocol_tree)
        
    def setProtocols(self, protocols):
        self.protocol_tree.clear()
        
        for protocol in protocols:
            item = QTreeWidgetItem(self.protocol_tree)
            item.setText(0, protocol.get('name', ''))
            item.setText(1, str(len(protocol.get('methods', []))))
            item.setText(2, protocol.get('offset', ''))
            
            # Add methods as children
            for method in protocol.get('methods', [])[:10]:
                child = QTreeWidgetItem(item)
                child.setText(1, method)

class SymbolViewer(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("Filter by Language:"))

        self.lang_filter = QComboBox()
        self.lang_filter.addItems(["All", "C", "C++", "Objective-C", "Undefined"])
        self.lang_filter.currentTextChanged.connect(self.filterSymbols)
        toolbar.addWidget(self.lang_filter)

        self.demangle_btn = QPushButton("Demangle C++/Objective-C")
        toolbar.addWidget(self.demangle_btn)

        toolbar.addStretch()
        layout.addLayout(toolbar)

        # Symbol tree
        self.symbol_tree = QTreeWidget()
        self.symbol_tree.setHeaderLabels(['Name', 'Demangled', 'Type', 'Value', 'Language'])
        self.symbol_tree.header().setStretchLastSection(True)
        layout.addWidget(self.symbol_tree)

        # Store data
        self.symbols_data = []

    def setSymbols(self, symbols):
        self.symbols_data = symbols if isinstance(symbols, list) else []
        self.displaySymbols(self.symbols_data)

    def displaySymbols(self, symbols):
        self.symbol_tree.clear()

        for symbol in symbols:
            if not isinstance(symbol, dict):
                continue

            item = QTreeWidgetItem(self.symbol_tree)
            name = symbol.get('name', '')
            demangled = symbol.get('demangled', '')
            language = self._detect_symbol_language(name, demangled)

            item.setText(0, str(name))
            item.setText(1, str(demangled))
            item.setText(2, str(symbol.get('type', '')))
            item.setText(3, str(symbol.get('value', '')))
            item.setText(4, str(language))

    def filterSymbols(self, language):
        if not hasattr(self, 'symbols_data') or not self.symbols_data:
            return

        if language == "All":
            self.displaySymbols(self.symbols_data)
        else:
            filtered = []
            for symbol in self.symbols_data:
                if not isinstance(symbol, dict):
                    continue
                sym_lang = self._detect_symbol_language(
                    symbol.get('name', ''),
                    symbol.get('demangled', '')
                )
                if sym_lang == language:
                    filtered.append(symbol)
            self.displaySymbols(filtered)

    def _detect_symbol_language(self, name, demangled):
        """Detect the programming language of a symbol"""
        name = str(name) if name else ''
        demangled = str(demangled) if demangled else ''

        if any(p in name for p in ['_OBJC_', '.c', 'objc']):
            return "Objective-C"
        elif any(p in name for p in ['_Z', '__Z']):
            return "C++"
        elif demangled and ('::' in demangled or 'std::' in demangled):
            return "C++"
        elif name.startswith('_'):
            return "C"
        else:
            return "Undefined"

    def setDemangleCallback(self, callback):
        self.demangle_btn.clicked.connect(callback)

class SignatureViewer(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        
        # Signature list
        self.signature_list = QListWidget()
        layout.addWidget(self.signature_list)
        
    def setSignatures(self, signatures):
        self.signature_list.clear()
        
        for sig in signatures:
            item_text = f"{sig.get('name', 'Unknown')} at {sig.get('offset', '0x0')}"
            item = QListWidgetItem(item_text)
            
            # Color code by type
            if 'Mach-O' in sig.get('name', ''):
                item.setForeground(QColor(0, 255, 0))  # Green
            elif 'Objective-C' in sig.get('name', ''):
                item.setForeground(QColor(255, 165, 0))  # Orange
            elif 'C++' in sig.get('name', ''):
                item.setForeground(QColor(100, 149, 237))  # Cornflower blue
                
            self.signature_list.addItem(item)

class HashViewer(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        
        # Hash display
        self.hash_text = QTextEdit()
        self.hash_text.setReadOnly(True)
        layout.addWidget(self.hash_text)
        
    def setHashes(self, macho_data):
        hash_text = []
        
        if 'hashes' in macho_data:
            hash_text.append("File Hashes:")
            hash_text.append("=" * 50)
            hash_text.append(f"MD5:    {macho_data['hashes'].get('md5', 'N/A')}")
            hash_text.append(f"SHA1:   {macho_data['hashes'].get('sha1', 'N/A')}")
            hash_text.append(f"SHA256: {macho_data['hashes'].get('sha256', 'N/A')}")
            hash_text.append("")
            
        hash_text.append("File Information:")
        hash_text.append("=" * 50)
        hash_text.append(f"File Type: {macho_data.get('file_type', 'N/A')}")
        hash_text.append(f"CPU Type: {macho_data.get('cpu_type', 'N/A')}")
        hash_text.append(f"Magic: {macho_data.get('magic', 'N/A')}")
        
        # Language information
        if 'languages' in macho_data:
            hash_text.append("\nDetected Languages:")
            for lang in macho_data['languages']:
                hash_text.append(f"  - {lang}")
                
        # Objective-C statistics
        if 'objc_classes' in macho_data:
            hash_text.append(f"\nObjective-C Statistics:")
            hash_text.append(f"  - Classes: {len(macho_data['objc_classes'])}")
            hash_text.append(f"  - Methods: {len(macho_data.get('objc_methods', []))}")
            hash_text.append(f"  - Protocols: {len(macho_data.get('objc_protocols', []))}")
            
        # C++ statistics
        if 'cpp_classes' in macho_data:
            hash_text.append(f"\nC++ Statistics:")
            hash_text.append(f"  - Classes: {len(macho_data['cpp_classes'])}")
            hash_text.append(f"  - Templates: {len(macho_data.get('cpp_templates', []))}")
            
        # C statistics
        if 'symbols' in macho_data:
            c_symbols = [s for s in macho_data['symbols'] 
                        if s.get('type') in ['N_SECT', 'N_ABS']]
            hash_text.append(f"\nC Statistics:")
            hash_text.append(f"  - Functions: {len(c_symbols)}")
            
        self.hash_text.setText('\n'.join(hash_text))

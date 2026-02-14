import sys
import os
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from macho_parser import MachOParser
from decompiler import Decompiler
from language_parser import LanguageParser
from widgets import (HexViewer, StringViewer, SymbolViewer, SignatureViewer, 
                    HashViewer, ObjCClassViewer, MethodViewer, ProtocolViewer)
from about import AboutDialog

class MachOFileAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_file = None
        self.macho_data = None
        self.decompiled_code = None
        self.parser = MachOParser()
        self.decompiler = Decompiler()
        self.language_parser = LanguageParser()
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle("MachoFileOpen (BETA 0.1.0)")
        self.setGeometry(100, 100, 1600, 1000)
        
        # Set application style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
            }
            QMenuBar {
                background-color: #3c3c3c;
                color: white;
                padding: 5px;
            }
            QMenuBar::item:selected {
                background-color: #505050;
            }
            QMenu {
                background-color: #3c3c3c;
                color: white;
                border: 1px solid #505050;
            }
            QMenu::item:selected {
                background-color: #505050;
            }
            QTabWidget::pane {
                border: 1px solid #505050;
                background-color: #2b2b2b;
            }
            QTabBar::tab {
                background-color: #3c3c3c;
                color: white;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #505050;
            }
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                font-family: 'Courier New';
                font-size: 12px;
                border: 1px solid #505050;
            }
            QTreeWidget {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #505050;
            }
            QTreeWidget::item:selected {
                background-color: #505050;
            }
            QPushButton {
                background-color: #505050;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #606060;
            }
            QLabel {
                color: white;
            }
            QComboBox {
                background-color: #3c3c3c;
                color: white;
                border: 1px solid #505050;
                padding: 5px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid white;
                margin-right: 5px;
            }
        """)
        
        self.createMenuBar()
        self.createToolBar()
        self.createCentralWidget()
        self.createStatusBar()
        
    def createMenuBar(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        import_action = QAction('Import Mach-O File', self)
        import_action.setShortcut('Ctrl+O')
        import_action.triggered.connect(self.importFile)
        file_menu.addAction(import_action)
        
        save_action = QAction('Save Decompiled Code', self)
        save_action.setShortcut('Ctrl+S')
        save_action.triggered.connect(self.saveDecompiledCode)
        file_menu.addAction(save_action)
        
        export_action = QAction('Export as Text', self)
        export_action.setShortcut('Ctrl+E')
        export_action.triggered.connect(self.exportAsText)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Language menu
        language_menu = menubar.addMenu('Language')
        
        self.detect_language_action = QAction('Auto-Detect Language', self)
        self.detect_language_action.setCheckable(True)
        self.detect_language_action.setChecked(True)
        language_menu.addAction(self.detect_language_action)
        
        language_menu.addSeparator()
        
        self.objc_action = QAction('Objective-C Analysis', self)
        self.objc_action.triggered.connect(self.showObjCAnalysis)
        language_menu.addAction(self.objc_action)
        
        self.cpp_action = QAction('C++ Analysis', self)
        self.cpp_action.triggered.connect(self.showCPPAnalysis)
        language_menu.addAction(self.cpp_action)
        
        self.c_action = QAction('C Analysis', self)
        self.c_action.triggered.connect(self.showCAnalysis)
        language_menu.addAction(self.c_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        decompile_menu = QMenu('Decompile As', self)
        decompile_cpp = QAction('C++', self)
        decompile_cpp.triggered.connect(lambda: self.decompileCode('cpp'))
        decompile_menu.addAction(decompile_cpp)
        
        decompile_c = QAction('C', self)
        decompile_c.triggered.connect(lambda: self.decompileCode('c'))
        decompile_menu.addAction(decompile_c)
        
        decompile_objc = QAction('Objective-C', self)
        decompile_objc.triggered.connect(lambda: self.decompileCode('objc'))
        decompile_menu.addAction(decompile_objc)
        
        tools_menu.addMenu(decompile_menu)
        
        demangle_action = QAction('Demangle Symbols', self)
        demangle_action.triggered.connect(self.demangleSymbols)
        tools_menu.addAction(demangle_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.showAbout)
        help_menu.addAction(about_action)
        
    def createToolBar(self):
        toolbar = self.addToolBar('Tools')
        toolbar.setStyleSheet("background-color: #3c3c3c;")
        
        import_btn = QAction(QIcon(), 'Import', self)
        import_btn.triggered.connect(self.importFile)
        toolbar.addAction(import_btn)
        
        save_btn = QAction(QIcon(), 'Save', self)
        save_btn.triggered.connect(self.saveDecompiledCode)
        toolbar.addAction(save_btn)
        
        # Language selector
        toolbar.addSeparator()
        toolbar.addWidget(QLabel("Language: "))
        
        self.language_combo = QComboBox()
        self.language_combo.addItems(["Auto-Detect", "C", "C++", "Objective-C", "Mixed"])
        self.language_combo.currentTextChanged.connect(self.onLanguageChanged)
        toolbar.addWidget(self.language_combo)
        
        decompile_btn = QPushButton("Decompile")
        decompile_btn.clicked.connect(self.decompileCode)
        toolbar.addWidget(decompile_btn)
        
    def createCentralWidget(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        
        # File info bar
        self.file_info_label = QLabel("No file loaded")
        self.file_info_label.setStyleSheet("""
            QLabel {
                background-color: #3c3c3c;
                padding: 10px;
                border: 1px solid #505050;
                font-weight: bold;
            }
        """)
        main_layout.addWidget(self.file_info_label)
        
        # Language detection info
        self.language_info_label = QLabel("")
        self.language_info_label.setStyleSheet("""
            QLabel {
                background-color: #404040;
                padding: 5px;
                border: 1px solid #505050;
                color: #a0a0a0;
            }
        """)
        main_layout.addWidget(self.language_info_label)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Decompiler tab
        self.decompiler_tab = QWidget()
        self.setupDecompilerTab()
        self.tab_widget.addTab(self.decompiler_tab, "Decompiler")
        
        # Objective-C Analysis tab
        self.objc_tab = QWidget()
        self.setupObjCTab()
        self.tab_widget.addTab(self.objc_tab, "Objective-C")
        
        # C/C++ Analysis tab
        self.cpp_tab = QWidget()
        self.setupCPPTab()
        self.tab_widget.addTab(self.cpp_tab, "C/C++")
        
        # Hex Viewer tab
        self.hex_viewer = HexViewer()
        self.tab_widget.addTab(self.hex_viewer, "Hex Viewer")
        
        # String Viewer tab
        self.string_viewer = StringViewer()
        self.tab_widget.addTab(self.string_viewer, "Strings")
        
        # Symbol Viewer tab
        self.symbol_viewer = SymbolViewer()
        self.tab_widget.addTab(self.symbol_viewer, "Symbols")
        
        # Signature Viewer tab
        self.signature_viewer = SignatureViewer()
        self.tab_widget.addTab(self.signature_viewer, "Signatures")
        
        # Hash Viewer tab
        self.hash_viewer = HashViewer()
        self.tab_widget.addTab(self.hash_viewer, "Hashes")
        
    def setupDecompilerTab(self):
        layout = QVBoxLayout(self.decompiler_tab)
        
        # Control buttons
        control_layout = QHBoxLayout()
        
        self.decompile_btn = QPushButton("Decompile (Auto-Detect)")
        self.decompile_btn.clicked.connect(lambda: self.decompileCode('auto'))
        control_layout.addWidget(self.decompile_btn)
        
        self.save_cpp_btn = QPushButton("Save as .cpp")
        self.save_cpp_btn.clicked.connect(lambda: self.saveDecompiledCode("cpp"))
        control_layout.addWidget(self.save_cpp_btn)
        
        self.save_c_btn = QPushButton("Save as .c")
        self.save_c_btn.clicked.connect(lambda: self.saveDecompiledCode("c"))
        control_layout.addWidget(self.save_c_btn)
        
        self.save_mm_btn = QPushButton("Save as .mm")
        self.save_mm_btn.clicked.connect(lambda: self.saveDecompiledCode("mm"))
        control_layout.addWidget(self.save_mm_btn)
        
        self.save_txt_btn = QPushButton("Save as .txt")
        self.save_txt_btn.clicked.connect(lambda: self.saveDecompiledCode("txt"))
        control_layout.addWidget(self.save_txt_btn)
        
        control_layout.addStretch()
        layout.addLayout(control_layout)
        
        # Language info bar
        info_layout = QHBoxLayout()
        info_layout.addWidget(QLabel("Detected Language:"))
        self.detected_language_label = QLabel("Not detected")
        self.detected_language_label.setStyleSheet("color: #00ff00; font-weight: bold;")
        info_layout.addWidget(self.detected_language_label)
        info_layout.addStretch()
        layout.addLayout(info_layout)
        
        # Decompiled code display
        self.decompiled_text = QTextEdit()
        self.decompiled_text.setReadOnly(True)
        
        # Set syntax highlighting based on language
        self.decompiled_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                font-family: 'Courier New', 'Menlo', 'Monaco', monospace;
                font-size: 12px;
            }
        """)
        
        layout.addWidget(self.decompiled_text)
        
    def setupObjCTab(self):
        layout = QVBoxLayout(self.objc_tab)
        
        # Splitter for better organization
        splitter = QSplitter(Qt.Vertical)
        
        # Class Viewer
        self.objc_class_viewer = ObjCClassViewer()
        splitter.addWidget(self.objc_class_viewer)
        
        # Method Viewer
        self.method_viewer = MethodViewer()
        splitter.addWidget(self.method_viewer)
        
        # Protocol Viewer
        self.protocol_viewer = ProtocolViewer()
        splitter.addWidget(self.protocol_viewer)
        
        layout.addWidget(splitter)
        
    def setupCPPTab(self):
        layout = QVBoxLayout(self.cpp_tab)
        
        # Splitter for C/C++ analysis
        splitter = QSplitter(Qt.Horizontal)
        
        # Class hierarchy viewer
        class_widget = QWidget()
        class_layout = QVBoxLayout(class_widget)
        class_layout.addWidget(QLabel("C++ Classes:"))
        self.cpp_class_tree = QTreeWidget()
        self.cpp_class_tree.setHeaderLabels(['Class Name', 'Methods', 'Inheritance'])
        class_layout.addWidget(self.cpp_class_tree)
        splitter.addWidget(class_widget)
        
        # Templates and STL viewer
        template_widget = QWidget()
        template_layout = QVBoxLayout(template_widget)
        template_layout.addWidget(QLabel("Templates/STL:"))
        self.template_list = QListWidget()
        template_layout.addWidget(self.template_list)
        splitter.addWidget(template_widget)
        
        layout.addWidget(splitter)
        
    def createStatusBar(self):
        self.statusBar().showMessage('Ready')
        self.statusBar().setStyleSheet("""
            QStatusBar {
                background-color: #3c3c3c;
                color: white;
            }
        """)
        
    def importFile(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Mach-O File",
            "",
            "Mach-O Files (*.o *.dylib *.bin *.so *.0 *.exe *.app/Contents/MacOS/*);;All Files (*)"
        )
        
        if file_path:
            try:
                self.current_file = file_path
                self.macho_data = self.parser.parse(file_path)
                
                # Detect languages used in the binary
                self.macho_data['languages'] = self.language_parser.detect_languages(self.macho_data)
                
                self.updateUI()
                self.statusBar().showMessage(f'Loaded: {os.path.basename(file_path)}')
                
                # Update language info
                languages = self.macho_data.get('languages', [])
                lang_str = ', '.join(languages) if languages else 'Unknown'
                self.language_info_label.setText(f"Detected Languages: {lang_str}")
                self.detected_language_label.setText(lang_str)
                
                # Auto-select language in combo
                if 'Objective-C' in languages:
                    self.language_combo.setCurrentText('Objective-C')
                elif 'C++' in languages:
                    self.language_combo.setCurrentText('C++')
                elif 'C' in languages:
                    self.language_combo.setCurrentText('C')
                else:
                    self.language_combo.setCurrentText('Auto-Detect')
                    
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {str(e)}")
                
    def updateUI(self):
        if self.macho_data:
            # Update hex viewer
            if 'raw_data' in self.macho_data:
                self.hex_viewer.setData(self.macho_data['raw_data'])
            
            # Update string viewer
            if 'strings' in self.macho_data:
                self.string_viewer.setStrings(self.macho_data['strings'])
            
            # Update symbol viewer
            if 'symbols' in self.macho_data:
                self.symbol_viewer.setSymbols(self.macho_data['symbols'])
            
            # Update signature viewer
            if 'signatures' in self.macho_data:
                self.signature_viewer.setSignatures(self.macho_data['signatures'])
            
            # Update hash viewer
            self.hash_viewer.setHashes(self.macho_data)
            
            # Update Objective-C views
            if 'objc_classes' in self.macho_data:
                self.objc_class_viewer.setClasses(self.macho_data['objc_classes'])
            if 'objc_methods' in self.macho_data:
                self.method_viewer.setMethods(self.macho_data['objc_methods'])
            if 'objc_protocols' in self.macho_data:
                self.protocol_viewer.setProtocols(self.macho_data['objc_protocols'])
            
            # Update C++ views
            if 'cpp_classes' in self.macho_data:
                self.updateCPPClasses(self.macho_data['cpp_classes'])
            if 'cpp_templates' in self.macho_data:
                self.updateCPPTemplates(self.macho_data['cpp_templates'])
                
    def updateCPPClasses(self, classes):
        self.cpp_class_tree.clear()
        for class_name, info in classes.items():
            item = QTreeWidgetItem(self.cpp_class_tree)
            item.setText(0, class_name)
            item.setText(1, str(info.get('method_count', 0)))
            item.setText(2, info.get('inheritance', 'None'))
            
    def updateCPPTemplates(self, templates):
        self.template_list.clear()
        for template in templates:
            self.template_list.addItem(template)

    def decompileCode(self, language='auto'):
        """Decompile the loaded Mach-O file"""
        if not self.macho_data:
            QMessageBox.warning(self, "Warning", "No file loaded")
            return

        try:
            self.statusBar().showMessage('Decompiling...')

            # Handle language parameter
            if isinstance(language, bool):
                language = 'auto'
            elif language is None:
                language = 'auto'

            # Convert to string and lowercase
            if not isinstance(language, str):
                language = str(language) if language else 'auto'

            language = language.lower()

            # Auto-detect if needed
            if language == 'auto':
                languages = self.macho_data.get('languages', [])
                if isinstance(languages, list):
                    if 'Objective-C' in languages:
                        language = 'objc'
                    elif 'C++' in languages:
                        language = 'cpp'
                    else:
                        language = 'c'
                else:
                    language = 'c'

            # Map language names
            lang_map = {
                'objective-c': 'objc',
                'objectivec': 'objc',
                'objc': 'objc',
                'c++': 'cpp',
                'cxx': 'cpp',
                'cpp': 'cpp',
                'c': 'c'
            }

            language = lang_map.get(language, 'c')

            # Decompile
            self.decompiled_code = self.decompiler.decompile(self.macho_data, language)

            if self.decompiled_code and isinstance(self.decompiled_code, str):
                self.decompiled_text.setText(self.decompiled_code)

                # Update detected language label
                lang_names = {'c': 'C', 'cpp': 'C++', 'objc': 'Objective-C'}
                detected_lang = lang_names.get(language, language.upper())
                self.detected_language_label.setText(detected_lang)

                self.statusBar().showMessage(f'Decompilation complete ({detected_lang})')
            else:
                self.statusBar().showMessage('Decompilation failed - no output')

        except Exception as e:
            error_msg = f"Decompilation failed: {str(e)}"
            print(error_msg)  # For debugging
            QMessageBox.critical(self, "Error", error_msg)
            self.statusBar().showMessage('Decompilation failed')
            
    def saveDecompiledCode(self, format_type="cpp"):
        if not self.decompiled_code:
            QMessageBox.warning(self, "Warning", "No decompiled code to save")
            return
            
        extensions = {
            "cpp": "C++ Files (*.cpp)",
            "c": "C Files (*.c)",
            "mm": "Objective-C Files (*.mm)",
            "txt": "Text Files (*.txt)",
            "h": "Header Files (*.h)"
        }
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Decompiled Code",
            "",
            extensions.get(format_type, "All Files (*)")
        )
        
        if file_path:
            with open(file_path, 'w') as f:
                f.write(self.decompiled_code)
            self.statusBar().showMessage(f'Saved: {file_path}')
            
    def exportAsText(self):
        self.saveDecompiledCode("txt")
        
    def demangleSymbols(self):
        if not self.macho_data or 'symbols' not in self.macho_data:
            QMessageBox.warning(self, "Warning", "No symbols to demangle")
            return
            
        demangled = self.parser.demangleSymbols(self.macho_data['symbols'])
        self.symbol_viewer.setSymbols(demangled)
        self.statusBar().showMessage('Symbols demangled')
        
    def onLanguageChanged(self, language):
        if language != "Auto-Detect" and self.macho_data:
            self.decompileCode(language.lower())
            
    def showObjCAnalysis(self):
        self.tab_widget.setCurrentWidget(self.objc_tab)
        
    def showCPPAnalysis(self):
        self.tab_widget.setCurrentWidget(self.cpp_tab)
        
    def showCAnalysis(self):
        self.tab_widget.setCurrentWidget(self.cpp_tab)
        
    def showAbout(self):
        about_dialog = AboutDialog(self)
        about_dialog.exec_()

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Set dark theme palette
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ToolTipBase, Qt.white)
    palette.setColor(QPalette.ToolTipText, Qt.white)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Highlight, QColor(142, 45, 197).lighter())
    palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(palette)
    
    window = MachOFileAnalyzer()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()

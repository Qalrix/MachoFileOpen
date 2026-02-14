from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About MachoFileOpen")
        self.setFixedSize(600, 500)
        
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("MachoFileOpen")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("Multi-Language Binary Analysis Tool")
        subtitle_font = QFont()
        subtitle_font.setPointSize(12)
        subtitle.setFont(subtitle_font)
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)
        
        # Version
        version = QLabel("Version 0.1.0 Beta")
        version.setAlignment(Qt.AlignCenter)
        layout.addWidget(version)
        
        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        layout.addWidget(separator)
        
        # Description with tabs for different languages
        tabs = QTabWidget()
        
        # Overview tab
        overview_tab = QTextEdit()
        overview_tab.setReadOnly(True)
        overview_tab.setHtml("""
        <h3>Complete Mach-O Analysis Suite</h3>
        
        <p>This application provides analysis capabilities for Mach-O binary files 
        with full support for multiple programming languages:</p>
        
        <ul>
            <li><b>C Code</b> - Traditional procedural code analysis</li>
            <li><b>C++ Code</b> - Object-oriented features, templates, STL</li>
            <li><b>Objective-C Code</b> - Dynamic runtime, messaging, categories</li>
            <li><b>Mixed Language Binaries</b> - Detect and analyze multiple languages</li>
        </ul>
        
        <p><b>Key Features:</b></p>
        <ul>
            <li>Automatic language detection</li>
            <li>Language-specific decompilation</li>
            <li>Symbol demangling for C++ and Objective-C</li>
            <li>Objective-C runtime structure analysis</li>
            <li>C++ class hierarchy reconstruction</li>
            <li>Template instantiation detection</li>
            <li>Protocol and category analysis</li>
            <li>Multi-format save options</li>
        </ul>
        """)
        tabs.addTab(overview_tab, "Overview")
        
        # C/C++ tab
        cpp_tab = QTextEdit()
        cpp_tab.setReadOnly(True)
        cpp_tab.setHtml("""
        <h3>C/C++ Analysis Features</h3>
        
        <ul>
            <li><b>Class Reconstruction</b> - Extract class hierarchies and relationships</li>
            <li><b>Virtual Table Analysis</b> - Identify virtual functions and inheritance</li>
            <li><b>Template Detection</b> - Find template instantiations</li>
            <li><b>STL Recognition</b> - Identify standard library usage</li>
            <li><b>Name Demangling</b> - Convert mangled names to readable form</li>
            <li><b>Exception Handling</b> - Detect C++ exception frames</li>
            <li><b>RTTI Analysis</b> - Extract runtime type information</li>
        </ul>
        
        <p><b>Output Formats:</b></p>
        <ul>
            <li>.cpp files with class definitions</li>
            <li>.h header files with declarations</li>
            <li>.txt exports for documentation</li>
        </ul>
        """)
        tabs.addTab(cpp_tab, "C/C++")
        
        # Objective-C tab
        objc_tab = QTextEdit()
        objc_tab.setReadOnly(True)
        objc_tab.setHtml("""
        <h3>Objective-C Analysis Features</h3>
        
        <ul>
            <li><b>Class Dumping</b> - Extract all class interfaces</li>
            <li><b>Method Extraction</b> - List all instance and class methods</li>
            <li><b>Protocol Analysis</b> - Identify adopted protocols</li>
            <li><b>Category Detection</b> - Find class categories and extensions</li>
            <li><b>Ivar Discovery</b> - Extract instance variables</li>
            <li><b>Selector References</b> - Map message selectors</li>
            <li><b>Property Detection</b> - Identify @property declarations</li>
        </ul>
        
        <p><b>Output Formats:</b></p>
        <ul>
            <li>.mm files with Objective-C++ syntax</li>
            <li>.h headers with @interface declarations</li>
            <li>Framework-style organization</li>
        </ul>
        """)
        tabs.addTab(objc_tab, "Objective-C")
        
        # Technical tab
        technical_tab = QTextEdit()
        technical_tab.setReadOnly(True)
        technical_tab.setHtml("""
        <h3>Technical Details</h3>
        
        <p><b>Supported Architectures:</b></p>
        <ul>
            <li>x86, x86_64</li>
            <li>ARM, ARM64</li>
            <li>PowerPC, PowerPC64</li>
            <li>Universal/Fat binaries</li>
        </ul>
        
        <p><b>File Types:</b></p>
        <ul>
            <li>MH_OBJECT (.o) - Object files</li>
            <li>MH_EXECUTE - Executables</li>
            <li>MH_DYLIB (.dylib) - Dynamic libraries</li>
            <li>MH_BUNDLE (.bundle) - Loadable bundles</li>
            <li>MH_KEXT_BUNDLE - Kernel extensions</li>
            <li>MH_DSYM (.dSYM) - Debug symbol files</li>
        </ul>
        
        <p><b>Analysis Depth:</b></p>
        <ul>
            <li>Static analysis of binary structures</li>
            <li>Symbol table parsing</li>
            <li>Section content extraction</li>
            <li>Load command interpretation</li>
            <li>String and pattern recognition</li>
        </ul>
        """)
        tabs.addTab(technical_tab, "Technical")
        
        layout.addWidget(tabs)
        
        # Copyright
        copyright_label = QLabel("© 2026 Qalrix. All rights reserved.")
        copyright_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(copyright_label)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        button_box.accepted.connect(self.accept)
        layout.addWidget(button_box)
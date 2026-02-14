import re
from typing import Dict, List, Any
import struct

class LanguageParser:
    def __init__(self):
        # Objective-C patterns
        self.objc_patterns = [
            (b'@interface', 'Objective-C Interface'),
            (b'@implementation', 'Objective-C Implementation'),
            (b'@protocol', 'Objective-C Protocol'),
            (b'@selector', 'Objective-C Selector'),
            (b'@encode', 'Objective-C Encoding'),
            (b'@synchronized', 'Objective-C Sync'),
            (b'@autoreleasepool', 'Objective-C Autorelease'),
            (b'objc_msgSend', 'Objective-C Messaging'),
            (b'objc_getClass', 'Objective-C Runtime'),
            (b'objc_allocateClassPair', 'Objective-C Runtime'),
            (b'NSObject', 'Foundation Class'),
            (b'NSString', 'Foundation String'),
            (b'NSArray', 'Foundation Array'),
            (b'NSDictionary', 'Foundation Dictionary'),
            (b'UIView', 'UIKit View'),
            (b'UIViewController', 'UIKit Controller'),
        ]
        
        # C++ patterns
        self.cpp_patterns = [
            (b'std::', 'STL'),
            (b'virtual', 'Virtual Function'),
            (b'class ', 'C++ Class'),
            (b'template<', 'Template'),
            (b'namespace', 'Namespace'),
            (b'operator', 'Operator Overload'),
            (b'new ', 'Dynamic Allocation'),
            (b'delete ', 'Dynamic Deallocation'),
            (b'public:', 'Access Specifier'),
            (b'private:', 'Access Specifier'),
            (b'protected:', 'Access Specifier'),
            (b'friend ', 'Friend Function'),
            (b'static_cast', 'C++ Cast'),
            (b'dynamic_cast', 'C++ Cast'),
            (b'reinterpret_cast', 'C++ Cast'),
            (b'const_cast', 'C++ Cast'),
            (b'explicit', 'Explicit Constructor'),
            (b'throw(', 'Exception Specification'),
            (b'noexcept', 'No Exception'),
            (b'override', 'Override Specifier'),
            (b'final', 'Final Specifier'),
            (b'unique_ptr', 'Smart Pointer'),
            (b'shared_ptr', 'Smart Pointer'),
            (b'vector<', 'STL Vector'),
            (b'list<', 'STL List'),
            (b'map<', 'STL Map'),
            (b'string', 'STL String'),
        ]
        
        # C patterns
        self.c_patterns = [
            (b'#include', 'Include'),
            (b'#define', 'Macro'),
            (b'#ifdef', 'Conditional'),
            (b'struct ', 'Structure'),
            (b'union ', 'Union'),
            (b'enum ', 'Enumeration'),
            (b'typedef ', 'Type Definition'),
            (b'malloc(', 'Memory Allocation'),
            (b'calloc(', 'Memory Allocation'),
            (b'realloc(', 'Memory Allocation'),
            (b'free(', 'Memory Deallocation'),
            (b'printf(', 'Print Function'),
            (b'scanf(', 'Scan Function'),
            (b'fopen(', 'File Operation'),
            (b'fclose(', 'File Operation'),
            (b'fread(', 'File Operation'),
            (b'fwrite(', 'File Operation'),
            (b'FILE*', 'File Pointer'),
            (b'->', 'Pointer Access'),
            (b'main(', 'Main Function'),
        ]
        
        # Demangled name patterns for C++
        self.cpp_mangled_patterns = [
            r'_Z(T?N?K?[0-9]+)',
            r'_Z[0-9]+',
            r'_ZN[0-9]+',
            r'__Z[0-9]+',
        ]
        
        # Objective-C mangled patterns
        self.objc_mangled_patterns = [
            r'_OBJC_CLASS_',
            r'_OBJC_METACLASS_',
            r'_OBJC_IVAR_',
            r'_OBJC_SELECTOR_',
            r'_OBJC_PROTOCOL_',
            r'_objc_msgSend',
            r'\.[cC]ategory',
        ]
        
    def detect_languages(self, macho_data: Dict[str, Any]) -> List[str]:
        """Detect which languages are used in the binary"""
        languages = []
        scores = {'C': 0, 'C++': 0, 'Objective-C': 0}
        
        # Check symbols first (most reliable)
        if 'symbols' in macho_data:
            objc_score, cpp_score, c_score = self._analyze_symbols(macho_data['symbols'])
            scores['Objective-C'] += objc_score
            scores['C++'] += cpp_score
            scores['C'] += c_score
            
        # Check raw data for language patterns
        if 'raw_data' in macho_data:
            objc_score, cpp_score, c_score = self._analyze_raw_data(macho_data['raw_data'])
            scores['Objective-C'] += objc_score
            scores['C++'] += cpp_score
            scores['C'] += c_score
            
        # Check for Objective-C runtime sections
        if 'sections' in macho_data:
            if self._has_objc_sections(macho_data['sections']):
                scores['Objective-C'] += 50
                
        # Check for C++ ABI and exception handling
        if 'sections' in macho_data:
            if self._has_cpp_sections(macho_data['sections']):
                scores['C++'] += 30
                
        # Determine languages based on scores
        threshold = 10
        for lang, score in scores.items():
            if score >= threshold:
                languages.append(lang)
                
        # If no language detected, default to C
        if not languages:
            languages.append('C')
            
        return languages
    
    def _analyze_symbols(self, symbols: List[Dict]) -> tuple:
        """Analyze symbols to detect languages"""
        objc_score = 0
        cpp_score = 0
        c_score = 0
        
        for symbol in symbols:
            name = symbol.get('name', '')
            demangled = symbol.get('demangled', '')
            
            # Check Objective-C patterns
            if any(pattern in name for pattern in ['.c', '_OBJC_', '_objc_', '@']):
                objc_score += 5
            elif any(re.search(p, name) for p in self.objc_mangled_patterns):
                objc_score += 10
                
            # Check C++ patterns
            if any(re.search(p, name) for p in self.cpp_mangled_patterns):
                cpp_score += 10
            if 'std::' in demangled or 'operator' in demangled:
                cpp_score += 5
            if 'virtual' in demangled or 'class' in demangled:
                cpp_score += 5
                
            # Check C patterns
            if '_' in name and not any(p in name for p in ['std', 'objc', 'OBJC']):
                if name.islower() and len(name) > 3:
                    c_score += 1
                    
        return objc_score, cpp_score, c_score
    
    def _analyze_raw_data(self, data: bytes) -> tuple:
        """Analyze raw binary data for language patterns"""
        objc_score = 0
        cpp_score = 0
        c_score = 0
        
        # Check Objective-C patterns
        for pattern, _ in self.objc_patterns:
            if data.find(pattern) != -1:
                objc_score += 10
                
        # Check C++ patterns
        for pattern, _ in self.cpp_patterns:
            if data.find(pattern) != -1:
                cpp_score += 8
                
        # Check C patterns
        for pattern, _ in self.c_patterns:
            if data.find(pattern) != -1:
                c_score += 6
                
        return objc_score, cpp_score, c_score
    
    def _has_objc_sections(self, sections: List[Dict]) -> bool:
        """Check for Objective-C specific sections"""
        objc_sections = [
            '__objc_classlist',
            '__objc_protolist',
            '__objc_catlist',
            '__objc_imageinfo',
            '__objc_const',
            '__objc_selrefs',
            '__objc_classrefs',
            '__objc_superrefs',
            '__objc_ivar',
            '__objc_data',
        ]
        
        for segment in sections:
            for section in segment.get('sections', []):
                if section.get('name') in objc_sections:
                    return True
        return False
    
    def _has_cpp_sections(self, sections: List[Dict]) -> bool:
        """Check for C++ specific sections"""
        cpp_sections = [
            '__gcc_except_tab',
            '__eh_frame',
            '__extab',
            '__ZSt',
            '__ZN',
        ]
        
        for segment in sections:
            for section in segment.get('sections', []):
                name = section.get('name', '')
                for cpp_section in cpp_sections:
                    if cpp_section in name:
                        return True
        return False
    
    def extract_objc_classes(self, macho_data: Dict[str, Any]) -> List[Dict]:
        """Extract Objective-C class information"""
        classes = []
        
        if 'raw_data' not in macho_data:
            return classes
            
        data = macho_data['raw_data']
        
        # Look for Objective-C class definitions
        class_patterns = [
            b'@interface',
            b'@implementation',
            b'_OBJC_CLASS_',
        ]
        
        for pattern in class_patterns:
            offset = 0
            while True:
                offset = data.find(pattern, offset)
                if offset == -1:
                    break
                    
                # Extract class name
                end = data.find(b'\n', offset)
                if end == -1:
                    end = min(offset + 100, len(data))
                    
                line = data[offset:end].decode('utf-8', errors='ignore')
                
                # Parse class name
                if '@interface' in line or '@implementation' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        class_name = parts[1].strip(':')
                        classes.append({
                            'name': class_name,
                            'offset': hex(offset),
                            'type': 'class',
                            'inheritance': self._parse_inheritance(line),
                            'protocols': self._parse_protocols(line)
                        })
                        
                offset += 1
                
        return classes
    
    def extract_objc_methods(self, macho_data: Dict[str, Any]) -> List[Dict]:
        """Extract Objective-C method information"""
        methods = []
        
        if 'raw_data' not in macho_data:
            return methods
            
        data = macho_data['raw_data']
        
        # Method patterns
        method_patterns = [
            (b'- (', 'instance'),
            (b'+ (', 'class'),
            (b'objc_msgSend', 'message'),
        ]
        
        for pattern, method_type in method_patterns:
            offset = 0
            while True:
                offset = data.find(pattern, offset)
                if offset == -1:
                    break
                    
                # Extract method signature
                end = data.find(b'\n', offset)
                if end == -1:
                    end = min(offset + 100, len(data))
                    
                signature = data[offset:end].decode('utf-8', errors='ignore')
                
                methods.append({
                    'signature': signature.strip(),
                    'type': method_type,
                    'offset': hex(offset)
                })
                
                offset += 1
                
        return methods
    
    def extract_objc_protocols(self, macho_data: Dict[str, Any]) -> List[Dict]:
        """Extract Objective-C protocol information"""
        protocols = []
        
        if 'raw_data' not in macho_data:
            return protocols
            
        data = macho_data['raw_data']
        
        offset = 0
        while True:
            offset = data.find(b'@protocol', offset)
            if offset == -1:
                break
                
            end = data.find(b'\n', offset)
            if end == -1:
                end = min(offset + 100, len(data))
                
            line = data[offset:end].decode('utf-8', errors='ignore')
            parts = line.split()
            
            if len(parts) >= 2:
                protocol_name = parts[1].strip()
                protocols.append({
                    'name': protocol_name,
                    'offset': hex(offset),
                    'methods': self._extract_protocol_methods(data, offset)
                })
                
            offset += 1
            
        return protocols
    
    def extract_cpp_classes(self, macho_data: Dict[str, Any]) -> Dict:
        """Extract C++ class information"""
        classes = {}
        
        if 'symbols' not in macho_data:
            return classes
            
        for symbol in macho_data['symbols']:
            name = symbol.get('demangled', symbol.get('name', ''))
            
            # Look for class definitions in demangled names
            if '::' in name and '(' not in name:
                # This is a class or method
                parts = name.split('::')
                if len(parts) >= 2:
                    class_name = parts[0]
                    if class_name not in classes:
                        classes[class_name] = {
                            'methods': set(),
                            'inheritance': None,
                            'is_template': False
                        }
                    
                    # Check if it's a method
                    if '(' in name:
                        method_name = name.split('(')[0].split('::')[-1]
                        classes[class_name]['methods'].add(method_name)
                        
                    # Check for inheritance
                    if ':' in name and 'public' in name:
                        classes[class_name]['inheritance'] = name.split(':')[-1].strip()
                        
                    # Check for templates
                    if '<' in name and '>' in name:
                        classes[class_name]['is_template'] = True
                        
        # Convert sets to lists
        for class_name in classes:
            classes[class_name]['methods'] = list(classes[class_name]['methods'])
            classes[class_name]['method_count'] = len(classes[class_name]['methods'])
            
        return classes
    
    def extract_cpp_templates(self, macho_data: Dict[str, Any]) -> List[str]:
        """Extract C++ template instantiations"""
        templates = set()
        
        if 'symbols' not in macho_data:
            return []
            
        for symbol in macho_data['symbols']:
            name = symbol.get('demangled', symbol.get('name', ''))
            
            # Look for template patterns
            if '<' in name and '>' in name:
                # Extract template name
                template_part = name.split('<')[0].split('::')[-1]
                templates.add(f"{template_part}<...>")
                
        return list(templates)[:50]  # Limit to 50 templates
    
    def _parse_inheritance(self, line: str) -> str:
        """Parse inheritance from Objective-C interface"""
        if ':' in line and '@interface' in line:
            parts = line.split(':')
            if len(parts) >= 2:
                return parts[1].strip().split()[0]
        return 'NSObject'
    
    def _parse_protocols(self, line: str) -> List[str]:
        """Parse protocols from Objective-C interface"""
        protocols = []
        if '<' in line and '>' in line:
            start = line.find('<')
            end = line.find('>')
            if start != -1 and end != -1:
                protocol_str = line[start + 1:end]
                protocols = [p.strip() for p in protocol_str.split(',')]
        return protocols
    
    def _extract_protocol_methods(self, data: bytes, start_offset: int) -> List[str]:
        """Extract methods from a protocol definition"""
        methods = []
        
        # Look for methods until the @end
        offset = start_offset
        while offset < len(data):
            offset = data.find(b'\n', offset)
            if offset == -1:
                break
                
            offset += 1
            line_start = offset
            
            # Check for method patterns
            if data[offset:offset+2] in (b'- ', b'+ '):
                end = data.find(b'\n', offset)
                if end != -1:
                    method = data[offset:end].decode('utf-8', errors='ignore').strip()
                    methods.append(method)
                    
            # End of protocol
            if data[offset:offset+5] == b'@end':
                break
                
        return methods
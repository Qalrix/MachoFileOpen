import struct
from typing import Dict, List, Any

class ObjCRuntimeAnalyzer:
    """Analyze Objective-C runtime structures in Mach-O files"""
    
    def __init__(self):
        self.objc_section_names = [
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
            '__objc_message_refs',
            '__objc_class_names',
            '__objc_methname',
            '__objc_methtype'
        ]
        
    def analyze(self, macho_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract Objective-C runtime information"""
        result = {
            'classes': [],
            'categories': [],
            'protocols': [],
            'methods': [],
            'ivars': [],
            'selectors': []
        }
        
        if 'raw_data' not in macho_data:
            return result
            
        data = macho_data['raw_data']
        
        # Find Objective-C sections
        objc_sections = self._find_objc_sections(macho_data)
        
        # Parse class list
        if '__objc_classlist' in objc_sections:
            classes = self._parse_class_list(data, objc_sections['__objc_classlist'])
            result['classes'].extend(classes)
            
        # Parse protocol list
        if '__objc_protolist' in objc_sections:
            protocols = self._parse_protocol_list(data, objc_sections['__objc_protolist'])
            result['protocols'].extend(protocols)
            
        # Parse category list
        if '__objc_catlist' in objc_sections:
            categories = self._parse_category_list(data, objc_sections['__objc_catlist'])
            result['categories'].extend(categories)
            
        # Extract selectors
        if '__objc_selrefs' in objc_sections:
            selectors = self._parse_selector_refs(data, objc_sections['__objc_selrefs'])
            result['selectors'].extend(selectors)
            
        # Extract methods from class data
        for cls in result['classes']:
            methods = self._extract_class_methods(data, cls)
            result['methods'].extend(methods)
            
        return result
    
    def _find_objc_sections(self, macho_data: Dict[str, Any]) -> Dict[str, int]:
        """Find Objective-C sections and their offsets"""
        objc_sections = {}
        
        if 'sections' not in macho_data:
            return objc_sections
            
        for segment in macho_data['sections']:
            for section in segment.get('sections', []):
                name = section.get('name', '')
                if name in self.objc_section_names:
                    try:
                        offset = int(section.get('offset', '0x0'), 16)
                        objc_sections[name] = offset
                    except:
                        pass
                        
        return objc_sections
    
    def _parse_class_list(self, data: bytes, offset: int) -> List[Dict]:
        """Parse Objective-C class list"""
        classes = []
        
        # This is a simplified implementation
        # Actual class parsing would be much more complex
        
        # Look for class references in the data
        class_patterns = [b'_OBJC_CLASS_$_', b'_OBJC_METACLASS_$_']
        
        for pattern in class_patterns:
            pos = 0
            while True:
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                    
                # Find class name
                name_start = pos + len(pattern)
                name_end = data.find(b'\x00', name_start)
                
                if name_end != -1:
                    class_name = data[name_start:name_end].decode('utf-8', errors='ignore')
                    classes.append({
                        'name': class_name,
                        'offset': hex(pos),
                        'type': 'class' if b'CLASS' in pattern else 'metaclass'
                    })
                    
                pos += 1
                
        return classes
    
    def _parse_protocol_list(self, data: bytes, offset: int) -> List[Dict]:
        """Parse Objective-C protocol list"""
        protocols = []
        
        pattern = b'_OBJC_PROTOCOL_$_'
        pos = 0
        
        while True:
            pos = data.find(pattern, pos)
            if pos == -1:
                break
                
            name_start = pos + len(pattern)
            name_end = data.find(b'\x00', name_start)
            
            if name_end != -1:
                protocol_name = data[name_start:name_end].decode('utf-8', errors='ignore')
                protocols.append({
                    'name': protocol_name,
                    'offset': hex(pos)
                })
                
            pos += 1
            
        return protocols
    
    def _parse_category_list(self, data: bytes, offset: int) -> List[Dict]:
        """Parse Objective-C category list"""
        categories = []
        
        pattern = b'_OBJC_CATEGORY_$_'
        pos = 0
        
        while True:
            pos = data.find(pattern, pos)
            if pos == -1:
                break
                
            name_start = pos + len(pattern)
            name_end = data.find(b'\x00', name_start)
            
            if name_end != -1:
                category_info = data[name_start:name_end].decode('utf-8', errors='ignore')
                if '.' in category_info:
                    class_name, category_name = category_info.split('.', 1)
                    categories.append({
                        'class': class_name,
                        'name': category_name,
                        'offset': hex(pos)
                    })
                    
            pos += 1
            
        return categories
    
    def _parse_selector_refs(self, data: bytes, offset: int) -> List[str]:
        """Parse Objective-C selector references"""
        selectors = []
        
        # Look for selector strings
        pos = offset
        while pos < len(data):
            # Try to read a pointer (8 bytes for 64-bit)
            if pos + 8 > len(data):
                break
                
            # This is simplified - actual selector references are indirect
            selector_offset = struct.unpack('<Q', data[pos:pos+8])[0]
            
            # Look for selector string
            if selector_offset < len(data):
                sel_name = self._read_selector_string(data, selector_offset)
                if sel_name:
                    selectors.append(sel_name)
                    
            pos += 8
            
        return selectors
    
    def _extract_class_methods(self, data: bytes, cls: Dict) -> List[Dict]:
        """Extract methods from a class"""
        methods = []
        
        # Look for method lists in class data
        # This is a simplified implementation
        
        class_name = cls.get('name', '')
        
        # Look for method patterns in the class's memory region
        method_patterns = [
            b'-[' + class_name.encode() + b' ',
            b'+[' + class_name.encode() + b' '
        ]
        
        for pattern in method_patterns:
            pos = 0
            while True:
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                    
                # Find method name
                name_start = pos + len(pattern)
                name_end = data.find(b']', name_start)
                
                if name_end != -1:
                    method_name = data[name_start:name_end].decode('utf-8', errors='ignore')
                    methods.append({
                        'class': class_name,
                        'name': method_name,
                        'type': 'instance' if pattern[0] == ord('-') else 'class',
                        'offset': hex(pos)
                    })
                    
                pos += 1
                
        return methods
    
    def _read_selector_string(self, data: bytes, offset: int) -> str:
        """Read a selector string from data"""
        if offset >= len(data):
            return ""
            
        end = offset
        while end < len(data) and data[end] != 0:
            end += 1
            
        if end > offset:
            try:
                return data[offset:end].decode('utf-8', errors='ignore')
            except:
                pass
                
        return ""
import struct
import hashlib
import re
from typing import Dict, List, Any

class MachOParser:
    def __init__(self):
        self.magic_numbers = {
            0xfeedface: 'MH_MAGIC',
            0xfeedfacf: 'MH_MAGIC_64',
            0xcafebabe: 'FAT_MAGIC',
            0xcafebabf: 'FAT_MAGIC_64'
        }
        
        self.file_types = {
            0x1: 'MH_OBJECT',
            0x2: 'MH_EXECUTE',
            0x3: 'MH_FVMLIB',
            0x4: 'MH_CORE',
            0x5: 'MH_PRELOAD',
            0x6: 'MH_DYLIB',
            0x7: 'MH_DYLINKER',
            0x8: 'MH_BUNDLE',
            0x9: 'MH_DYLIB_STUB',
            0xa: 'MH_DSYM',
            0xb: 'MH_KEXT_BUNDLE'
        }
        
    def parse(self, file_path: str) -> Dict[str, Any]:
        """Parse Mach-O file and extract information"""
        result = {
            'file_path': file_path,
            'file_type': 'Unknown',
            'architectures': [],
            'symbols': [],
            'strings': [],
            'signatures': [],
            'sections': [],
            'imports': [],
            'exports': [],
            'raw_data': None,
            'hashes': {}
        }
        
        with open(file_path, 'rb') as f:
            data = f.read()
            result['raw_data'] = data
            
            # Calculate hashes
            result['hashes']['md5'] = hashlib.md5(data).hexdigest()
            result['hashes']['sha1'] = hashlib.sha1(data).hexdigest()
            result['hashes']['sha256'] = hashlib.sha256(data).hexdigest()
            
            # Check magic number
            if len(data) >= 4:
                magic = struct.unpack('<I', data[:4])[0]
                result['magic'] = self.magic_numbers.get(magic, f'Unknown (0x{magic:x})')
                
                if magic in [0xfeedface, 0xfeedfacf]:
                    self._parse_mach_o(data, result)
                elif magic in [0xcafebabe, 0xcafebabf]:
                    self._parse_fat_binary(data, result)
                    
            # Extract strings
            result['strings'] = self._extract_strings(data)
            
            # Extract signatures
            result['signatures'] = self._extract_signatures(data)
            
            # Try to find original C++ code references
            result['original_cpp'] = self._extract_cpp_references(data)
            
        return result
    
    def _parse_mach_o(self, data: bytes, result: Dict[str, Any]):
        """Parse Mach-O header and load commands"""
        is_64 = struct.unpack('<I', data[:4])[0] == 0xfeedfacf
        
        # Parse header
        if is_64:
            header_format = '<IIIIII'
            header_size = 32
        else:
            header_format = '<IIIIII'
            header_size = 28
            
        header = struct.unpack(header_format, data[:header_size])
        cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags = header
        
        result['file_type'] = self.file_types.get(file_type, f'Unknown (0x{file_type:x})')
        result['cpu_type'] = self._get_cpu_type(cpu_type)
        result['flags'] = self._parse_flags(flags)
        
        # Parse load commands
        offset = header_size
        for _ in range(ncmds):
            if offset + 8 > len(data):
                break
                
            cmd, cmdsize = struct.unpack('<II', data[offset:offset+8])
            
            if cmd == 0x1:  # LC_SEGMENT/LC_SEGMENT_64
                self._parse_segment_command(data, offset, cmdsize, is_64, result)
            elif cmd == 0x2:  # LC_SYMTAB
                self._parse_symtab_command(data, offset, result)
            elif cmd == 0x18:  # LC_LOAD_DYLIB
                self._parse_dylib_command(data, offset, result)
            elif cmd == 0x1e:  # LC_CODE_SIGNATURE
                self._parse_code_signature(data, offset, result)
                
            offset += cmdsize
            
    def _parse_fat_binary(self, data: bytes, result: Dict[str, Any]):
        """Parse fat binary header"""
        result['file_type'] = 'FAT_BINARY'
        magic = struct.unpack('<I', data[:4])[0]
        is_64 = magic == 0xcafebabf
        
        nfat_arch = struct.unpack('>I' if magic == 0xcafebabe else '<I', data[4:8])[0]
        
        arch_offset = 8
        arch_size = 20 if not is_64 else 32
        
        for i in range(nfat_arch):
            if arch_offset + arch_size > len(data):
                break
                
            if not is_64:
                cpu_type, cpu_subtype, offset, size, align = struct.unpack('>IIIII', 
                    data[arch_offset:arch_offset+20])
            else:
                cpu_type, cpu_subtype, offset, size, align, reserved = struct.unpack('<IIQQQI',
                    data[arch_offset:arch_offset+32])
                    
            arch_info = {
                'cpu_type': self._get_cpu_type(cpu_type),
                'offset': offset,
                'size': size
            }
            result['architectures'].append(arch_info)
            arch_offset += arch_size
            
    def _parse_segment_command(self, data: bytes, offset: int, cmdsize: int, is_64: bool, result: Dict[str, Any]):
        """Parse segment command"""
        if is_64:
            segname = data[offset+8:offset+24].decode('utf-8', errors='ignore').strip('\x00')
            vmaddr, vmsize, fileoff, filesize = struct.unpack('<QQQQ', data[offset+24:offset+56])
            maxprot, initprot, nsects, flags = struct.unpack('<IIII', data[offset+56:offset+72])
            section_offset = offset + 72
            section_size = 80
        else:
            segname = data[offset+8:offset+24].decode('utf-8', errors='ignore').strip('\x00')
            vmaddr, vmsize, fileoff, filesize = struct.unpack('<IIII', data[offset+24:offset+40])
            maxprot, initprot, nsects, flags = struct.unpack('<IIII', data[offset+40:offset+56])
            section_offset = offset + 56
            section_size = 68
            
        segment_info = {
            'name': segname,
            'vmaddr': hex(vmaddr),
            'vmsize': hex(vmsize),
            'fileoff': hex(fileoff),
            'filesize': hex(filesize),
            'sections': []
        }
        
        # Parse sections
        for _ in range(nsects):
            if is_64:
                sectname = data[section_offset:section_offset+16].decode('utf-8', errors='ignore').strip('\x00')
                segname = data[section_offset+16:section_offset+32].decode('utf-8', errors='ignore').strip('\x00')
                addr, size = struct.unpack('<QQ', data[section_offset+32:section_offset+48])
                offset_val, align, reloff, nreloc, flags = struct.unpack('<IIIII', data[section_offset+48:section_offset+68])
                reserved1, reserved2, reserved3 = struct.unpack('<III', data[section_offset+68:section_offset+80])
                section_offset += 80
            else:
                sectname = data[section_offset:section_offset+16].decode('utf-8', errors='ignore').strip('\x00')
                segname = data[section_offset+16:section_offset+32].decode('utf-8', errors='ignore').strip('\x00')
                addr, size = struct.unpack('<II', data[section_offset+32:section_offset+40])
                offset_val, align, reloff, nreloc, flags = struct.unpack('<IIIII', data[section_offset+40:section_offset+60])
                reserved1, reserved2 = struct.unpack('<II', data[section_offset+60:section_offset+68])
                section_offset += 68
                
            section_info = {
                'name': sectname,
                'segment': segname,
                'address': hex(addr),
                'size': hex(size),
                'offset': hex(offset_val)
            }
            segment_info['sections'].append(section_info)
            
        result['sections'].append(segment_info)
        
    def _parse_symtab_command(self, data: bytes, offset: int, result: Dict[str, Any]):
        """Parse symbol table command"""
        symoff, nsyms, stroff, strsize = struct.unpack('<IIII', data[offset+8:offset+24])
        
        # Parse symbols
        symbol_size = 16  # nlist_64 is 16 bytes
        for i in range(nsyms):
            sym_offset = symoff + (i * symbol_size)
            if sym_offset + symbol_size > len(data):
                break
                
            n_strx, n_type, n_sect, n_desc, n_value = struct.unpack('<IBBBI', 
                data[sym_offset:sym_offset+12])
                
            # Get symbol name from string table
            if n_strx > 0 and n_strx < strsize:
                str_offset = stroff + n_strx
                name = self._read_c_string(data, str_offset)
            else:
                name = f"symbol_{i}"
                
            symbol_info = {
                'name': name,
                'type': self._get_symbol_type(n_type),
                'section': n_sect,
                'value': hex(n_value)
            }
            result['symbols'].append(symbol_info)
            
    def _parse_dylib_command(self, data: bytes, offset: int, result: Dict[str, Any]):
        """Parse dylib load command"""
        name_offset = offset + struct.calcsize('<IIII')
        name = self._read_c_string(data, name_offset)
        result['imports'].append(name)
        
    def _parse_code_signature(self, data: bytes, offset: int, result: Dict[str, Any]):
        """Parse code signature command"""
        dataoff, datasize = struct.unpack('<II', data[offset+8:offset+16])
        result['signatures'].append({
            'offset': hex(dataoff),
            'size': hex(datasize)
        })
        
    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[Dict[str, Any]]:
        """Extract ASCII strings from binary data"""
        strings = []
        current_string = ""
        
        for i, byte in enumerate(data):
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append({
                        'offset': hex(i - len(current_string)),
                        'string': current_string
                    })
                current_string = ""
                
        return strings
    
    def _extract_signatures(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract signatures and patterns"""
        signatures = []
        
        # Look for common signature patterns
        patterns = [
            (b'\x7fELF', 'ELF'),
            (b'MZ', 'PE'),
            (b'!<arch>\n', 'Archive'),
            (b'\xCA\xFE\xBA\xBE', 'Mach-O FAT'),
            (b'\xFE\xED\xFA\xCE', 'Mach-O 32-bit'),
            (b'\xFE\xED\xFA\xCF', 'Mach-O 64-bit'),
            (b'\xCE\xFA\xED\xFE', 'Mach-O 32-bit (reverse)'),
            (b'\xCF\xFA\xED\xFE', 'Mach-O 64-bit (reverse)')
        ]
        
        for pattern, name in patterns:
            offset = data.find(pattern)
            if offset != -1:
                signatures.append({
                    'name': name,
                    'offset': hex(offset),
                    'pattern': pattern.hex()
                })
                
        return signatures
    
    def _extract_cpp_references(self, data: bytes) -> str:
        """Try to extract C++ code references"""
        cpp_patterns = [
            b'class',
            b'public:',
            b'private:',
            b'protected:',
            b'virtual',
            b'std::',
            b'namespace',
            b'template',
            b'operator',
            b'new',
            b'delete'
        ]
        
        found_lines = []
        data_str = data.decode('utf-8', errors='ignore')
        lines = data_str.split('\n')
        
        for line in lines:
            for pattern in cpp_patterns:
                if pattern.decode() in line.lower():
                    found_lines.append(line)
                    break
                    
        if found_lines:
            return '\n'.join(found_lines[:100])  # Limit to 100 lines
        return "No original C++ code references found"
    
    def _read_c_string(self, data: bytes, offset: int) -> str:
        """Read null-terminated string from data"""
        end = offset
        while end < len(data) and data[end] != 0:
            end += 1
        return data[offset:end].decode('utf-8', errors='ignore')
    
    def _get_cpu_type(self, cpu_type: int) -> str:
        """Get CPU type string"""
        cpu_types = {
            0x7: 'x86',
            0x7fffffff: 'x86_64',
            0xc: 'ARM',
            0x100000c: 'ARM64',
            0xa: 'PowerPC',
            0x100000a: 'PowerPC64'
        }
        return cpu_types.get(cpu_type, f'Unknown (0x{cpu_type:x})')
    
    def _parse_flags(self, flags: int) -> List[str]:
        """Parse Mach-O flags"""
        flag_names = []
        flag_map = {
            0x1: 'MH_NOUNDEFS',
            0x2: 'MH_INCRLINK',
            0x4: 'MH_DYLDLINK',
            0x8: 'MH_BINDATLOAD',
            0x10: 'MH_PREBOUND',
            0x20: 'MH_SPLIT_SEGS',
            0x40: 'MH_LAZY_INIT',
            0x80: 'MH_TWOLEVEL',
            0x100: 'MH_FORCE_FLAT',
            0x200: 'MH_NOMULTIDEFS',
            0x400: 'MH_NOFIXPREBINDING',
            0x800: 'MH_PREBINDABLE',
            0x1000: 'MH_ALLMODSBOUND',
            0x2000: 'MH_SUBSECTIONS_VIA_SYMBOLS',
            0x4000: 'MH_CANONICAL',
            0x8000: 'MH_WEAK_DEFINES',
            0x10000: 'MH_BINDS_TO_WEAK',
            0x20000: 'MH_ALLOW_STACK_EXECUTION',
            0x40000: 'MH_ROOT_SAFE',
            0x80000: 'MH_SETUID_SAFE',
            0x100000: 'MH_NO_REEXPORTED_DYLIBS',
            0x200000: 'MH_PIE',
            0x400000: 'MH_DEAD_STRIPPABLE_DYLIB',
            0x800000: 'MH_HAS_TLV_DESCRIPTORS',
            0x1000000: 'MH_NO_HEAP_EXECUTION',
            0x2000000: 'MH_APP_EXTENSION_SAFE'
        }
        
        for flag_bit, flag_name in flag_map.items():
            if flags & flag_bit:
                flag_names.append(flag_name)
                
        return flag_names
    
    def _get_symbol_type(self, n_type: int) -> str:
        """Get symbol type string"""
        type_map = {
            0x0: 'N_UNDF',
            0x1: 'N_ABS',
            0x2: 'N_SECT',
            0x3: 'N_PBUD',
            0x4: 'N_INDR',
            0xe: 'N_SETA',
            0xf: 'N_SETB'
        }
        return type_map.get(n_type & 0xf, f'Unknown (0x{n_type:x})')
    
    def demangleSymbols(self, symbols: List[Dict]) -> List[Dict]:
        """Demangle C++ symbols"""
        import cxxfilt
        
        demangled = []
        for symbol in symbols:
            demangled_symbol = symbol.copy()
            try:
                demangled_name = cxxfilt.demangle(symbol['name'])
                demangled_symbol['demangled'] = demangled_name
            except:
                demangled_symbol['demangled'] = symbol['name']
            demangled.append(demangled_symbol)
            
        return demangled
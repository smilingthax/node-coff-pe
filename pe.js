
var fs = require('fs');

function parseDosHeader(buf) {
  // assert(buf.length>=0x40); // 64
  // (NOTE: for best compatibility, hdrsize*16 shall be multiple of 512 [but not in pe...?])
  return {
    lastsize: buf.readUInt16LE(2, true),  // bytes_used_in_last_block; 0 means 512!
    nblocks: buf.readUInt16LE(4, true),   // blocks_in_file (block = 512 bytes)
    nreloc: buf.readUInt16LE(6, true),
    hdrsize: buf.readUInt16LE(8, true),   // header_paragraphs (paragraph = 16 bytes)
    minalloc: buf.readUInt16LE(10, true), // min_extra_paragraphs
    maxalloc: buf.readUInt16LE(12, true), // max_extra_paragraphs
    ss: buf.readUInt16LE(14, true),
    sp: buf.readUInt16LE(16, true),
    checksum: buf.readUInt16LE(18, true), // (usually just 0)
    ip: buf.readUInt16LE(20, true),
    cs: buf.readUInt16LE(22, true),
    relocpos: buf.readUInt16LE(24, true), // reloc_table_offset
    noverlay: buf.readUInt16LE(26, true), // overlay_number (main program: 0)

    // PE, etc ...:  (if relocpos >= 0x40)
    reserved1: buf.slice(28, 28+8),
    oem_id: buf.readUInt16LE(36, true),
    oem_info: buf.readUInt16LE(38, true),
    reserved2: buf.slice(40, 40+20),
    e_lfanew: buf.readUInt32LE(60, true) // 0 = just exe (?)
  };
}

// cb(err, exehdr)
function readExe(fd, cb) {
  var buffer = new Buffer(0x40); // expect pe...
  fs.read(fd, buffer, 0, 0x40, 0, function(err, bytesRead, buf) {
    if (err) {
      cb(err);
    } else if (bytesRead < 0x40) {
      cb(new Error('File too short'));
    } else if ( (buf[0]!==0x4d)||(buf[1]!==0x5a) ) { // MZ
      cb(new Error('Not an EXE file'));
    } else if ( (buf[24]<0x40)&&(buf[25]===0x00) ) {
      cb(new Error('Not a PE file'));  // TODO?
    } else {
      var exehdr = parseDosHeader(buf);
      var extraStart = exehdr.nblocks * 512;
      if (exehdr.lastsize) {
        extraStart += exehdr.lastsize - 512;
      }
      exehdr._fileOffsets = {
        start: 0,
        relocStart: exehdr.relocpos, // (e.g.) PE-part of header is between 0x1c and this value
        // relocEnd: exehdr.relocpos + 4*exehdr.nreloc, // (==dataStart...(?))
        dataStart: exehdr.hdrsize * 16, // reloc is part of hdr!
        extraStart: extraStart // "after exe data"  // (?? TODO? +dataStart???)
      };
      cb(null, exehdr);
    }
  });
}

function parseSectionHeader(buf, offset) {
  // assert(buf.length>=offset+0x28); // 40
  return {
    Name: buf.slice(offset, offset+8), //  .toString(),     // TODO/FIXME:   if "/4" -> @217905 (0x35331)  -? string table ?  (but executables dont have one -> long names not supported...? [mingw does generate them...])
    PhysicalAddress_VirtualSize: buf.readUInt32LE(offset+8, true), // VirtualSize.
    VirtualAddress: buf.readUInt32LE(offset+12, true),
    SizeOfRawData: buf.readUInt32LE(offset+16, true),
    PointerToRawData: buf.readUInt32LE(offset+20, true),

    // or: Reserved(12 bytes)
    PointerToRelocations: buf.readUInt32LE(offset+24, true),
    PointerToLinenumbers: buf.readUInt32LE(offset+28, true),
    NumberOfRelocations: buf.readUInt16LE(offset+32, true),
    NumberOfLinenumbers: buf.readUInt16LE(offset+34, true),

    Characteristics: buf.readUInt32LE(offset+36, true) // Flags
  };
}

function parseCoffHeader(buf) {
  // assert(buf.length>=0x14); // 20
  return {
    Machine: buf.readUInt16LE(0, true),
    NumberOfSections: buf.readUInt16LE(2, true),
    TimeDateStamp: buf.readUInt32LE(4, true),
    PointerToSymbolTable: buf.readUInt32LE(8, true),
    NumberOfSymbols: buf.readUInt32LE(12, true),
    SizeOfOptionalHeader: buf.readUInt16LE(16, true),
    Characteristics: buf.readUInt16LE(18, true),
    Optional: null, // esp. PE Optional Header
    SectionHeaders: []
//    SymbolTable: null,
//    StringTable: null
  };
}

function cstring(buf) {
  var ret = buf.toString();
  var pos = ret.indexOf('\0');
  if (pos >= 0) {
    return ret.slice(0, pos);
  }
  return ret;
}

// cb(err)  - will modify coffhdr
function readSectionHeaders(fd, coffhdr, cb) {
  // assert(coffhdr);
  var buffer = new Buffer(0x28 * coffhdr.NumberOfSections);
  fs.read(fd, buffer, 0, buffer.length, coffhdr._fileOffsets.sectionStart, function(err, bytesRead, buf) {
    if (err) {
      cb(err);
    } else if (bytesRead < buf.length) {
      cb(new Error('File too short'));
    } else {
      coffhdr._sectionMap = {};
      for (var i=0, len=coffhdr.NumberOfSections; i<len; i++) {
        var secthdr = parseSectionHeader(buf, 0x28*i);
        secthdr._name = cstring(secthdr.Name);
        coffhdr.SectionHeaders[i] = secthdr;
        coffhdr._sectionMap[secthdr._name] = i;
      }
      cb(null);
    }
  });
}

function parseDataDirectoryEntry(buf, offset) {
  // assert(buf.length>=offset+0x08);
  return {
    VirtualAddress: buf.readUInt32LE(offset, true),
    Size: buf.readUInt32LE(offset+4, true)
  };
}

function parsePEOptHeader(buf, len) {
  // assert(buf.length>=len);
  if (len < 0x1c) { // 28
    return 'COFF Optional too short';
  }
  var coff = {
    // COFF Optional
    Signature: buf.readUInt16LE(0, true), // or: Magic
    MajorLinkerVersion: buf.readUInt8(2, true),
    MinorLinkerVersion: buf.readUInt8(3, true),
    SizeOfCode: buf.readUInt32LE(4, true),
    SizeOfInitializedData: buf.readUInt32LE(8, true),
    SizeOfUninitializedData: buf.readUInt32LE(12, true),
    AddressOfEntryPoint: buf.readUInt32LE(16, true), // !
    BaseOfCode: buf.readUInt32LE(20, true),
    BaseOfData: buf.readUInt32LE(24, true)
  };
  if ( (coff.Signature !== 0x10b)&&(coff.Signature !== 0x20b)&&
       (coff.Signature !== 0x107) ) { // TODO?
    if (len > 0x1c) {
      coff._more = buf.slice(28, len);
    }
    return coff;
  } else if (len < 0x60) { // 96
    return 'PE Header too short';
  }
  var pe = {
    ImageBase: buf.readUInt32LE(28, true),
    SectionAlignment: buf.readUInt32LE(32, true),
    FileAlignment: buf.readUInt32LE(36, true),
    MajorOSVersion: buf.readUInt16LE(40, true),
    MinorOSVersion: buf.readUInt16LE(42, true),
    MajorImageVersion: buf.readUInt16LE(44, true),
    MinorImageVersion: buf.readUInt16LE(46, true),
    MajorSubsystemVersion: buf.readUInt16LE(48, true),
    MinorSubsystemVersion: buf.readUInt16LE(50, true),
    Win32VersionValue: buf.readUInt32LE(52, true), // Reserved1
    SizeOfImage: buf.readUInt32LE(56, true),
    SizeOfHeaders: buf.readUInt32LE(60, true),
    Checksum: buf.readUInt32LE(64, true),
    Subsystem: buf.readUInt16LE(68, true),
    DLLCharacteristics: buf.readUInt16LE(70, true),
    SizeOfStackReserve: buf.readUInt32LE(72, true),
    SizeOfStackCommit: buf.readUInt32LE(76, true),
    SizeOfHeapReserve: buf.readUInt32LE(80, true),
    SizeOfHeapCommit: buf.readUInt32LE(84, true),
    LoaderFlags: buf.readUInt32LE(88, true),
    NumberOfRvaAndSizes: buf.readUInt32LE(92, true),
    DataDirectory: []
  };
  if (pe.Signature == 0x20b) { // PE32+
    if (len < 0x70) { // 112
      return 'PE32+ Header too short';
    }
    pe.ImageBase = [ret.ImageBase, ret.BaseOfData]; // no 64 bit type in nodejs...
    pe.BaseOfData = null;
    pe.SizeOfStackReserve = [ret.SizeOfStackCommit, ret.SizeOfStackReserve];
    pe.SizeOfStackCommit = [ret.SizeOfHeapCommit, ret.SizeOfHeapReserve];
    pe.SizeOfHeapReserve = [ret.NumberOfRvaAndSizes, ret.LoaderFlags];
    pe.SizeOfHeapCommit = [buf.readUInt32LE(100, true), buf.readUInt32LE(96, true)];
    pe.LoaderFlags = buf.readUInt32LE(104, true);
    pe.NumberOfRvaAndSizes = buf.readUInt32LE(108, true);
    if (len > 0x70 + 8*pe.NumberOfRvaAndSizes) {
      pe._more = buf.slice(112, len);
    }
  } else if (len > 0x60 + 8*pe.NumberOfRvaAndSizes) {
    pe._more = buf.slice(96, len);
  }
  for (var k in pe) {
    coff[k] = pe[k];
  }
  return coff;
}

// cb(err, exehdr, coffhdr)
function readCoffPE(fd, exehdr, cb) {
  if (exehdr.e_lfanew === 0) {
    cb(null, exehdr); // just exe
    return;
  } else if (exehdr.e_lfanew <= 0x40) {
    cb(new Error('Bad e_lfanew value'), exehdr);
    return;
  }
  var buffer = new Buffer(0x18 + 0x70 + 16*8);
  fs.read(fd, buffer, 0, 0x108, exehdr.e_lfanew, function(err, bytesRead, buf) {
    if (err) {
      cb(err, exehdr);
    } else if (bytesRead < 0x18) {
      cb(new Error('File too short'), exehdr);
    } else if ( (buf[0]!==0x50)||(buf[1]!==0x45)||(buf[2]!==0)||(buf[3]!==0) ) { // PE\0\0  (Signature)   // note: win16,os/2:  NE, LE
      cb(new Error('Not a (little-endian) PE file'), exehdr);
    } else {
      var coffhdr = parseCoffHeader(buf.slice(4));
      coffhdr._fileOffsets = {
        start: exehdr.e_lfanew,
        optionalStart: exehdr.e_lfanew + 0x18,
        sectionStart: exehdr.e_lfanew + 0x18 + coffhdr.SizeOfOptionalHeader,
        sectionEnd: exehdr.e_lfanew + 0x18 + coffhdr.SizeOfOptionalHeader + 0x28 * coffhdr.NumberOfSections,
        headerEnd: null,
        symbolStart: null,
        stringStart: null,
        stringEnd: null
      };
      if (coffhdr.PointerToSymbolTable) {
        coffhdr._fileOffsets.symbolStart = coffhdr.PointerToSymbolTable;
        coffhdr._fileOffsets.stringStart = coffhdr.PointerToSymbolTable + 0x12*coffhdr.NumberOfSymbols;
      }
      if (coffhdr.SizeOfOptionalHeader) {
        if (bytesRead < 0x18+coffhdr.SizeOfOptionalHeader) {
          cb(new Error('File too short'), exehdr, coffhdr);
          return;
        }
        var peopt = parsePEOptHeader(buf.slice(0x18), coffhdr.SizeOfOptionalHeader);
        if (typeof peopt === 'string') {
          // TODO? coffhdr.Optional = buf.slice(0x18, 0x18+coffhdr.SizeOfOptionalHeader);
          cb(new Error(peopt), exehdr, coffhdr);
          return;
        }
        coffhdr.Optional = peopt;
        coffhdr._fileOffsets.headerEnd = coffhdr.Optional.SizeOfHeaders; // not PE: undefined
        if (coffhdr.Optional.NumberOfRvaAndSizes>0) {
          for (var i=0, len=Math.min(coffhdr.Optional.NumberOfRvaAndSizes, 16); i<len; i++) {
            coffhdr.Optional.DataDirectory[i] = parseDataDirectoryEntry(buf, 0x78 + 8*i);
          }
          if (coffhdr.Optional.NumberOfRvaAndSizes > 16) {
            var buffer = new Buffer((coffhdr.Optional.NumberOfRvaAndSizes-16)*8);
            fs.read(fd, buffer, 0, buffer.length, exehdr.e_lfanew + 0xf8, function(err, bytesRead, buf) {
              if (err) {
                cb(err, exehdr, coffhdr);
              } else if (bytesRead < buf.length) {
                cb(new Error('File too short'), exehdr, coffhdr);
              } else {
                for (var i=16, len=coffhdr.Optional.NumberOfRvaAndSizes; i<len; i++) {
                  coffhdr.Optional.DataDirectory[i] = parseDataDirectoryEntry(buf, (i - 16)*8);
                }
                cb(null, exehdr, coffhdr);
              }
            });
            return;
          }
        }
      } else {
        coffhdr._fileOffsets.headerEnd = coffhdr._fileOffsets.sectionEnd; // TODO?
      }
      cb(null, exehdr, coffhdr);
    }
  });
}

function getSectionHeader(coffhdr, name) {
  if ( (coffhdr)&&(coffhdr.SectionHeaders)&&(coffhdr._sectionMap) ) {
    var idx = coffhdr._sectionMap[name];
    if (idx != null) {
      return coffhdr.SectionHeaders[idx];
    }
  }
  return null;
}

// cb(err, buf)
function readBlock(fd, offset, length, cb) {
  var buffer = new Buffer(length);
  fs.read(fd, buffer, 0, buffer.length, offset, function(err, bytesRead, buf) {
    if (err) {
      cb(err);
    } else if (bytesRead !== buf.length) {
      cb(new Error('Bad read length'));
    } else {
      cb(null, buf);
    }
  });
}

module.exports = {
  // cb(err, exehdr, coffhdr)
  read: function(fd, cb) {
    var dataname = this.PEDataDirectory;
    readExe(fd, function(err, exehdr) {
      if (err) {
        cb(err);
      } else {
        readCoffPE(fd, exehdr, function(err, exehdr, coffhdr) {
          if ( (err)||(!exehdr)||(!coffhdr) ) {
            cb(err, exehdr, coffhdr);
            return;
          }
          // prettify output
          if ( (coffhdr.Optional)&&(coffhdr.Optional.DataDirectory) ) {
            for (var i=0, len=coffhdr.Optional.DataDirectory.length; i<len; i++) {
              if (dataname[i]) {
                coffhdr.Optional.DataDirectory[i].name = dataname[i];
              }
            }
          }
          readSectionHeaders(fd, coffhdr, function(err) {
            cb(err, exehdr, coffhdr);
          });
        });
      }
    });
  },

  getSectionHeader: getSectionHeader, // (coffhdr, name) 

  // cb(err, data)  - data==null, if not found
  getSection: function(fd, coffhdr, name, cb) {
    var hdr = getSectionHeader(coffhdr, name);
    if (!hdr) {
      cb(null, null); // Section not found
      return;
    }
    readBlock(fd, hdr.PointerToRawData, Math.min(hdr.PhysicalAddress_VirtualSize, hdr.SizeOfRawData), cb); // TODO? [0 padded in real load...]
  },

  checksum: require('./pe-checksum.js'), // (fd, coffhdr, cb) w/ cb(err, checksum)

  CoffMachines: {
    0x014c: 'Intel 386',
    0x0162: 'MIPS R3000',
    0x0168: 'MIPS R10000',
    0x0169: 'MIPS little endian WCI v2',
    0x0183: 'old Alpha AXP',
    0x0184: 'Alpha AXP',
    0x01c0: 'ARM little endian',
    0x01c2: 'ARM thumb', // ?
    0x01f0: 'PowerPC little endian',
    0x01f1: 'PowerPC w/ FPU',
    0x0200: 'Intel IA64 (Itanium)',
    0x0266: 'MIPS16',
    0x0268: 'Motorola 68000',
    0x0284: 'Alpha AXP 64bit',
    0x0366: 'MIPS16 w/ FPU',
    0x0466: 'MIPS w/ FPU',
    0x0ebc: 'EFI Byte Code',
    0x8664: 'x64 / AMD64',
    0xc0ee: '.NET / CLR / MSIL'
  },
  CoffCharacteristics: {
    0x0001: 'Relocation info stripped',  // i.e. non-relocatable??
    0x0002: 'Executable file',
    0x0004: 'COFF line numbers stripped',
    0x0008: 'COFF symbol table stripped',
    0x0020: 'Large Address(>2 GB) aware',
    0x0100: '32-bit supported',
//    0x0200: 'non-relocatable',
    0x0200: 'Debug info stripped',
    0x0400: 'Run from swap instead of from removable',
    0x0800: 'Run from swap instead of from net',
    0x1000: 'System file',
    0x2000: 'DLL Library',
    0x4000: 'Uniprocessor only'
  },
  PESignatures: {
    0x10b: '32bit executable image',
    0x20b: '64bit executable image',
    0x107: 'ROM image'
  },
  PESubsystems: {
    0: 'Unknown',
    1: 'Native', // e.g. a driver
    2: 'Windows GUI',
    3: 'Windows CUI',
    5: 'OS/2 CUI',
    7: 'POSIX CUI',
    9: 'Windows CE',
    10: 'EFI Application',
    11: 'EFI Boot Service Driver',
    12: 'EFI Runtime Driver',
    13: 'EFI ROM Image',
    14: 'Xbox',
    16: 'Windows Boot Application'
  },
  // ? PEDllCharacteristics: {},
  PEDataDirectory: [
    'Export', 'Import', 'Resource', 'Exception',
    'Security', 'BaseReloc', 'Debug', 'Architecture / Description',
    'GlobalPtr / Special', 'Tls', 'Load_Config', 'Bound_Import',
    'Import Address Table (IAT)', 'Delay_Import / CLR Runtime Header', 'COM_Descriptor', null // (Reserved)
  ],
  COFFSectionCharacteristics: {
    0x00000008: 'NO_PAD', // (obsolete)

//    0x00000010: '(reserved)',
    0x00000020: 'CNT_CODE',
    0x00000040: 'CNT_INITIALIZED_DATA',
    0x00000080: 'CNT_UNINITIALIZED_DATA',

    0x00000100: '(reserved)', // LNK_OTHER
    0x00000200: 'LNK_INFO',
//    0x00000400: '(reserved)', // ?
    0x00000800: 'LNK_REMOVE',
    0x00001000: 'LNK_COMDAT',

    0x00004000: 'NO_DEFER_SPEC_EXC',
    0x00008000: 'GPREL',

    0x00020000: 'MEM_PURGEABLE',
    0x00040000: 'MEM_LOCKED',
    0x00080000: 'MEM_PRELOAD',

    0x00f00000: 'ALIGN_MASK',
/*
    0x00100000: 'ALIGN_1BYTES',
    0x00200000: 'ALIGN_2BYTES',
    0x00300000: 'ALIGN_4BYTES',
    0x00400000: 'ALIGN_8BYTES',
    0x00500000: 'ALIGN_16BYTES',
    0x00600000: 'ALIGN_32BYTES',
    0x00700000: 'ALIGN_64BYTES',
    0x00800000: 'ALIGN_128BYTES',
    0x00900000: 'ALIGN_256BYTES',
    0x00a00000: 'ALIGN_512BYTES',
    0x00b00000: 'ALIGN_1024BYTES',
    0x00c00000: 'ALIGN_2048BYTES',
    0x00d00000: 'ALIGN_4096BYTES',
    0x00e00000: 'ALIGN_8192BYTES',
*/

    0x01000000: 'LNK_NRELOC_OVFL',
    0x02000000: 'MEM_DISCARDABLE',
    0x04000000: 'MEM_NOT_CACHED',
    0x08000000: 'MEM_NOT_PAGED',
    0x10000000: 'MEM_SHARED',
    0x20000000: 'MEM_EXECUTE',
    0x40000000: 'MEM_READ',
    0x80000000: 'MEM_WRITE'
  }
};


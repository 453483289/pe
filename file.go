// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pe implements access to PE (Microsoft Windows Portable Executable) files.
package pe

import (
	"debug/dwarf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// A File represents an open PE file.
type File struct {
	FileHeader
	OptionalHeader interface{} // of type *OptionalHeader32 or *OptionalHeader64
	Sections       []*Section
	Symbols        []*Symbol    // COFF symbols with auxiliary symbol records removed
	_COFFSymbols   []COFFSymbol // all COFF symbols (including auxiliary symbol records)
	_StringTable   _StringTable

	closer io.Closer
}

// Open opens the named file using os.Open and prepares it for use as a PE binary.
func Open(name string) (*File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	ff, err := NewFile(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	ff.closer = f
	return ff, nil
}

// Close closes the File.
// If the File was created using NewFile directly instead of Open,
// Close has no effect.
func (f *File) Close() error {
	var err error
	if f.closer != nil {
		err = f.closer.Close()
		f.closer = nil
	}
	return err
}

var (
	sizeofOptionalHeader32 = uint16(binary.Size(OptionalHeader32{}))
	sizeofOptionalHeader64 = uint16(binary.Size(OptionalHeader64{}))
)

// TODO(brainman): add Load function, as a replacement for NewFile, that does not call removeAuxSymbols (for performance)

// NewFile creates a new File for accessing a PE binary in an underlying reader.
func NewFile(r io.ReaderAt) (*File, error) {
	f := new(File)
	sr := io.NewSectionReader(r, 0, 1<<63-1)

	var dosheader [96]byte
	if _, err := r.ReadAt(dosheader[0:], 0); err != nil {
		return nil, err
	}
	var base int64
	if dosheader[0] == 'M' && dosheader[1] == 'Z' {
		signoff := int64(binary.LittleEndian.Uint32(dosheader[0x3c:]))
		var sign [4]byte
		r.ReadAt(sign[:], signoff)
		if !(sign[0] == 'P' && sign[1] == 'E' && sign[2] == 0 && sign[3] == 0) {
			return nil, fmt.Errorf("Invalid PE COFF file signature of %v.", sign)
		}
		base = signoff + 4
	} else {
		base = int64(0)
	}
	sr.Seek(base, io.SeekStart)
	if err := binary.Read(sr, binary.LittleEndian, &f.FileHeader); err != nil {
		return nil, err
	}
	switch f.FileHeader.Machine {
	case IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386:
	default:
		return nil, fmt.Errorf("Unrecognised COFF file header machine value of 0x%x.", f.FileHeader.Machine)
	}

	var err error

	// Read string table.
	f._StringTable, err = readStringTable(&f.FileHeader, sr)
	if err != nil {
		return nil, err
	}

	// Read symbol table.
	f._COFFSymbols, err = readCOFFSymbols(&f.FileHeader, sr)
	if err != nil {
		return nil, err
	}
	f.Symbols, err = removeAuxSymbols(f._COFFSymbols, f._StringTable)
	if err != nil {
		return nil, err
	}

	// Read optional header.
	sr.Seek(base, io.SeekStart)
	if err := binary.Read(sr, binary.LittleEndian, &f.FileHeader); err != nil {
		return nil, err
	}
	var oh32 OptionalHeader32
	var oh64 OptionalHeader64
	switch f.FileHeader.SizeOfOptionalHeader {
	case sizeofOptionalHeader32:
		if err := binary.Read(sr, binary.LittleEndian, &oh32); err != nil {
			return nil, err
		}
		if oh32.Magic != 0x10b { // PE32
			return nil, fmt.Errorf("pe32 optional header has unexpected Magic of 0x%x", oh32.Magic)
		}
		f.OptionalHeader = &oh32
	case sizeofOptionalHeader64:
		if err := binary.Read(sr, binary.LittleEndian, &oh64); err != nil {
			return nil, err
		}
		if oh64.Magic != 0x20b { // PE32+
			return nil, fmt.Errorf("pe32+ optional header has unexpected Magic of 0x%x", oh64.Magic)
		}
		f.OptionalHeader = &oh64
	}

	// Process sections.
	f.Sections = make([]*Section, f.FileHeader.NumberOfSections)
	for i := 0; i < int(f.FileHeader.NumberOfSections); i++ {
		sh := new(SectionHeader32)
		if err := binary.Read(sr, binary.LittleEndian, sh); err != nil {
			return nil, err
		}
		name, err := sh.fullName(f._StringTable)
		if err != nil {
			return nil, err
		}
		s := new(Section)
		s.SectionHeader = SectionHeader{
			Name:                 name,
			VirtualSize:          sh.VirtualSize,
			VirtualAddress:       sh.VirtualAddress,
			Size:                 sh.SizeOfRawData,
			Offset:               sh.PointerToRawData,
			PointerToRelocations: sh.PointerToRelocations,
			PointerToLineNumbers: sh.PointerToLineNumbers,
			NumberOfRelocations:  sh.NumberOfRelocations,
			NumberOfLineNumbers:  sh.NumberOfLineNumbers,
			Characteristics:      sh.Characteristics,
		}
		r2 := r
		if sh.PointerToRawData == 0 { // .bss must have all 0s
			r2 = zeroReaderAt{}
		}
		s.sr = io.NewSectionReader(r2, int64(s.SectionHeader.Offset), int64(s.SectionHeader.Size))
		s.ReaderAt = s.sr
		f.Sections[i] = s
	}
	for i := range f.Sections {
		var err error
		f.Sections[i]._Relocs, err = readRelocs(&f.Sections[i].SectionHeader, sr)
		if err != nil {
			return nil, err
		}
	}

	return f, nil
}

// zeroReaderAt is ReaderAt that reads 0s.
type zeroReaderAt struct{}

// ReadAt writes len(p) 0s into p.
func (w zeroReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// getString extracts a string from symbol string table.
func getString(section []byte, start int) (string, bool) {
	if start < 0 || start >= len(section) {
		return "", false
	}

	for end := start; end < len(section); end++ {
		if section[end] == 0 {
			return string(section[start:end]), true
		}
	}
	return "", false
}

// Section returns the first section with the given name, or nil if no such
// section exists.
func (f *File) Section(name string) *Section {
	for _, s := range f.Sections {
		if s.Name == name {
			return s
		}
	}
	return nil
}

func (f *File) DWARF() (*dwarf.Data, error) {
	// There are many other DWARF sections, but these
	// are the ones the debug/dwarf package uses.
	// Don't bother loading others.
	var names = [...]string{"abbrev", "info", "line", "ranges", "str"}
	var dat [len(names)][]byte
	for i, name := range names {
		name = ".debug_" + name
		s := f.Section(name)
		if s == nil {
			continue
		}
		b, err := s.Data()
		if err != nil && uint32(len(b)) < s.Size {
			return nil, err
		}
		if 0 < s.VirtualSize && s.VirtualSize < s.Size {
			b = b[:s.VirtualSize]
		}
		dat[i] = b
	}

	abbrev, info, line, ranges, str := dat[0], dat[1], dat[2], dat[3], dat[4]
	return dwarf.New(abbrev, nil, nil, info, line, nil, ranges, str)
}

// ImportedSymbols returns the names of all symbols
// referred to by the binary f that are expected to be
// satisfied by other libraries at dynamic load time.
// It does not return weak symbols.
func (f *File) ImportedSymbols() ([]string, error) {

	return nil, nil
}

// Find a given offset depending on the data section
func (f *File) rvaToSectionOffset(rva uint32) (*Section, int64) {
	var section *Section
	var offset int64
	for i := range f.Sections {
		section = f.Sections[i]
		if (section.VirtualAddress <= rva) && (rva < section.VirtualAddress+section.Size) {
			offset = int64(rva - section.VirtualAddress)
			break
		}
	}

	return section, offset
}

func readArrayUntilEmpty(destination *interface{}) error {
	return nil
}

// ImportedLibraries returns all libraries referred to by the binary f that are expected to be linked with the binary at dynamic link time.
func (f *File) ImportedLibraries() (map[string]*ImportDescriptor, error) {
	var importDirectory DataDirectory
	imports := make(map[string]*ImportDescriptor)

	switch f.FileHeader.Machine {
	case IMAGE_FILE_MACHINE_I386:
		importDirectory = f.OptionalHeader.(*OptionalHeader32).DataDirectory[1]
	case IMAGE_FILE_MACHINE_AMD64:
		importDirectory = f.OptionalHeader.(*OptionalHeader64).DataDirectory[1]
	default:
		return nil, fmt.Errorf("unsupported Machine: %#x", f.FileHeader.Machine)
	}

	section, descriptorOffset := f.rvaToSectionOffset(importDirectory.VirtualAddress)
	if section == nil {
		return nil, fmt.Errorf("unable to find offset for importDescritor")
	}

	seeker := section.Open()
	_, err := seeker.Seek(descriptorOffset, 0)
	if err != nil {
		return nil, err
	}

	descriptorCount := int(importDirectory.Size) / binary.Size(ImportDescriptor{})

	descriptorList := make([]ImportDescriptor, descriptorCount)

	err = binary.Read(seeker, binary.LittleEndian, &descriptorList)
	if err != nil {
		return nil, fmt.Errorf("unable to read the descriptorList: %s", err)
	}

	if len(descriptorList) > 0 {
		for i := range descriptorList[:len(descriptorList)-1] { // Last one is the 0
			// .net assemblies often have a size larger than the actual number of descriptors
			// if we get an empty entry we consider we reached the end of the list
			if descriptorList[i] == (ImportDescriptor{}) {
				descriptorList = descriptorList[:i]
				break
			}

			section, nameOffset := f.rvaToSectionOffset(descriptorList[i].Name)
			data, err := section.Data()
			if err != nil {
				return nil, fmt.Errorf("Error reading data from section %s: %s", section.Name, err)
			}
			name, _ := getString(data, int(nameOffset))

			imports[name] = &descriptorList[i]
		}

	}

	return imports, nil
}

// DelayImportedLibraries returns all libraries referred to by the binary f that are expected to be dynamically linked upon first use of the library
func (f *File) DelayImportedLibraries() (map[string]*DelayLoadDescriptor, error) {
	var directory DataDirectory
	imports := make(map[string]*DelayLoadDescriptor)

	switch f.FileHeader.Machine {
	case IMAGE_FILE_MACHINE_I386:
		directory = f.OptionalHeader.(*OptionalHeader32).DataDirectory[13]
	case IMAGE_FILE_MACHINE_AMD64:
		directory = f.OptionalHeader.(*OptionalHeader64).DataDirectory[13]
	default:
		return nil, fmt.Errorf("unsupported Machine: %#x", f.FileHeader.Machine)
	}

	section, descriptorOffset := f.rvaToSectionOffset(directory.VirtualAddress)
	if section == nil {
		return nil, fmt.Errorf("unable to find offset for DelayLoadDescriptor")
	}

	seeker := section.Open()
	_, err := seeker.Seek(descriptorOffset, 0)
	if err != nil {
		return nil, err
	}

	descriptorCount := int(directory.Size) / binary.Size(DelayLoadDescriptor{})

	descriptorList := make([]DelayLoadDescriptor, descriptorCount)

	err = binary.Read(seeker, binary.LittleEndian, &descriptorList)
	if err != nil {
		return nil, fmt.Errorf("unable to read the descriptorList: %s", err)
	}

	if len(descriptorList) > 0 {
		for i := range descriptorList[:len(descriptorList)-1] { // Last one is the 0 delimiter
			section, nameOffset := f.rvaToSectionOffset(descriptorList[i].Name)
			data, err := section.Data()
			if err != nil {
				return nil, fmt.Errorf("Error reading data from section %s: %s", section.Name, err)
			}
			name, _ := getString(data, int(nameOffset))
			imports[name] = &descriptorList[i]
		}
	}

	return imports, nil
}

// FormatError is unused.
// The type is retained for compatibility.
type FormatError struct {
}

func (e *FormatError) Error() string {
	return "unknown error"
}

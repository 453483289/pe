Microsoft's Portable Executable parsing library based on golang debug/pe package

# Usage

    go get -u "github.com/eltuerto/pe"

Parsing imports and delay loads

    pefile, err := pe.Open(filename)
    if err != nil {
    	return false, err
    }

    imports, err := pefile.ImportedLibraries()
    if err != nil {
    	return false, err
    }

    delayLoads, err := pefile.DelayImportedLibraries()
    if err != nil {
    	return false, err
    }

    dlls := make([]string, len(imports)+len(delayLoads))
    i := 0
    for dll := range imports {
    	dlls[i] = dll
    	i++
    }

    for dll := range delayLoads {
    	dlls[i] = dll
    	i++
    }

    fmt.Printf("%s\n", dlls)

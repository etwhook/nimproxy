import winim, strutils, ptr_math , cligen, strformat

proc RVAtoRawOffset(RVA: DWORD_PTR, section: PIMAGE_SECTION_HEADER): PVOID =
    return cast[PVOID](RVA - section.VirtualAddress + section.PointerToRawData)

proc toString(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc DLLProxy(dllPath : string , outputPath : string , special_add : string = "_bak"): BOOL =
    var
        file: HANDLE
        outputFile: File = open(outputPath , fmAppend)
        fileSize: DWORD
        bytesRead: DWORD
        fileData: LPVOID
        ntdllString: LPCSTR = dllPath
        nullHandle: HANDLE

    file = CreateFileA(ntdllString, cast[DWORD](GENERIC_READ), cast[DWORD](FILE_SHARE_READ), cast[LPSECURITY_ATTRIBUTES](NULL), cast[DWORD](OPEN_EXISTING), cast[DWORD](FILE_ATTRIBUTE_NORMAL), nullHandle)
    fileSize = GetFileSize(file, nil)
    fileData = HeapAlloc(GetProcessHeap(), 0, fileSize)
    ReadFile(file, fileData, fileSize, addr bytesRead, nil)
    
    var
        dosHeader: PIMAGE_DOS_HEADER = cast[PIMAGE_DOS_HEADER](fileData)
        imageNTHeaders: PIMAGE_NT_HEADERS = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](fileData) + dosHeader.e_lfanew)
        exportDirRVA: DWORD = imageNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        section: PIMAGE_SECTION_HEADER = IMAGE_FIRST_SECTION(imageNTHeaders)
        rdataSection: PIMAGE_SECTION_HEADER = section
    var low: uint16 = 0
    var low2: int = 0
    for Section in low ..< imageNTHeaders.FileHeader.NumberOfSections:
        var ntdllSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(imageNTHeaders)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
        if ".rdata" in toString(ntdllSectionHeader.Name):
            rdataSection = ntdllSectionHeader
        
    var exportDirectory: PIMAGE_EXPORT_DIRECTORY = cast[PIMAGE_EXPORT_DIRECTORY](RVAtoRawOffset(cast[DWORD_PTR](fileData) + exportDirRVA, rdataSection))
    var addressOfNames: PDWORD = cast[PDWORD](RVAtoRawOffset(cast[DWORD_PTR](fileData) + cast[DWORD_PTR](exportDirectory.AddressOfNames), rdataSection))
    echo(fmt"[*] Redirecting {exportDirectory.NumberOfNames} Routines ...")
    for low2 in 0 ..< exportDirectory.NumberOfNames:
        var functionNameVA: DWORD_PTR = cast[DWORD_PTR](RVAtoRawOffset(cast[DWORD_PTR](fileData) + addressOfNames[low2], rdataSection))
        var name: LPCSTR = cast[LPCSTR](functionNameVA)
        echo(fmt"[+] Redirecting {name}")
        let valid_path = dllPath.replace(".dll","").replace(r"\",r"\\")
        outputFile.write($"""#pragma comment(linker , "/export:""" & $name & "=" & valid_path & special_add & "." & $name & """")""" & "\n")
        
when isMainModule:
    dispatch DLLProxy
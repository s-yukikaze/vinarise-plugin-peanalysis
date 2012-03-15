" Author:  Sakura-yukikaze <sakura_yukikaze@live.jp>
" Version: 0.0.5
" License: MIT License (see below)
" {{{
" Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
"
" The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
"
" THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
" }}}


let s:save_cpo = &cpo
set cpo&vim

" Constants
let s:IMAGE_DOS_SIGNATURE = 0x5A4D
let s:IMAGE_NT_SIGNATURE = 0x4550

let s:IMAGE_SIZEOF_SHORT_NAME = 8

let s:ACCEPTABLE_MINIMUM_SIZE_OF_OPTIONAL_HEADER = 40

" Structure field offsets and structure sizes
let s:IMAGE_DOS_HEADER = {
 \ 'e_magic' : 0,
 \ 'e_cblp' : 2,
 \ 'e_cp' : 4,
 \ 'e_crlc' : 6,
 \ 'e_cparhdr' : 8,
 \ 'e_minalloc' : 10,
 \ 'e_maxalloc' : 12,
 \ 'e_ss' : 14,
 \ 'e_sp' : 16,
 \ 'e_csum' : 18,
 \ 'e_ip' : 20,
 \ 'e_cs' : 22,
 \ 'e_lfarlc' : 24,
 \ 'e_onvo' : 26,
 \ 'e_res' : 28,
 \ 'e_oemid' : 36,
 \ 'e_oeminfo' : 48,
 \ 'e_res2' : 50,
 \ 'e_lfanew': 60,
 \ '__size__' : 64
 \}
" Notes : The size of IMAGE_NT_HEADERS.OptionalHeader is variable.
let s:IMAGE_NT_HEADERS32 = {
 \ 'Signature' : 0,
 \ 'FileHeader' : 4,
 \ 'OptionalHeader' : 24,
 \ '__size__' : 248
 \}
let s:IMAGE_FILE_HEADER = {
 \ 'Machine' : 0,
 \ 'NumberOfSections' : 2,
 \ 'TimeDataStamp' : 4,
 \ 'PointerToSymbolTable' : 8,
 \ 'NumberOfSymbols' : 12,
 \ 'SizeOfOptionalHeader' : 16,
 \ 'Characteristics' : 18,
 \ '__size__' : 20
 \}
let s:IMAGE_OPTIONAL_HEADER = {
 \ 'Magic' : 0,
 \ 'MajorLinkerVersion' : 2,
 \ 'MinorLinkerVersion' : 3,
 \ 'SizeOfCode' : 4,
 \ 'SizeOfInitializedData' : 8,
 \ 'SizeOfUninitializedData' : 12,
 \ 'AddressOfEntryPoint' : 16,
 \ 'BaseOfCode' : 20,
 \ 'BaseOfData' : 24,
 \ 'ImageBase' : 28,
 \ 'SectionAlignment' : 32,
 \ 'FileAlignment' : 36,
 \ '__size__' : 224
 \}
let s:IMAGE_SECTION_HEADER = {
 \ 'Name' : 0,
 \ 'PhysicalAddress' : 8,
 \ 'VirtualSize' : 8,
 \ 'VirtualAddress' : 12,
 \ 'SizeOfRawData' : 16,
 \ 'PointerToRawData' : 20,
 \ 'PointerToRelocations' : 24,
 \ 'PointerToLinenumbers' : 28,
 \ 'NumberOfRelocations' : 32,
 \ 'NumberOfLinenumbers' : 34,
 \ 'Characteristics' : 36,
 \ '__size__' : 40
 \}

" Plugin interface
function! vinarise#plugins#peanalysis#define()
  return s:plugin
endfunction

let s:plugin = {
 \ 'name' : 'peanalysis',
 \ 'description' : 'PE file analysis feature'
 \}

function! s:plugin.initialize(vinarise, context)"{{{
  command! VinarisePluginPEAnalysisShowSections call s:peanalysis_show_sections()
  command! VinarisePluginPEAnalysisShowVA call s:peanalysis_show_virtual_address()
  command! -nargs=? VinarisePluginPEAnalysisMoveToVA call s:peanalysis_move_to_virtual_address(<q-args>)
  command! VinarisePluginPEAnalysisMoveToEP call s:peanalysis_move_to_entry_point()
endfunction"}}}

" Command handlers
function! s:peanalysis_show_sections()"{{{
  try
    let context = copy(s:PEContext).init(vinarise#get_current_vinarise())
    let baseaddr = context.base_address()
  catch
    echo printf("Failed.\n%s", v:exception)
    return
  endtry

  let idx = 1
  for sec in context.sections()
    echo printf("[%02d] Name=%-8s RawAddr=%08x RawSize=%08x VirtAddr=%08x VirtSize=%08x",
      \ idx, sec.name, sec.rawaddr, sec.rawsize, sec.virtaddr + baseaddr, sec.virtsize)
    let idx += 1
  endfor
endfunction"}}}

function! s:peanalysis_show_virtual_address()"{{{
  let [type, address] = vinarise#parse_address(getline('.'), vinarise#cur_text(getline('.'), col('.')))

  try
    let context = copy(s:PEContext).init(vinarise#get_current_vinarise())
    let vaddr = context.address_file_to_virtual(address)
  catch
    echo printf("Failed.\n%s", v:exception)
    return
  endtry

  echo printf("Virtual Address of %08x: %08x", address, vaddr)
endfunction"}}}

function! s:peanalysis_move_to_virtual_address(input)"{{{
  let offset = (a:input == '') ? input('Please input address : 0x', '') : a:input

  if offset =~ '^\x\+$'
    " Convert hex.
    let address = str2nr(printf('0x%s', offset), 16)
  else
    echo 'Invalid input.'
    return
  endif

  try
    let context = copy(s:PEContext).init(vinarise#get_current_vinarise())
    let fileaddr = context.address_virtual_to_file(address)
  catch
    echo printf("Failed.\n%s", v:exception)
    return
  endtry

  call vinarise#mappings#move_to_address(fileaddr)
endfunction"}}}

function! s:peanalysis_move_to_entry_point()"{{{
  try
    let context = copy(s:PEContext).init(vinarise#get_current_vinarise())
    let address = context.base_address() + context.entry_point()
    let fileaddr = context.address_virtual_to_file(address)
  catch
    echo printf("Failed.\n%s", v:exception)
    return
  endtry

  call vinarise#mappings#move_to_address(fileaddr)
endfunction"}}}

"-----------------------------------------------------------------------------
" PE File Context class
let s:PEContext = {}

function! s:PEContext.init(vinarise)"{{{
  let self._vinarise = a:vinarise

  " Parse NTHeaders#FileHeader
  let self._nthdr = self.nt_headers_offset()
  let self._filehdr = self._nthdr + s:IMAGE_NT_HEADERS32.FileHeader
  let self._secnum = self.get_int16le(self._filehdr + s:IMAGE_FILE_HEADER.NumberOfSections)
  let self._opthdrsize = self.get_int16le(self._filehdr + s:IMAGE_FILE_HEADER.SizeOfOptionalHeader)
  if self._secnum < 1
    throw "PEAnalysis: The file has no section."
  endif
  if self._opthdrsize < s:ACCEPTABLE_MINIMUM_SIZE_OF_OPTIONAL_HEADER
    throw "PEAnalysis: FileHeader.SizeOfOptionalHeader is less than the acceptable minimum."
  endif

  " Parse NTHeaders#OptionalHeader
  let self._opthdr = self._nthdr + s:IMAGE_NT_HEADERS32.OptionalHeader
  let self._baseaddr = self.get_int32le(self._opthdr + s:IMAGE_OPTIONAL_HEADER.ImageBase)
  let self._entrypoint = self.get_int32le(self._opthdr + s:IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint)
  let self._rawalign = self.get_int32le(self._opthdr + s:IMAGE_OPTIONAL_HEADER.FileAlignment)
  let self._virtalign = self.get_int32le(self._opthdr + s:IMAGE_OPTIONAL_HEADER.SectionAlignment)
  if !(512 <= self._rawalign && self._rawalign <= 65536 && s:get_hamming_weight(self._rawalign) == 1)
    throw "PEAnalysis: OptionalHeader.FileAlignment field is broken."
  endif
  if !(self._virtalign >= self._rawalign && s:get_hamming_weight(self._rawalign) == 1)
    throw "PEAnalysis: OptionalHeader.SectionAlignment field is broken."
  endif

  " Parse NTHeaders#SectionHeader[]
  let self._sechdrs = self._opthdr + self._opthdrsize
  let self._sections = []
  for i in range(self._secnum)
    let sechdr = self._sechdrs + i * s:IMAGE_SECTION_HEADER.__size__
    call add(self._sections, {
      \ 'name' : self.get_ascii_cstr(sechdr + s:IMAGE_SECTION_HEADER.Name, s:IMAGE_SIZEOF_SHORT_NAME),
      \ 'rawsize' : s:align(self.get_int32le(sechdr + s:IMAGE_SECTION_HEADER.SizeOfRawData), self._rawalign),
      \ 'rawaddr' : s:align(self.get_int32le(sechdr + s:IMAGE_SECTION_HEADER.PointerToRawData), self._rawalign),
      \ 'virtsize' : s:align(self.get_int32le(sechdr + s:IMAGE_SECTION_HEADER.VirtualSize), self._virtalign),
      \ 'virtaddr' : s:align(self.get_int32le(sechdr + s:IMAGE_SECTION_HEADER.VirtualAddress), self._virtalign),
      \ 'attr' : self.get_int16le(sechdr + s:IMAGE_SECTION_HEADER.Characteristics)
      \})
  endfor
  return self
endfunction"}}}

function! s:PEContext.address_file_to_virtual(address)"{{{
  for sec in self._sections
    if sec.rawaddr <= a:address && a:address < sec.rawaddr + sec.rawsize
      let offset = a:address - sec.rawaddr
      if offset < sec.virtsize
        return self._baseaddr + sec.virtaddr + offset
      endif
    endif
  endfor
  throw "PEAnalysis: Invaild address."
endfunction"}}}

function! s:PEContext.address_virtual_to_file(address)"{{{
  if a:address >= self._baseaddr
    let rva = a:address - self._baseaddr
    for sec in self._sections
      if sec.virtaddr <= rva && rva < sec.virtaddr + sec.virtsize
        let offset = rva - sec.virtaddr
        if offset < sec.rawsize
          return sec.rawaddr + offset
        endif
      endif
    endfor
  endif
  throw "PEAnalysis: Invalid address."
endfunction"}}}

function! s:PEContext.sections()"{{{
  return self._sections
endfunction"}}}

function! s:PEContext.entry_point()"{{{
  return self._entrypoint
endfunction"}}}

function! s:PEContext.base_address()"{{{
  return self._baseaddr
endfunction"}}}

function! s:PEContext.nt_headers_offset()"{{{
  " Verify DOS header signature
  let doshdr = 0
  let dossig = self.get_int16le(doshdr + s:IMAGE_DOS_HEADER.e_magic)
  if dossig != s:IMAGE_DOS_SIGNATURE
    throw "PEAnalysis: DOS header signature is broken."
  endif

  let nthdr = self.get_byte(doshdr + s:IMAGE_DOS_HEADER.e_lfanew)

  " Verify NT headers signature
  let ntsig = self.get_int32le(nthdr + s:IMAGE_NT_HEADERS32.Signature)
  if ntsig != s:IMAGE_NT_SIGNATURE
    throw "PEAnalysis: NT Headers signature is broken."
  endif
  return nthdr
endfunction"}}}

function! s:PEContext.get_byte(offset)"{{{
  return self._vinarise.get_byte(a:offset)
endfunction"}}}
function! s:PEContext.get_int16le(offset)"{{{
  let bytes = self._vinarise.get_bytes(a:offset, 2)
  return bytes[0] + bytes[1] * 0x100
endfunction"}}}
function! s:PEContext.get_int32le(offset)"{{{
  let bytes = self._vinarise.get_bytes(a:offset, 4)
  return bytes[0] +  bytes[1] * 0x100 + bytes[2] * 0x10000 + bytes[3] * 0x1000000
endfunction"}}}

function! s:PEContext.get_ascii_cstr(offset, maxlen)"{{{
  let bytes = self._vinarise.get_bytes(a:offset, a:maxlen)
  let str = ""
  for c in bytes
    if c == 0
      break
    endif
    let str .= c < 32 || c > 127 ? '?' : nr2char(c)
  endfor
  return str
endfunction"}}}

" Utility functions
function! s:get_hamming_weight(source)"{{{
  let [_source, weight] = a:source < 0 ? [a:source + 0x80000000, 1] : [a:source, 0]
  while _source
    let weight += s:hamming_weight_byte[_source % 0x100]
    let _source = _source / 0x100
  endwhile
  return weight
endfunction
let s:hamming_weight_byte = [
 \ 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
 \ 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
 \ 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
 \ 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
 \ 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
 \ 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
 \ 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
 \ 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
 \ 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
 \ 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
 \ 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
 \ 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
 \ 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
 \ 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
 \ 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
 \ 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
 \]"}}}

function! s:align(source, align)"{{{
  return (a:source + a:align - 1) / a:align * a:align
endfunction"}}}

let &cpo = s:save_cpo
unlet s:save_cpo

" vim: foldmethod=marker

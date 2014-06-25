import os.path
import sys
import pefile

class PESecurityCheck:

  # IMAGE_OPTIONAL_HEADER structure
  # http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
  IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040  # http://en.wikipedia.org/wiki/Address_space_layout_randomization
  IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100     # http://en.wikipedia.org/wiki/Data_Execution_Prevention
  IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400        # ttp://en.wikipedia.org/wiki/Microsoft-specific_exception_handling_mechanisms
  
  def __init__(self,pe):
    self.pe = pe

  def aslr(self):
    return bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & self.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
      
  def dep(self):
    return bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & self.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)

  def seh(self):
    return bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & self.IMAGE_DLLCHARACTERISTICS_NO_SEH)

if len(sys.argv) < 2:
  print 'Usage: %s <file_path>' % sys.argv[0] 
  sys.exit()

def main():
  file_path = sys.argv[1]   
  
  try:
    if os.path.isfile(file_path):
      pe = pefile.PE(file_path,True)
    else:
      print "File '%s' not found!" % file_path     
      sys.exit(0)  
  except pefile.PEFormatError:
    print "Not a PE file!"
    sys.exit(0)  
  
  ps = PESecurityCheck(pe)
  
  if ps.aslr():
    print "[+] ASLR Enabled"
  else:
    print "[-] ASLR Not Enabled"
  
  if ps.dep():
    print "[+] DEP Enabled"
  else:
    print "[-] DEP Not Enabled"
  
  if ps.seh():
    print "[+] SEH Enabled"
  else:
    print "[-] SEH Not Enabled"

if __name__ == '__main__':
  main()
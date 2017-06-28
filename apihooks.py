from imageinfo import image_info
import subprocess
import re
from rm import _rm
class record(object):
	def __init__(self,hook_mode,hook_type,pid,name,victim_module,function,hook_address,hooking_module):
		self.hook_mode=hook_mode
		self.hook_type=hook_type
		self.pid=pid
		self.name=name
		self.victim_module=victim_module
		self.function=function
		self.hook_address=hook_address
		self.hooking_module=hooking_module
class _apihooks(record):
	list_of_apihooks=[]
	def __init__(self,filename):
		self.filename=filename
	def return_hooks(self):
		try:
			f=open(self.filename,"r")
			f_read=f.readlines()
			for i in range(0,len(f_read)-1):
				if re.search("Hook mode",f_read[i]):
					hook_mode=_rm(f_read[i][11:])
					hook_type=_rm(f_read[i+1][11:])
					pid=re.findall(r'\d+',_rm(f_read[i+2]))
					name=_rm(re.sub(r'[0-9]','',(f_read[i+2][10:])))
					victim_module=_rm(f_read[i+3][15:])
					function=_rm(f_read[i+4][10:])
					hook_address=_rm(f_read[i+5][10:])
					hooking_module=_rm(f_read[i+6][16:])
					a=record(hook_mode,hook_type,pid[0],name,victim_module,function,hook_address,hooking_module)
					self.list_of_apihooks.append(a)
			return self.list_of_apihooks	
		except IOError:
			print "No file found it means apihooks plugin didnt worked"
if __name__=='__main__':
	sample="./samples/"+raw_input("Enter your sample input :")
	a="volatility -f "+sample+" imageinfo > imageinfo"
	d=subprocess.call(a,shell=True)
	b=image_info("imageinfo")
	profile=b.version
	c="volatility --profile="+profile+" -f "+sample+" apihooks > apihooks"
	d=subprocess.call(c,shell=True)
	e=_apihooks("apihooks")
	aa=e.return_hooks()
	for i in aa:
		print i.hooking_module
	
'''
Hook mode: Usermode
Hook type: NT Syscall
Process: 1928 (lsass.exe)
Victim module: ntdll.dll (0x7c900000 - 0x7c9af000)
Function: ZwQuerySection
Hook address: 0x7c900058
Hooking module: ntdll.dll
'''

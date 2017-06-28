import subprocess
import re
from imageinfo import image_info
def rm(string):
    new_string = ""
    for i in string:
        if i == " " or i=="(" or i==")":
            continue
        else:
            new_string = new_string + i
    return new_string
class record(object):
	def __init__(self,name,pid,sid,desc):
		self.name=name
		self.pid=pid
		self.sid=sid
		self.desc=desc
class _getsids(object):
	admins=[]
	list_sids=[]
	def __init__(self,filename):
		self.filename=filename
		try:
			a=open(filename,"r")
		except IOError:
			print "No file found"
			exit() 
	def _job(self):
		_var1=open(self.filename,"r")
		_var2=_var1.readlines()
		#S-1-5-21-1757981266-796845957-682003330-500
		for i in _var2:		
			_name=i.find(" ")
			name=rm(i[:_name])
			_a=(i[_name:])			
			_pid=rm(_a).find(":")
			pid=rm(_a[:_pid])
			#print _a
			_sid=_a.find("(")
			print name
			print pid
			_c=_a.find(":")
			_d=_a.find("(")
			print _a[_c:]
if __name__=="__main__":
	sample="./samples/"+raw_input("Enter your sample:")
	command1="volatility imageinfo -f"+sample+" > imageinfo"
	print command1
	exe=subprocess.call(command1,shell=True)
	a=image_info("imageinfo")
	profile=a.version
	command="volatility --profile="+profile+" -f "+sample+" getsids > getsids"
	print command
	exe=subprocess.call(command,shell=True)
	obj=_getsids("getsids")
	_a=obj._job()

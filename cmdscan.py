from rm import _rm
from imageinfo import image_info
import subprocess
import re
class cmd(object):
	def __init__(self,filename1,filename2):
		self.filename1=filename1
		self.filename2=filename2
		try:
			if((open(filename1)) and (open(filename2))):
				pass
			else:
				print "File not foud"
				exit()
		except IOError:
			print "File not found"	
	def check_cmd(self):
		a=open(self.filename1,"r")
		b=open(self.filename2,"r")
		d=a.readlines()
		c=b.readlines()
		e=len(c)
		f=len(d)
		self.console_history=""
		self.cmd_history=""
		self.list_of_cmd={}		
		for i in range(0,e-1):
			if re.search("ConsoleProcess",c[i]):
				pid=c[i].find("Pid")
				self.console_process=_rm(c[i][15:pid])
				#print self.cmd_process
			if re.search("AttachedProcess",c[i]):
				pid=c[i].find("Pid")
				self.attached_process=_rm(c[i][16:pid])
				self.list_of_cmd[self.console_process]=self.attached_process
				#print self.attached_process	
			if re.search("Dump",c[i]):
				for i in range(i+1,e-1):
					self.console_history=self.console_history+c[i]
		#print self.list_of_cmd
		#print self.console_history
					#self.console_history=self.console_history+c[i]		
		#self.list_of_cmd.append(self.console_history)
	'''	for i in range(0,f-1):
			if re.search("CommandProcess",d[i]):
				pid=d[i].find("Pid")
				self.cmd_process=_rm(c[i][15:pid])
				self.list_of_cmd.append(self.cmd_process)
			if re.search("Cmd",d[i]):
				pass
				#self.cmd_history=self.cmd_history+d[i]
		#print "The process which is initating the cmd process is \""+self.cmd_process +"\" attached by "+self.attached_process+"\""
		#print self.cmd_history
		#self.list_of_cmd.append(self.cmd_history)'''
		
if __name__=="__main__":
	sample=raw_input("Enter a sample :")
	a1="volatility  -f "+sample+" imageinfo >./output/imageinfo"
	exe=subprocess.call(a1,shell=True)
	b=image_info("./output/imageinfo")
	profile=b.version
	c="volatility --profile="+profile+" -f "+sample+" consoles > consoles"
	d="volatility --profile="+profile+" -f "+sample+" cmdscan > cmd"	
	e=subprocess.call(c,shell=True)
	f=subprocess.call(d,shell=True)
	g=cmd("cmd","consoles")
	g.check_cmd()

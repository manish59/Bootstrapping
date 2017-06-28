import os
import subprocess
import re
import sys
class reg(object):
	username=""
	domainname=""
	def __init__(self,profile,filename):
		self.filename=filename
		self.profile=profile
		SOFTWARE_RUN_KEYS = [
    "Microsoft\Windows\CurrentVersion\Run",
    "Microsoft\Windows\CurrentVersion\RunOnce",
    "Microsoft\Windows\CurrentVersion\RunServices",
    "Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run",
    "Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce",
]
		NTUSER_RUN_KEYS = [
    "Software\Microsoft\Windows\CurrentVersion\Run",
    "Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "Software\Microsoft\Windows\CurrentVersion\RunServices",
    "Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run",
    "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "Software\Microsoft\Windows NT\CurrentVersion\Run",
    "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
]
		list2=["CurrentControlSet\Control\Session Manager\BootExecute","CurrentControlSet\Services","CurrentControlSet\Services","Microsoft\Windows\CurrentVersion\RunServicesOnce","Microsoft\Windows\CurrentVersion\RunServicesOnce","Microsoft\Windows\CurrentVersion\RunServices","Microsoft\Windows\CurrentVersion\RunServices","Microsoft\Windows NT\CurrentVersion\Winlogon\Notify","Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit","Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell","Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell","Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad","Microsoft\Windows\CurrentVersion\RunOnce","Microsoft\Windows\CurrentVersion\RunOnceEx","Microsoft\Windows\CurrentVersion\Run","Microsoft\Windows\CurrentVersion\Run","Microsoft\Windows\CurrentVersion\RunOnce","Microsoft\Windows\CurrentVersion\Policies\Explorer\Run","Microsoft\Windows\CurrentVersion\Policies\Explorer\Run","Microsoft\Windows NT\CurrentVersion\Windows\load","Microsoft\Windows NT\CurrentVersion\Windows","Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler","Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"]
		list1=NTUSER_RUN_KEYS+SOFTWARE_RUN_KEYS
		locations=open("locations","r")
		clean=open("registry","w")
		_locations=locations.readlines()
		for i in _locations:
			if i not in list1:
				list1.append(i[:-1])
		for i in list1:
			cmd="volatility -f "+self.filename+" --profile="+self.profile+" printkey -K " + "\""+i+"\" >> registry"
			print cmd
			exe=subprocess.call(cmd,shell=True)
		clean=open("registry","r")
		_clean=clean.readlines()
		for i in _clean:
			if re.search("Run",i):
				print i
			if re.search("REG_SZ",i):
				print i
if __name__=="__main__":
	profile=sys.argv[1]
	sample=sys.argv[2]
	print profile
	print sample
	a=reg(profile,sample)


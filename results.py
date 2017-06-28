from pslist import artifacts
from imageinfo import image_info 
from psscan import  pool
from totaldll import _dlls
from psxview import _psxview
from privileges import privs
from Tkinter import Tk
from tkFileDialog import askopenfilename
import subprocess
import re
from malfind import mal
from networking import *
from registry import reg
from cmdscan import cmd
comments=[]
profile=""
outfile=open("Output.txt","w+")
logfile=open("logfile.txt","w+")
list_of_pids=[] #List of all processes pids which are found from every experiment
def get_profile(sample):
	command="volatility -f "+sample+" imageinfo > ./output/imageinfo"
	execution=subprocess.call(command,shell=True)
	try:
		image_file=open("./output/imageinfo")
	except IOError:
		print "No file found for finding profile"
		logile.write("No file found for finding profile")
	asd=image_info('./output/imageinfo')
	profile=asd.version #It stores the profile of the image
	return profile
def check_file(sample):
	try:
		_sample_open=open(sample,"r")
		return True
	except IOError:
		print "No sample is found \nTry again"
		logfile.write("No sample is found \nTry again")
		exit()
def pslist_experiment(sample,profile):
	print "\n\nParsing _ESTRUCTURES LIST\n"
	outfile.write("\n\nParsing _ESTRUCTURES LIST\n")	
	_a="volatility --profile="
	_b=" pslist -f"
	_c=" > pslist "
	command=_a+profile+_b+sample+_c
	#print command #command running for pslist
	execution=subprocess.call(command,shell=True)
	pslist_obj=artifacts("pslist") # instatiing the pslist from here
	pslist_obj.artifact()
	pslist_processes=[]
	for i in pslist_obj.list_of_process:
		pslist_processes.append(i.pid)
	#print pslist_processes
	if len(pslist_obj.d)>=1:
		print "\nThe list of process ids which are found suspecting from pslist are:\n"
		outfile.write("\nThe list of process ids which are found suspecting RING-1 are:\n")
		print "Name\t\t\t"+"Pid"+"\t\t"+"Comments"
		outfile.write("\nName\t\t\t"+"Pid"+"\t\t"+"Comments\n")
	#Evidence1=pslist_obj.d which containts list of suspected programs from pslist experiment	
		for i in pslist_obj.d:
			print i.name+"\t\t\t"+i.pid+"\t\t"+pslist_obj.d[i]
			_manish=str("\n"+i.name+"\t\t"+pslist_obj.d[i]+"\n")
			outfile.write(_manish)	
			list_of_pids.append(i.pid)
	else:
		print "No artefacts are found from PSLIST experiment"
		outfile.write("\nNo artefacts are found from PSLIST experiment\n")
	return (list_of_pids,pslist_processes)
def psscan_experiment(sample,profile):
	psscan_process=[]
	command2="volatility --profile="+profile+" psscan -f "+sample+" > psscan"
	#print command2
	a1=subprocess.call(command2,shell=True)
    #pslist_obj.artifact.list_of_suspects stores the list of suspected processes objects
	psscan_obj=pool("psscan")
	list_of_poolspid=psscan_obj.dict_of_pool.keys()  #dictionary with pools of keys
	#print psscan_obj.dict_of_pool
	return (list_of_poolspid,psscan_obj.dict_of_pool)
def psxview_experiment(sample,profile):
	command3="volatility --profile=" + profile + " psxview -f "+sample+">psxview"
	a2=subprocess.call(command3,shell=True)
	_psxview_obj=_psxview("psxview") #instanting the psxview with the object
	Evidence2= _psxview_obj.dict_of_results.keys() #gives the suspected process from psxview experiment
	if len(Evidence2)>=1:
		print "The list of process ids which are found suspecting from psxview are :"
		outfile.write("\nThe list of process ids which are found suspecting from psxview are :\n")
	#_psxview_obj.dict_of_results.keys() are the keys where suspecting are coming from
		for i in  _psxview_obj.dict_of_results.keys():
			print i
			outfile.write(i)
			list_of_pids.append(i)
def dict_dlllist(sample,profile):
	command6="volatility --profile="+profile+" dlllist -f "+sample+" > dlllist"
	a6=subprocess.call(command6,shell=True)
	_dlls_obj=_dlls("dlllist")# _dlls_obj.dict_of_locations is the dictionary which stores the locations of all the running process
	return _dlls_obj.dict_of_locations
def check_priveleges(sample):
	pass
def rogueprocess(list1,list2):
	for i in list1:
		if i not in list2:
			list_of_pids.append(i)
def malfind(sample,profile):
	command="volatility --profile="+profile+" malfind -f "+sample +" > malfinder"
	exe=subprocess.call(command,shell=True)
	a=mal("malfinder")
	b=a.solution()
	l=[]
	for i in b:
		l.append(i.pid)
	return (l,b)
def cmd_scan(sample,profile):
	c="volatility --profile="+profile+" -f "+sample+" consoles > consoles"
	d="volatility --profile="+profile+" -f "+sample+" cmdscan > cmd"	
	e=subprocess.call(c,shell=True)
	f=subprocess.call(d,shell=True)
	g=cmd("cmd","consoles")
	g.check_cmd()
	return (g.list_of_cmd,g.console_history)
def connect(profile):
	if re.search("XP",profile):
		_var1=connections("connections","connscan","sockets","sockscan")
		return(_var1.list_connections,_var1.list_sockets)
	if re.search("7",profile):	
		_var2=net_conn("netscan")
		return (_var2.list_win7)
def run():
	Tk().withdraw() # we don't want a full GUI, so keep the root window from appearing
	sample = askopenfilename() #
	if check_file(sample):
		profile=get_profile(sample)
		print "\n\nThe version of the image is ",profile
		outfile.write("\n\nThe version of the image is:")
		outfile.write(profile)
		values_pslist=pslist_experiment(sample,profile)
		#print "The total list of porcesses pids are \n",values_pslist[1]
		values_psscan=psscan_experiment(sample,profile)
		print "The Unlinked process from detection are :"
		outfile.write("\nThe Unlinked process from detection are :\n")
		if (len(values_psscan[0])-len(values_pslist[1]))>1:
			print "\nThere are some processes which are unlinked from ESTRCUTURES (it is one of the windows data structure which keeps tracks of all the running processes\) "
			print "PID \t\t Name of the Progras"
			outfile.write("\nThere are some processes which are unlinked from ESTRCUTURES (it is one of the windows data structure which keeps tracks of all the running processes\)")
			outfile.write("\nPID \t\t Name of the Programs\n")
			for i in values_psscan[0]:
				if i not in values_pslist[1]:
					print i,"\t\t",values_psscan[1][i][1]
					_manish2=str("\n"+i+"\t\t"+values_psscan[1][i][1]+"\n")
					outfile.write(_manish2)
					list_of_pids.append(i)
		else:
			print "\nThere are no processes which are unlinked from ESTRUCTRES(it is one of the windows data structure which keeps tracks of all the running proecsses in windows operating syste)"
			outfile.write("\nThere are no processes which are unlinked from ESTRUCTRES(it is one of the windows data structure which keeps tracks of all the running proecsses in windows operating syste)")
		values_dlls=dict_dlllist(sample,profile)
		#print list_of_pids
		values_malfind=malfind(sample,profile)
		for i in values_malfind[0]:
			if i not in list_of_pids:
				list_of_pids.append(i)
	print list_of_pids
	values_dlllist=dict_dlllist(sample,profile)
	#command="volatility --profile="+profile+" -f "+sample+" procdump -p " +a[:-1]+" --dump-dir ./output"
	#exe=subprocess.call(command,shell=True)
	
	for i in list_of_pids:
		try:
			if re.search("Users",values_dlllist[i][1]):
				print i+"\t\t"+values_dlllist[i][0]+"\t\t"+values_dlllist[i][1]
				_var21=i+"\t\t"+values_dlllist[i][0]+"\t\t"+values_dlllist[i][1]+"\n"		
				outfile.write(_var21)
			else:
				print i+"\t\t"+values_dlllist[i][0]+"\t\t"+values_dlllist[i][1]
				outfile.write(i+"\t\t"+values_dlllist[i][0]+"\t\t"+values_dlllist[i][1]+"\n")
		except KeyError:
			print "Pid "+i+" is paged out from the memory"
			outfile.write("Pid "+i+" is paged out from the memory\n")
	'''	try:
			print i+"\t\t"+values_dlllist[i][0]+"\t\t"+values_dlllist[i][1]
		except KeyError:
			print "Pid "+i+" is paged out from the memory"
'''
	_var1=network(profile,sample)
	values_connect=connect(profile)
	_temp=[]
	if  re.search("XP",profile):
		for i in values_connect[0]:
			if i.pid in list_of_pids:
				if i.pid not in _temp:
					_temp.append(i.pid)
					outfile.write(i.pid+" is creating a connection to "+ i.ip+"which is probably a backdoor\n")				
					print i.pid+" is creating a connection to "+ i.ip+"which is probably a backdoor"
		for i in values_connect[1]:	
			if i.pid in list_of_pids:
				if i.pid not in _temp:
					_temp.append(i.pid)
					outfile.write(i.pid+" is creating a backdoor connection"+i.ip+" at "+i.time+" using "+i.port+"\n")
					print i.pid+" is creating a backdoor connection"+i.ip+" at "+i.time+" using "+i.port
	else:
		_list=[]
		print "The following pid with names are either listening or got connection established outside world "
		for i in values_connect:
			if  i.state=="ESTABLISHED":
				if i.pid in list_of_pids:
					if i.pid not in _list:
						_list.append(i.pid)
						outfile.write(i.pid+" "+i.name+" opened a backdoor and connected to outside world "+i.fip+"\n")
						print i.pid+" "+i.name+" opened a backdoor"
			if i.state=="LISTENING":
				if i.pid in list_of_pids:
					if i.pid not in _list:
						_list.append(i.pid)
						outfile.write(i.pid+" "+i.name+" opened a backdoor and started listening from outside world "+ i.fip+"\n")	
	values_cmd=cmd_scan(sample,profile)
	if len(values_cmd[0])>=1:
		for i in values_cmd[0]:
			print i +" is the process initated to run programs in cmd and attached by "+ values_cmd[0][i]
			outfile.write(i +" is the process initated to run programs in cmd and attached by "+ values_cmd[0][i]+"\n")
			if len(values_cmd[1])>=1:
				print "The history of commands run in the consoles are:\n "+values_cmd[1]
				outfile.write("\nThe history of commands run in the consoles are:\n "+values_cmd[1])			
	registry_obj=reg(profile,sample)
	if len(registry_obj.runkeys)>=1:
		print "Malware made to run the following programs to run every time the computer restars"
		outfile.write("\nMalware made to run the following programs to run every time the computer restars\n")
		for i in registry_obj.runkeys:
			print i
			outfile.write(i)
	print "Name of the computer is ",registry_obj.username
	outfile.write("\nNmae of the computer is ")
	outfile.write(registry_obj.username)
	if len(registry_obj.domainname)<1:
		print "Domain of the computer is ",registry_obj.domainname
		outfile.write("\nDomain of the computer is ")
		outfile.write(registry_obj.domainname)
	if len(registry_obj.userinit)>80:
		print "Registry key of userinit is changed by the malicious program ",registry_obj.userinit
		outfile.write("\nRegistry key of userinit is changed by the malicious program ")
		outfile.write(registry_obj.userinit)
	temp_pids=" "
	print "The injected process are dumped by the tool"
	for i in list_of_pids:
		cmd="volatility -f "+sample+" --profile="+profile+" memdump -p "+i+" -D ./output/malwarepids"
		exe=subprocess.call(cmd,shell=True)
if __name__=="__main__":
	run()
'''	if check_file(sample):
		profile=get_profile(sample)
		print "\n\nThe version of the image is ",profile
		outfile.write("\n\nThe version of the image is:")
		outfile.write(profile)
		values_pslist=pslist_experiment(sample)
		#print "The total list of porcesses pids are \n",values_pslist[1]
		values_psscan=psscan_experiment(sample,profile)
		print "The Unlinked process from detection are :"
		outfile.write("\nThe Unlinked process from detection are :\n")
		if (len(values_psscan[0])-len(values_pslist[1]))>1:
			print "\nThere are some processes which are unlinked from ESTRCUTURES (it is one of the windows data structure which keeps tracks of all the running processes\) "
			print "PID \t\t Name of the Progras"
			outfile.write("\nThere are some processes which are unlinked from ESTRCUTURES (it is one of the windows data structure which keeps tracks of all the running processes\)")
			outfile.write("\nPID \t\t Name of the Programs\n")
			for i in values_psscan[0]:
				if i not in values_pslist[1]:
					print i,"\t\t",values_psscan[1][i][1]
					_manish2=str("\n"+i+"\t\t"+values_psscan[1][i][1]+"\n")
					outfile.write(_manish2)
					list_of_pids.append(i)
		else:
			print "\nThere are no processes which are unlinked from ESTRUCTRES(it is one of the windows data structure which keeps tracks of all the running proecsses in windows operating syste)"
			outfile.write("\nThere are no processes which are unlinked from ESTRUCTRES(it is one of the windows data structure which keeps tracks of all the running proecsses in windows operating syste)")
		values_dlls=dict_dlllist(sample)
		#print list_of_pids
		values_malfind=malfind(sample)
		for i in values_malfind[0]:
			if i not in list_of_pids:
				list_of_pids.append(i)
	print list_of_pids
	values_dlllist=dict_dlllist(sample)
	#command="volatility --profile="+profile+" -f "+sample+" procdump -p " +a[:-1]+" --dump-dir ./output"
	#exe=subprocess.call(command,shell=True)
	
	for i in list_of_pids:
		try:
			if re.search("Users",values_dlllist[i][1]):
				print i+"\t\t"+values_dlllist[i][0]+"\t\t"+values_dlllist[i][1]
				_var21=i+"\t\t"+values_dlllist[i][0]+"\t\t"+values_dlllist[i][1]+"\n"		
				outfile.write(_var21)
			else:
				print i+"\t\t"+values_dlllist[i][0]+"\t\t"+values_dlllist[i][1]
				outfile.write(i+"\t\t"+values_dlllist[i][0]+"\t\t"+values_dlllist[i][1]+"\n")
		except KeyError:
			print "Pid "+i+" is paged out from the memory"
			outfile.write("Pid "+i+" is paged out from the memory\n")
'''	'''	try:
			print i+"\t\t"+values_dlllist[i][0]+"\t\t"+values_dlllist[i][1]
		except KeyError:
			print "Pid "+i+" is paged out from the memory"
''' '''
	_var1=network(profile,sample)
	values_connect=connect(profile)
	_temp=[]
	if  re.search("XP",profile):
		for i in values_connect[0]:
			if i.pid in list_of_pids:
				if i.pid not in _temp:
					_temp.append(i.pid)
					outfile.write(i.pid+" is creating a connection to "+ i.ip+"which is probably a backdoor\n")				
					print i.pid+" is creating a connection to "+ i.ip+"which is probably a backdoor"
		for i in values_connect[1]:	
			if i.pid in list_of_pids:
				if i.pid not in _temp:
					_temp.append(i.pid)
					outfile.write(i.pid+" is creating a backdoor connection"+i.ip+" at "+i.time+" using "+i.port+"\n")
					print i.pid+" is creating a backdoor connection"+i.ip+" at "+i.time+" using "+i.port
	else:
		_list=[]
		print "The following pid with names are either listening or got connection established outside world "
		for i in values_connect:
			if  i.state=="ESTABLISHED":
				if i.pid in list_of_pids:
					if i.pid not in _list:
						_list.append(i.pid)
						outfile.write(i.pid+" "+i.name+" opened a backdoor and connected to outside world "+i.fip+"\n")
						print i.pid+" "+i.name+" opened a backdoor"
			if i.state=="LISTENING":
				if i.pid in list_of_pids:
					if i.pid not in _list:
						_list.append(i.pid)
						outfile.write(i.pid+" "+i.name+" opened a backdoor and started listening from outside world "+ i.fip+"\n")	
	values_cmd=cmd_scan(sample)
	if len(values_cmd[0])>=1:
		for i in values_cmd[0]:
			print i +" is the process initated to run programs in cmd and attached by "+ values_cmd[0][i]
			outfile.write(i +" is the process initated to run programs in cmd and attached by "+ values_cmd[0][i]+"\n")
			if len(values_cmd[1])>=1:
				print "The history of commands run in the consoles are:\n "+values_cmd[1]
				outfile.write("\nThe history of commands run in the consoles are:\n "+values_cmd[1])			
	registry_obj=reg(profile,sample)
	if len(registry_obj.runkeys)>=1:
		print "Malware made to run the following programs to run every time the computer restars"
		outfile.write("\nMalware made to run the following programs to run every time the computer restars\n")
		for i in registry_obj.runkeys:
			print i
			outfile.write(i)
	print "Name of the computer is ",registry_obj.username
	outfile.write("\nNmae of the computer is ")
	outfile.write(registry_obj.username)
	if len(registry_obj.domainname)<1:
		print "Domain of the computer is ",registry_obj.domainname
		outfile.write("\nDomain of the computer is ")
		outfile.write(registry_obj.domainname)
	if len(registry_obj.userinit)>80:
		print "Registry key of userinit is changed by the malicious program ",registry_obj.userinit
		outfile.write("\nRegistry key of userinit is changed by the malicious program ")
		outfile.write(registry_obj.userinit)
	temp_pids=" "
	print "The injected process are dumped by the tool"
	for i in list_of_pids:
		cmd="volatility -f "+sample+" --profile="+profile+" memdump -p "+i+" -D ./output/malwarepids"
		exe=subprocess.call(cmd,shell=True)

'''

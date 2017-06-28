from imageinfo import image_info
from rm import _rm
import subprocess
import re
import itertools
from sockets import rec1
class rec_conn(object):
	def __init__(self,offset,ip,remote,pid):
		self.offset=offset
		self.ip=ip
		self.remote=remote
		self.pid=pid
class rec_netconn(object):
	def __init__(self,offset,protocol,ip,fip,state,pid,name,time):
		self.offset=offset
		self.protocol=protocol
		self.ip=ip
		self.fip=fip
		self.state=state
		self.pid=pid
		self.name=name
		self.time=time
class net_conn(rec_netconn):
	list_win7=[]
	def __init__(self,filename5):
		self.filename5=filename5
		e=open(self.filename5,"r")
		_e=e.readlines()
		if len(_e)>2:
			for i in _e[1:]:
				offset=_rm(i[0:18])
				protocol=_rm(i[19:25])
				ip=_rm(i[28:48])
				fip=_rm(i[59:97])
				pid=_rm(i[97:106])
				state=_rm(i[80:97])
				name=_rm(i[106:121])
				time=_rm(i[121:153])
				a=rec_netconn(offset,protocol,ip,fip,state,pid,name,time)
				self.list_win7.append(a)
		else:
			print "No network connections"
class connections(rec_conn):
	list_connections=[]
	list_sockets=[]
	
	def __init__(self,filename1,filename2,filename3,filename4):
		self.filename1=filename1
		self.filename2=filename2
		self.filename3=filename3
		self.filename4=filename4
		try :
			a=open(self.filename1,"r")
			_a=open(self.filename2,"r")
			b=a.readlines()
			_b=_a.readlines()
			_varlist=list(itertools.chain(b,_b))
			if len(_varlist)>3:
				for i in _varlist:
					if re.search("Offset",i) or re.search("--",i):
						continue
					else:
						offset=_rm(i[0:10])
						ip=_rm(i[11:36])
						remote=_rm(i[37:62])
						pid=_rm(i[63:])
						#print offset+ip+remote+pid
						_var1=rec_conn(offset,ip,remote,pid)
						self.list_connections.append(_var1)
			else:
				print "No socket connections"
			c=open(self.filename3,"r")
			_c=c.readlines()
			d=open(self.filename4,"r")
			_d=d.readlines()
			_varlist1=list(itertools.chain(_c,_d))
			if (len(_varlist1)>3):
				for i in _varlist1:
					if re.search("Offset",i) or re.search("--",i):
						continue
					else:
						offset=_rm(i[0:10])
						pid=_rm(i[11:20])
						port=_rm(i[21:27])
						protocol=_rm(i[34:50])
						ip=_rm(i[50:65])
						time=_rm(i[65:95])
						a=rec1(offset,pid,port,protocol,ip,time)
						self.list_sockets.append(a)
			else:
				print "No connections"
		except IOError:
			print "Connections command didnt excuted"
class network(object):
	def __init__(self,profile,sample):
		self.profile=profile
		self.sample=sample
		if re.search("XP",self.profile):
			cmd="volatility -f "+self.sample+" --profile="+self.profile+" connections > connections"
			exe=subprocess.call(cmd,shell=True)
			cmd="volatility -f "+self.sample+" --profile="+self.profile+" connscan > connscan"
			exe=subprocess.call(cmd,shell=True)
			cmd="volatility -f "+self.sample+" --profile="+self.profile+" sockets > sockets"
			exe=subprocess.call(cmd,shell=True)
			cmd="volatility -f "+self.sample+" --profile="+self.profile+" sockscan > sockscan"
			exe=subprocess.call(cmd,shell=True)
		if re.search("7",self.profile):
			cmd="volatility -f "+self.sample+" --profile="+self.profile+" netscan > netscan"
			exe=subprocess.call(cmd,shell=True)
		else:
			print "Unknown profile"
if __name__=="__main__":
	sample="./samples/"+raw_input("Enter your sample:")
	cmd="volatility -f "+sample+" imageinfo > imageinfo"
	exe=subprocess.call(cmd,shell=True)
	_var1=image_info('imageinfo')
	profile=_var1.version
	_var2=network(profile,sample)
	if re.search("XP",profile):
		_var3=connections("connections","connscan","sockets","sockscan")
	if re.search("7",profile):		
		_var4=net_conn("netscan")
		for i in _var4.list_win7:
			if i.state=="LISTENING" or i.state=="ESTABLISHED":
				print i.pid,i.name
'''	for i in _var3.list_connections:
		print i.pid,i.offset,i.remote
	for i in _var3.list_sockets:
		print i.pid,i.offset,i.time'''
	

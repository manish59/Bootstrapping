from imageinfo import image_info as im
import re,sys
import subprocess
def remove_white_space(string):
    new_string = ""
    for i in string:
        if i == " " or i=="\n":
            continue
        else:
            new_string = new_string + i
    return new_string
class mal_record(object):
	def __init__(self,name,pid,address):
		self.name=name
		self.pid=pid
		self.address=address
class mal(mal_record):
	list_of_malfind=[]
	list_pids=[]
	def __init__(self,filename):
		self.filename=filename
	def solution(self):
		'''try:
			a=open("filename","r")
			b=a.readlines()
			print b
		except IOError:
			print "No file found"
			exit()'''
		a=open(self.filename,"r")
		b=a.readlines()
		search_term="Process"
		for i in range (0,len(b)-2):
			if re.search(search_term,b[i]):
				a1=b[i].find("Process")
				a2=b[i].find("Address")
				a3=b[i].find("Pid")
				name=b[i][9:a3]
				pid=b[i][a3+5:a2]
				address=remove_white_space(b[i][a2+9:])
				if pid not in self.list_pids:
					self.list_pids.append(pid)
					a=mal_record(remove_white_space(name),remove_white_space(pid),remove_white_space(address))
					self.list_of_malfind.append(a)
		return self.list_of_malfind
if __name__=="__main__":
	sample=raw_input("Enter your sample :")
	command="volatility -f "+sample+" imageinfo > imageinfo"
	aa=subprocess.call(command,shell=True)
	#print command
	a=im("imageinfo")
	profile=a.version
	#print profile
	command1="volatility --profile="+profile+" -f "+sample+" malfind > malfinder"
	bb=subprocess.call(command1,shell=True)	
	print command1
	a=open("malfinder")
	if a:
		mal_obj=mal("malfinder")
		print mal_obj.solution()
	else:
		exit()
	

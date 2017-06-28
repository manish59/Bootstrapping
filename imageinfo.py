import os
import subprocess
#from pslist import remove_white_space as rm
list_of_profiles=[]
def rm(string):
    new_string = ""
    for i in string:
        if i == " ":
            continue
        else:
            new_string = new_string + i
    return new_string
class image_info(object):
	def __init__(self,filename):
		self.filename=filename
		profiles=open("profiles","r")
		_profiles=profiles.readlines()
		for i in _profiles:
			list_of_profiles.append(rm(i[0:22]))	
	#	print 1
		try:
	#		print 2        		
			a=open(filename,"r")
        		b=a.readlines()
			#flag=False
			for i in b:
	#			print 3
        			for j in list_of_profiles:
	#				print 4
					if j in i:
	#					print 5
						self.version=j
			#			print self.version
						break
		except IOError:
			print "File not found"
if __name__=='__main__':
	sample=raw_input("Enter your sample :")
	command="volatility -f "+sample+" imageinfo > ./output/imageinfo"
	execution=subprocess.call(command,shell=True)
	a=image_info('./output/imageinfo')
	print a.version

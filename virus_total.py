import requests
import time
import os
import virustotal
ratio_dict={}
key="b19b042d1c9df8073d6e876e81a121b717953efe098feb30493be2bb7c326dec"
def _main():
	dir="./samples/malfind/be2/"
	a=os.listdir(dir)
	for i in a:
		count=0
		c=dir+i
		v=virustotal.VirusTotal(key)
		report=v.scan(c)
		try:
			for antivirus,malware in report:
				if malware is not None:
					count=count+1
		except TypeError:
			print "Program is going to sleep for two minutes"
			time.sleep(120)	
		ratio_dict[c]=count	
		c=""
if __name__=="__main__":
	_main()
	print ratio_dict

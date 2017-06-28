import collections
#from profile import result
import os
#import results
def remove_white_space(string):
    new_string = ""
    for i in string:
        if i == " ":
            continue
        else:
            new_string = new_string + i
    return new_string
class record(object):
    def __init__(self,offset,name,pid,ppid,pdb,start,last):
		self.offset=offset
		self.name=name
		self.pid=pid
		self.ppid=ppid
		self.pdb=pdb
		self.start=start
		self.last=last
class pool(record):
	dict_of_pool={}

	def __init__(self,filename):
		self.filename=filename
		buffer=open(self.filename)
        	temp_list=buffer.readlines()
        #print temp_list
       		self.dict_of_process = collections.defaultdict(list)
        	for items in temp_list[2:]:
            		memory=remove_white_space(items[0:19])
           		name=remove_white_space(items[19:36])
            		pid=remove_white_space(items[36:43])
            		ppid=remove_white_space(items[43:50])
            		pdb=remove_white_space(items[50:61])
            		start=remove_white_space(items[61:92])
            		end=remove_white_space(items[92:123])
			self.dict_of_pool.setdefault(pid,[]).append(memory)
			self.dict_of_pool.setdefault(pid,[]).append(name)
			self.dict_of_pool.setdefault(pid,[]).append(ppid)
			self.dict_of_pool.setdefault(pid,[]).append(pdb)
			self.dict_of_pool.setdefault(pid,[]).append(start)
			self.dict_of_pool.setdefault(pid,[]).append(end)
if __name__=='__main__':
	a=pool("psscan")
	b=a.dict_of_pool
	print b

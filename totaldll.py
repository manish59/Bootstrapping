import re
def remove_white_space(string):
    new_string = ""
    for i in string:
        if i == " " or i=="\n":
            continue
        else:
            new_string = new_string + i
    return new_string
class _dlls:
	dict_of_locations={}
	d_of_suspects={}# list of suspected pids stored in this dictionary
	def __init__(self,file_name):
		self.file_name=file_name
		buffer=open(self.file_name)
		temp_buffer=buffer.readlines()
		for i in range(len(temp_buffer)):
			name=""
			pid=""
			location=""
			a=temp_buffer[i].find("pid")
			if a>=0:
				name=temp_buffer[i][:a]
				pid=temp_buffer[i][a+4:]
				location=temp_buffer[i+1][15:]
				#print name,pid,location
				self.dict_of_locations.setdefault(remove_white_space(pid),[]).append(remove_white_space(name))
				self.dict_of_locations.setdefault(remove_white_space(pid), []).append(remove_white_space(location))
		for i in self.dict_of_locations:
			aaa=self.dict_of_locations[i][1].find("C:\WINDOWS")
			if aaa<0:
				name=self.dict_of_locations[i][0]
				location=self.dict_of_locations[i][1]
				self.d_of_suspects.setdefault(remove_white_space(i),[]).append(remove_white_space(name))
				self.d_of_suspects.setdefault(remove_white_space(i), []).append(remove_white_space(location))
if __name__=="__main__":
        a=_dlls("dlllist")
	for i in a.dict_of_locations:
		print i,a.dict_of_locations[i][1]

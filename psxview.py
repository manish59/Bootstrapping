def remove_white_space(string):
	new_string = ""
	for i in string:
		if i == " ":
			continue
		else:
			new_string = new_string + i
	return new_string


class _psxview:
	dict_of_results = {}

	def __init__(self, file_name):
                self.file_name = file_name
		buffer = open(self.file_name)  # how to append multiple values to a dict in python
		temp_list = buffer.readlines()
		pslist=psscan=session=csrss=pspcid=threadproc=deskthrd=0
		for items in temp_list[2:]:
			pslist = psscan = session = csrss = pspcid = threadproc = deskthrd = 0
			address = remove_white_space(items[0:11])
			name = remove_white_space(items[11:32])
			pid = remove_white_space(items[32:39])
			if (remove_white_space(items[39:46])=='True' or remove_white_space(items[39:46])=='Okay'):
				pslist=0
			else:
				pslist=1
			if (remove_white_space(items[46:53])=='True' or remove_white_space(items[46:53])=='Okay'):
				psscan=0
			else:
				psscan=1
			if (remove_white_space(items[53:62])=='True' or remove_white_space(items[53:62])=='Okay'):
				threadproc=0
			else:
				threadproc=1
			if remove_white_space(items[62:69])=='True' or remove_white_space(items[62:69])=='Okay':
				pspcid=0
			else:
				pspcid=1
			if remove_white_space(items[62:69])=='True' or remove_white_space(items[62:69])=='Okay':
				csrss = 0
			else:
				csrss=1
			if remove_white_space(items[75:83])=='True' or remove_white_space(items[75:83])=='Okay':
				session=0
			else:
				session=1
			if remove_white_space(items[83:92])=='True' or remove_white_space(items[83:92])=='Okay':
				deskthrd=0
			else:
				deskthrd=1
			total=pslist+pspcid+psscan+deskthrd+csrss+session+threadproc
			exittime = remove_white_space(items[92:121])
			if total!=0:
				self.dict_of_results.setdefault(pid, []).append(address)
				self.dict_of_results.setdefault(pid, []).append(name)
				self.dict_of_results.setdefault(pid, []).append(total)
				self.dict_of_results.setdefault(pid, []).append(exittime)
			else:
				continue
if __name__=="__main__":
	a = _psxview("psxview")
	if len(a.dict_of_results.keys())>0:
		for i in a.dict_of_results.keys():
		    print i,a.dict_of_results[i][2]
	else:
		print "No evidence found"

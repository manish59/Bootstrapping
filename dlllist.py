class dll:
	def __init__(self,file_name):
		self.file_name=file_name
		buffer=open(self.file_name)
		temp_buffer=buffer.readlines()
		index=temp_buffer[1].find("pid")
		name=temp_buffer[1][:index]
		pid=temp_buffer[1][index:]
		location=temp_buffer[2][15:]
		print "Name :",name
		print pid
		print "Location:",location
a=dll('offset')

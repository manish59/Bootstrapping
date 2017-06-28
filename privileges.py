import re
def remove_white_space(string):
    new_string = ""
    for i in string:
        if i == " ":
            continue
        else:
            new_string = new_string + i
    return new_string
class privs:
	def __init__(self,filename):
		self.filename=filename
		a=open(self.filename,"r")
		b=a.readlines()
		var1=["SeBackupPrivilege","SeDebugPrivilege","SeRestorePrivilege","SeLoadDriverPrivilege","SeTcbPrivilege","SeShutdownPrivilege","SeUndockPrivilege","SeAssignPrimaryTokenPrivilege","SeIncreaseQuotaPrivilege Issues","SeRemoteShutdownPrivilege","SeTakeOwnershipPrivilege"]
		count=0
		for i in b[2:]:
			print i
			priv_name=remove_white_space(i[33:70])
			attr=remove_white_space(i[70:95])
			desc=(i[95:])
			if priv_name in var1 and attr!="Present" and attr!="Present,Enabled,Default":
					print priv_name,desc			
if __name__=='__main__':
	a=privs("privs")

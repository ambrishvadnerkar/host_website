import sys
import glob
import os
import re
import crypt
from random import *
import string
from distutils.dir_util import copy_tree
import pwd
import grp
import urllib2
import requests
from requests.auth import HTTPDigestAuth
import mysql.connector
import subprocess

def generate_ran_pass():
	characters = string.ascii_letters + "-+=_!@$#*%<>{}[]" + string.digits
	password = "".join(choice(characters) for x in range(randint(8,12)))
	return password
def create_user(homeDir):
	userDetial = dict()
	while True:
		uname = raw_input("Please insert username: ")
		try:
			uname = uname.lower().strip()
			if verify_users([uname])==True and verify_groups([uname])==True:
				print("Username varified")				
				break
			else:
				print("user or group already exists")
				break
		except ValueError:  
			print("Invalid value. Please try again")
	while True:
		password = generate_ran_pass()
		try:
			password = password.lower().strip()
			break
		except ValueError:  
			print("Invalid value. Please try again")
	if get_confirmation("Do you want to give shell access to this user? "):
		ubash="/bin/bash"
	else:
		ubash="/bin/false"
	
	userDetial = {"user": uname, "password": password, "homedir": homeDir, "shell": ubash}
	
	encPass = crypt.crypt(password,"22")  
	print("useradd -p "+encPass+ " -s "+ ubash + " -d " +homeDir+ " " + uname)
	res = os.system("useradd -p "+encPass+ " -s "+ ubash + " -d " +homeDir+ " " + uname)
	print ("Below is the message while creating user: ")
	print (res)
	return userDetial
			
def get_confirmation(msg):
	confirmation = ""
	#This function will ask for any kind of confirmation and returns True or False
	while True:
		cnf = raw_input(msg + " [Y/N]: ")
		
		try:
			cnf = cnf.lower().strip()
			if cnf  == 'y' or cnf == 'yes': confirmation=True
			elif cnf  == 'n' or cnf == 'no': confirmation=False
			else: print("Invalid value. Please try again")
		except ValueError:  
			print("Invalid value. Please try again")
		if confirmation==True or confirmation==False:
			break
			
	return confirmation
def filter_content(content,strs):
	emptylist = []
	pos = content.index(strs)
	if(pos == 0):
		rlst = content.replace(strs, "").strip().rsplit(" ") if (content.replace(strs, "").strip().count(" ") > 0) else [content.replace(strs, "").strip()]
		return rlst
	else:
		return emptylist
def get_web_dir(exflist,apacheConfDir):
	dirlst = []
	os.chdir( apacheConfDir )
	fin = open(exflist, 'r')
	for ln in fin:
		nlst = ""
		if 'DocumentRoot' in ln:
			nlst = filter_content(ln.strip(),'DocumentRoot')
			if (len(nlst) > 0):
				dirlst.append(nlst[0].strip("\""))
	if len(dirlst)>0 : dirlst = list(set(dirlst))
	if len(dirlst)>1 :	
		fname = select_option("This website is having more than 1 home directories in  config file.\nPlease select any one from below: ", dirlst)
	elif len(dirlst)==1 :
		fname = dirlst[0]
	else:
		fname = ""
		
	return fname
def find_file(content,apacheConfDir):
	filelist = []
	os.chdir( apacheConfDir )
	foundmatch = False
	for file in glob.glob('*.conf'):
		with open(file) as fp:
			foundmatch = False
			nlst = ""
			for line in fp:
				strline = line.strip()
				if content in strline:
					if 'ServerName' in strline:
						nlst = filter_content(strline,'ServerName')
					if 'ServerAlias' in strline:
						nlst = filter_content(strline,'ServerAlias')
					if (len(nlst) > 0): 
						filelist.append(file)
						foundmatch = True
						break;
	return filelist
def select_option(message, arr):
	opt = ""
	while True:
		print(message)
		if len(arr) > 1:
			cnt = 1
			for opt in arr: 
				print(str(cnt) + ") " + opt) 
				cnt += 1
			input = raw_input("Please select any value between 1 to "+str(cnt-1)+" : ")
			try:  
				input = int(input)
				if input > 0 and input < cnt:
					opt = arr[input-1]
					break;
				else:
					print("Invalid value. Please try again")
			except ValueError:  
				print("Invalid value. Please try again")
	return opt.strip()
def set_alias():
	alias = ""

	if get_confirmation("Do you want to set Alias URL? "):
		while True:
			alias = raw_input("Please insert all alias domains here: ")
			if len(alias.lower().strip()) > 0:
				break;
			else:
				print("Invalid value. Please try again\n")
	return alias
def get_input(msg):
	while True:
		dm = raw_input(msg)
		try:  			
			if dm!='':
				break;
			else:
				print("Invalid value. Please try again\n")
		except ValueError:  
			print("Invalid value. Please try again\n")
	return dm
def get_domain(msg):
	regex = re.compile(
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
	
	while True:
		dm = raw_input(msg)
		try:  			
			if re.match(regex, dm):
				print("\n"+dm + " is valid domain/website name.\n")
				break;
			else:
				print("Invalid domain. Please try again\n")
		except ValueError:  
			print("Invalid domain. Please try again\n")
	return dm
def compare_lists(lst1, lst2):
    com_lst = []
    if len(lst1) > 0 and len(lst2) > 0:
        for ls in lst1:
            if ls in lst2:
                com_lst.append(ls)
    return com_lst
def fetch_group_data(data_type):
    fpass = open('/etc/group','r')
    data = {
        "groupname": [],
        "gid": [],
    }
    sel = {
        "groupname": 0,
        "gid": 2,
        "users": 3,
    }
    groupid = fetch_pass_data("gid")

    for ln in fpass:
        lst = ln.rsplit(":")
        data["groupname"].append(lst[sel.get("groupname")])
        data["gid"].append(lst[sel.get("gid")])

    fpass.close()
    return data
def fetch_pass_data(data_type):
    fpass = open('/etc/passwd','r')
    data = {
        "user": [],
        "uid": [],
        "gid": [],
        "homedir": []
    }
    sel = {
        "user": 0,
        "uid": 2,
        "gid": 3,
        "homedir": 5
    }

    if data_type in sel.keys():
        shll = tuple(("/bin/bash","/bin/false"))
        for ln in fpass:
         lst = ln.rsplit(":")
         data["user"].append(lst[sel.get("user")])
         data["uid"].append(lst[sel.get("uid")])
         data["gid"].append(lst[sel.get("gid")])
         data["homedir"].append(lst[sel.get("homedir")])
    fpass.close()
    return data
def verify_users(usrlist):
    users = fetch_pass_data("user")
    unmlist = users["user"]
    cname = compare_lists(usrlist, unmlist)
    if len(cname) > 0:
        return False
    return True
def verify_groups(gnm):
    grpname = fetch_group_data("groupname")
    gname = compare_lists(gnm,grpname["groupname"])
    if len(gname) > 0:
        return False
    return True
def create_apache_config(weburl,alias,homedir,usrname,grpname,apacheConfDir):
	print("Creating apache config file")
	datagrid = urllib2.urlopen("http://APACHE_CONFIG_FILE_URL/webconf.txt").read()
	log_dir = homedir + "/logs/"
	if alias!='':
		aliasURL = 'ServerAlias ' + alias
	else:
		aliasURL = ''
	
	data = datagrid.replace('HOME_DIR', homedir + "/public_html/").replace('ALIAS_URL', aliasURL).replace('WEB_URL',weburl).replace('WEB_USR',usrname).replace('WEB_GRP',grpname).replace('WEB_USR',usrname).replace('ERR_LOG',log_dir+weburl+'_error-log').replace('ACC_LOG',log_dir+weburl+'_access-log')
	
	file = open(apacheConfDir + weburl + ".conf", "w") 
	file.write(data)
	file.close()
	print("\n\nApache config file created\n\n")
	#print(data)
	
def copy_dir(src, dst, username):
	print("\n\n\nStarting copying files.....\n\n")
	src = src.rstrip('/')
	dst = dst+'/'
	
	print ("Soure folder is : "+src)
	print ("Desitnation folder is : "+dst)
	copy_tree(src, dst)
	uid = pwd.getpwnam(username).pw_uid
	gid = grp.getgrnam(username).gr_gid
	os.chown(dst, uid, gid)
	for root, dirs, files in os.walk(dst):  
		for momo in dirs:  
			os.chown(os.path.join(root, momo), uid, gid)
		for momo in files:
			os.chown(os.path.join(root, momo), uid, gid)
	
	print("\n\nFiles copied successfully.....\n\n")
def clone_db(dbrootusr,dbrootpass,dbname,dbhost,newdb,newdbusr,newdbpass,newdbdhost):
	print("\nCreating Database....\n\n")
	mydb = mysql.connector.connect(host=dbhost,user=dbrootusr,passwd=dbrootpass)
	mycursor = mydb.cursor()
	mycursor.execute("create database "+newdb)
	
	print("\nDatabase created....\n\n")
	
	print("\nAssigning privileges....\n\n")
	mycursor.execute("grant all privileges on "+ newdb +".* to "+ newdbusr +"@'"+newdbdhost+"' identified by '"+ newdbpass +"';")
	mycursor.execute("flush privileges;")
	print("\nCloning database....\n\n")
	mydb.close()
	if dbrootpass!='':
		subprocess.Popen('mysqldump -u'+dbrootusr+' -p'+dbrootpass+' '+ dbname +' | mysql -u'+dbrootusr+' -p'+dbrootpass+' '+ newdb , shell=True)
	else:
		subprocess.Popen('mysqldump -u'+dbrootusr+' '+ dbname +' | mysql -u'+dbrootusr+' '+ newdb , shell=True)
def print_details(configfile,weburl,aliasurl,homedir,ftpuser,ftp_pass,dbname,dbhost,dbuser,dbpass):
	print("Below are the websites details to add in DevTracker")
	print("Website URL: "+weburl)
	if aliasurl!='':
		print("Aliases URL: "+aliasurl)
	print("Database name: "+dbname)
	print("DB User: "+dbuser)
	print("DB Pass: "+dbpass)
	print("DB Server: "+dbhost)
	print("Webdir: "+homedir)
	print("Config file: "+configfile)
	print("FTP User: "+ftpuser)
	print("FTP Password: "+ftp_pass)
	
def main():
	apacheConfDir = '/etc/httpd/conf.d/'
	#apacheConfDir = '/root/python_script/conf.d/'
	dbrootusr = 'DB_ROOT_USER'
	dbrootpass = 'DB_ROOT_PASSWORD'
	dbname = ''
	dbhost = 'DB_HOST'
	newdb = ''
	newdbusr = ''
	newdbpass = ''
	newdbdhost = 'DB_HOST'
	
	website = get_domain("Please write the website name which you want to clone/copy: ")
	website = " " + website
	newweb = get_domain("Please new website name: ")
	newAliasweb = set_alias()
	
	print ("\n\n\nAlias urls are : "+newAliasweb)
	exflist = []
	newhomedir = "/home/" + newweb.strip().strip("*.").replace(".","_").replace("-","_")
	exwebdir = ""
	
	
	newflist1 = find_file(newweb,apacheConfDir)
	newflist2 = find_file(newAliasweb,apacheConfDir)
	
	if (len(newflist1)==0 and len(newflist2)==0) :
		exflist = find_file(website,apacheConfDir) #search all files
		if (len(exflist) == 0):
			print(website+ "website does not exist on this server")
		elif (len(exflist) > 1):
			fname = select_option("This website is having more than 1 Apache config file.\nPlease select any one from below: ", exflist)
			exwebdir = get_web_dir(fname.strip(),apacheConfDir)
		else:
			exwebdir = get_web_dir(exflist[0],apacheConfDir)
		
		exwebdir = exwebdir.replace('public_html', '').rstrip('/')
		print(exwebdir)
	
	else: print(newweb + " or " + newAliasweb +" websites already exists on this server")
	
	userDetial = create_user(newhomedir)
	print(userDetial)
	
	if len(userDetial) > 0 and userDetial["user"] !='':
		copy_dir(exwebdir, newhomedir, userDetial["user"])
		create_apache_config(newweb,newAliasweb,newhomedir,userDetial["user"],userDetial["user"],apacheConfDir)
		#dbrootusr dbrootpass dbhost newdb newdbusr newdbpass newdbdhost
		dbname = get_input("Please provide existing database name: ")
		newdb = get_input("Please provide new database name: ")
		newdbusr = get_input("Please provide new DB user : ")
		newdbpass = get_input("Please provide new DB password : ")
		
		if dbrootusr!='' and dbname!='' and dbhost !='' and newdbusr!='' and newdbpass!='' and newdbdhost!='':
			clone_db(dbrootusr,dbrootpass,dbname,dbhost,newdb,newdbusr,newdbpass,newdbdhost)
			print_details(configfile,newweb,newAliasweb,newhomedir,ftpuser,ftp_pass,newdb,newdbdhost,newdbusr,newdbpass)
		else
			print("Invalid database information")
		
if __name__ == '__main__':main()
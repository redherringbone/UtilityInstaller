#####
## This is a utility installer.  It installs stuff
## installGAM()	Call this to install GAM on Debian 8
##				1. Create a directory off the home ~/installscripts
##				2. Copy this file into the directory
##				3. Copy oauth2service.json into the directory
##				4. Copy client_secrets.json into the directory
##				5. Execute this file with python ~/installscripts/utilityinstaller.py from the command prompt
#####





import time
print (time.strftime("%Y-%m-%d %H:%M:%S"))
import subprocess
#import nmap
#import MySQLdb as mdb
import os
import urllib2
import shutil
import sys

# vars
global GAM_DIRECTORY
global INSTALL_SCRIPT_DIRECTORY
GAM_DIRECTORY = 'gam'
INSTALL_SCRIPT_DIRECTORY = "installscripts"
SQL_PASSWORD = 'xxx'
GISP_TUNNEL_PASSWORD = 'xxx'



def executeCMDShell(sCMD):
	print "Executing: %s" % sCMD
	p = subprocess.Popen(sCMD, shell=True)
	p.communicate()

	

def executeCMD(theCommand):
	print "Executing: %s" % (theCommand)
	p = subprocess.Popen(theCommand,
											 stdout=subprocess.PIPE,
											 close_fds=True)
	theOutput = bytes.decode(p.communicate()[0])
	print theOutput
	return theOutput
	
def installHoneyD():
	## double hash = true comment
	## single hash = command skipped for testing
	##
	## set the source to be the Kali rolling source only
	
	if 1==1:
		print "Updating the OS"
		executeCMDShell("sudo apt-get update -y")
		executeCMDShell("sudo apt-get upgrade -y")		
		## depends on bzip2
		print "Installing some helper packages"
		executeCMDShell("sudo apt-get install libevent-dev -y")
		executeCMDShell("sudo apt-get install libdnet-dev -y")
		executeCMDShell("sudo apt-get install libpcap-dev -y")
		executeCMDShell("sudo apt-get install libpcre3-dev -y")
		executeCMDShell("sudo apt-get install make -y")
		executeCMDShell("sudo apt-get install git-core -y")
		executeCMDShell("sudo apt-get install bzip2 -y")
		executeCMDShell("sudo apt-get install nmap -y")
		executeCMDShell("sudo apt-get install psmisc -y")
		executeCMDShell("git clone https://github.com/DataSoft/Honeyd.git")
		executeCMDShell("sudo apt-get install  libtool")
		executeCMDShell("sudo apt-get install automake")
		executeCMDShell("cd Honeyd")
		executeCMDShell("sudo apt-get install libdumbnet-dev -y")
		executeCMDShell("sudo apt-get install zlib1g-dev -y")
		executeCMDShell("cd Honeyd && ./autogen.sh")
		executeCMDShell("cd Honeyd && ./configure")
		executeCMDShell("cd Honeyd && make")
		executeCMDShell("cd Honeyd && sudo make install")
		print "Installing Kippo"
		executeCMDShell("sudo apt-get install python-twisted -y")
		executeCMDShell("git clone https://github.com/desaster/kippo.git")
		executeCMDShell("cd kippo && cp kippo.cfg.dist kippo.cfg")

		
	print "---- Complete ---------"
	

	
	quit()

def installGlastopf():
	## double hash = true comment
	## single hash = command skipped for testing
	##
	## set the source to be the Kali rolling source only
	
	print "installingGlastopf"
	executeCMDShell("sudo apt-get update -y")
	executeCMDShell("sudo apt-get install python python-openssl python-gevent libevent-dev python-dev build-essential make -y")
	executeCMDShell("sudo apt-get install python-argparse python-chardet python-requests python-sqlalchemy python-lxml -y")
	executeCMDShell("sudo apt-get install python-beautifulsoup mongodb python-pip python-dev python-setuptools -y")
	executeCMDShell("sudo apt-get install g++ git php5 php5-dev liblapack-dev gfortran -y")
	executeCMDShell("sudo apt-get install libxml2-dev libxslt-dev -y")
	executeCMDShell("sudo apt-get install libmysqlclient-dev -y")
	executeCMDShell("sudo pip install --upgrade distribute")
	executeCMDShell("cd /opt && sudo git clone git://github.com/mushorg/BFR.git")
	executeCMDShell("cd /opt/BFR && sudo phpize && sudo ./configure --enable-bfr && sudo make && sudo make test && sudo make install")
	executeCMDShell("cd /opt && sudo git clone https://github.com/mushorg/glastopf.git")
	executeCMDShell("cd /opt && sudo git clone https://github.com/client9/libinjection.git")
	executeCMDShell("cd /opt && sudo git clone https://github.com/mushorg/pylibinjection.git")
	executeCMDShell("sudo rm -rf /usr/local/lib/python2.7/dist-packages/distribute-0.7.3-py2.7.egg-info/")
	executeCMDShell("sudo rm -rf /usr/local/lib/python2.7/dist-packages/setuptools*")

	#executeCMDShell("cd /opt/glastopf && sudo python setup.py install")
	executeCMDShell("wget https://pypi.python.org/packages/source/d/distribute/distribute-0.6.35.tar.gz")
	executeCMDShell("tar -xzvf distribute-0.6.35.tar.gz")
	executeCMDShell("cd distribute-0.6.35 && sudo python setup.py install")
	executeCMDShell("sudo pip install glastopf")
	


def setUpTunnels():
	## create user account for remote access
	executeCMDShell("sudo adduser gispremote  --gecos \"\" --disabled-password")
	executeCMDShell("sudo sh -c \"echo gispremote:%s | chpasswd\"") % GISP_TUNNEL_PASSWORD
	executeCMDShell("sudo sed -i 's/Port 443/' /etc/ssh/ssh_config")
	executeCMDShell("sudo sed -i -e '/Match User gispremote/ { N; d; }' /etc/ssh/sshd_config")
	#executeCMDShell("sudo sed -i 's/Match User gispremote/' /etc/ssh/ssh_config")
	#executeCMDShell("sudo sed -i 's/PasswordAuthentication yes' /etc/ssh/ssh_config")
	
	executeCMDShell("sudo sh -c \"echo '# Created by UtilityInstaller' >> /etc/ssh/sshd_config\"")
	executeCMDShell("sudo sh -c \"echo 'Port 443' >> /etc/ssh/sshd_config\"")
	
	executeCMDShell("sudo sh -c \"echo 'PasswordAuthentication no'  >> /etc/ssh/sshd_config\"")
	executeCMDShell("sudo sh -c \"echo 'Match User gispremote'  >> /etc/ssh/sshd_config\"")
	executeCMDShell("sudo sh -c \"echo 'PasswordAuthentication yes'  >> /etc/ssh/sshd_config\"")
#sudo /etc/init.d/ssh restart



	
def installSnort():
	## double hash = true comment
	## single hash = command skipped for testing
	##
	## set the source to be the Kali rolling source only
	
	print "installing Snort"
	print "via https://s3.amazonaws.com/snort-org-site/production/document_files/files/000/000/090/original/Snort_2.9.8.x_on_Ubuntu_12-14-15.pdf?AWSAccessKeyId=AKIAIXACIED2SPMSC7GA&Expires=1458462653&Signature=OooTLEZbtxxUEoCBfmJ0Ifn78Wo%3D "
	if 1==1:
		executeCMDShell("sudo apt-get update -y")
		executeCMDShell("sudo apt-get install -y build-essential")
		executeCMDShell("sudo apt-get install -y libpcap-dev libpcre3-dev libdumbnet-dev")
		executeCMDShell("sudo apt-get install -y bison flex")
		executeCMDShell("wget https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz")
		executeCMDShell("sudo tar -xvzf daq-2.0.6.tar.gz")
		executeCMDShell("cd daq-2.0.6 && sudo ./configure")
		executeCMDShell("cd daq-2.0.6 && sudo make")
		executeCMDShell("cd daq-2.0.6 && sudo make install")
		executeCMDShell("sudo apt-get install -y zlib1g-dev liblzma-dev openssl libssl-dev")
		executeCMDShell("wget https://snort.org/downloads/snort/snort-2.9.8.0.tar.gz")
		executeCMDShell("sudo tar -xvzf snort-2.9.8.0.tar.gz")
		executeCMDShell("cd snort-2.9.8.0 && sudo ./configure --enable-sourcefire")
		executeCMDShell("cd snort-2.9.8.0 && sudo make")
		executeCMDShell("cd snort-2.9.8.0 && sudo make install")
		executeCMDShell("sudo ldconfig")
		executeCMDShell("sudo ln -s /usr/local/bin/snort /usr/sbin/snort")
		executeCMDShell("rm daq-2.0.6.tar.gz")
		executeCMDShell("rm snort-2.9.8.0.tar.gz")

	## tutorial	
	# Create the Snort directories:
		executeCMDShell("sudo mkdir /etc/snort")
		executeCMDShell("sudo mkdir /etc/snort/rules")
		executeCMDShell("sudo mkdir /etc/snort/rules/iplists")
		executeCMDShell("sudo mkdir /etc/snort/preproc_rules")
		executeCMDShell("sudo mkdir /usr/local/lib/snort_dynamicrules")
		executeCMDShell("sudo mkdir /etc/snort/so_rules")
	# Create some files that stores rules and ip lists
		executeCMDShell("sudo touch /etc/snort/rules/iplists/black_list.rules")
		executeCMDShell("sudo touch /etc/snort/rules/iplists/white_list.rules")
		executeCMDShell("sudo touch /etc/snort/rules/local.rules")
		executeCMDShell("sudo touch /etc/snort/sid-msg.map")
	# Create our logging directories:
		executeCMDShell("sudo mkdir /var/log/snort")
		executeCMDShell("sudo mkdir /var/log/snort/archived_logs")
	#cd ~/snort-2.9.8.0/etc/
		executeCMDShell("sudo cp snort-2.9.8.0/etc/*.conf* /etc/snort")
		executeCMDShell("sudo cp snort-2.9.8.0/etc/*.map /etc/snort")
		executeCMDShell("sudo cp snort-2.9.8.0/etc/*.dtd /etc/snort")
		#executeCMDShell("cd ~/snort-2.9.8.0/src/dynamic-preprocessors/build/usr/local/lib/snort_dynamicpreprocessor/
		executeCMDShell("sudo cp snort-2.9.8.0/src/dynamic-preprocessors/build/usr/local/lib/snort_dynamicpreprocessor/ /usr/local/lib/snort_dynamicpreprocessor/")
		executeCMDShell("sudo cp /etc/snort/snort.conf /etc/snort/snort.conf.bak")
		executeCMDShell("sudo sed -i 's/include \$RULE\_PATH/#include \$RULE\_PATH/' /etc/snort/snort.conf")
		executeCMDShell("sudo sed -i 's/var RULE_PATH ..\/rules/var RULE_PATH \/etc\/snort\/rules/'  /etc/snort/snort.conf")
		executeCMDShell("sudo sed -i 's/var SO_RULE_PATH ..\/so_rules/var SO_RULE_PATH \/etc\/snort\/so_rules/'  /etc/snort/snort.conf")
		executeCMDShell("sudo sed -i 's/var PREPROC_RULE_PATH ..\/preproc_rules/var PREPROC_RULE_PATH \/etc\/snort\/preproc_rules/'  /etc/snort/snort.conf")
		executeCMDShell("sudo sed -i 's/var WHITE_LIST_PATH ..\/rules/var WHITE_LIST_PATH \/etc\/snort\/rules\/iplists/'  /etc/snort/snort.conf")
		executeCMDShell("sudo sed -i 's/var BLACK_LIST_PATH ..\/rules/var BLACK_LIST_PATH \/etc\/snort\/rules\/iplists/'  /etc/snort/snort.conf")
		executeCMDShell("sudo sed -i 's/#include $RULE_PATH\/local.rules/include $RULE_PATH\/local.rules/'  /etc/snort/snort.conf")

	
		executeCMDShell("sudo sh -c \"echo 'alert icmp any any -> \$HOME_NET any (msg:\\\"ICMP test detected\\\"; GID:1; sid:10000001; rev:001; classtype:icmp-event;)' >>  /etc/snort/rules/local.rules \"")
		executeCMDShell("sudo sh -c \"echo '1 || 10000001 || 001 || icmp-event || 0 || ICMP Test detected || url,tools.ietf.org/html/rfc792' >>  /etc/snort/sid-msg.map \"")
	
	# test  sudo /usr/local/bin/snort -A console -q -u snort -g snort -c /etc/snort/snort.conf -i eth0

	
	# install barnyard
		executeCMDShell("sudo apt-get install -y mysql-server libmysqlclient-dev mysql-client autoconf libtool")
		executeCMDShell("sudo sed -i '/# output unified2: filename merged.log, limit 128, nostamp, mpls_event_types, vlan_event_types/aoutput unified2: filename snort.u2, limit 128' /etc/snort/snort.conf")
		executeCMDShell("sudo apt-get install -y git")
		executeCMDShell("sudo git clone https://github.com/firnsy/barnyard2.git")
		executeCMDShell("sudo ln -s /usr/include/dumbnet.h /usr/include/dnet.h")
		executeCMDShell("sudo ldconfig")
		executeCMDShell("cd barnyard2 && sudo ./autogen.sh")
		executeCMDShell("cd barnyard2 && sudo ./configure")
		executeCMDShell("cd barnyard2 && sudo ./configure --with-mysql --with-mysql-libraries=/usr/lib/x86_64-linux-gnu/ --with-mysql-includes=/usr/include/")
		executeCMDShell("cd barnyard2 && sudo make")
		executeCMDShell("cd barnyard2 && sudo make install ")
		executeCMDShell("sudo cp barnyard2/etc/barnyard2.conf /etc/snort")
	# # the /var/log/barnyard2 folder is never used or referenced
	# # but barnyard2 will error without it existing
		executeCMDShell("sudo mkdir /var/log/barnyard2")
	# #sudo chown snort.snort /var/log/barnyard2
		executeCMDShell("sudo touch /var/log/snort/barnyard2.waldo")
	# #sudo chown snort.snort /var/log/snort/barnyard2.waldo
		executeCMDShell("sudo sh -c \"echo 'output database: log, mysql, user=snort password=violet dbname=snort host=localhost' >> /etc/snort/barnyard2.conf\"")

	executeCMDShell("mysql -u root --password=%s -e 'create database snort;use snort; '") % SQL_PASSWORD
	executeCMDShell("mysql -u root --password=%s -e 'use snort; source ~/barnyard2/schemas/create_mysql;'") % SQL_PASSWORD
	executeCMDShell("mysql -u root --password=%s -e \"use snort; CREATE USER 'snort'@'localhost' IDENTIFIED BY 'violet';\"") % SQL_PASSWORD
	executeCMDShell("mysql -u root --password=%s -e \"use snort; grant create, insert, select, delete, update on snort.* to 'snort'@'localhost';\"") % SQL_PASSWORD
	print "Snort installation now complete"


# test with
#sudo barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort -f snort.u2 -w /var/log/snort/barnyard2.waldo
	
	# test it
	#executeCMDShell("sudo snort -A console -q -c /etc/snort/snort.conf")




	


	



	

def installNewOpenVas():
	
	## double hash = true comment
	## single hash = command skipped for testing
	##
	## set the source to be the Kali rolling source only
	print "Preparing sources.list to update from Kali"
	executeCMDShell("sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak")
	#### alternative ### executeCMDShell("sudo sh -c \"echo 'deb http://http.kali.org/kali kali-rolling main contrib non-free' >> /etc/apt/sources.list\"")
	executeCMDShell("sudo sh -c \"echo 'deb http://http.kali.org/kali kali-rolling main contrib non-free' > /etc/apt/sources.list\"")
	## fix the kali authentication keys
	print "Fixing the Kali authentication keys"
	executeCMDShell("sudo gpg --keyserver pgpkeys.mit.edu --recv-key  ED444FF07D8D0BF6")
	executeCMDShell("sudo gpg -a --export ED444FF07D8D0BF6 | sudo apt-key add -")
	print "Updating the OS"
	executeCMDShell("sudo apt-get update -y")
	executeCMDShell("sudo apt-get upgrade -y")
	## depends on bzip2
	print "Installing some helper packages"
	executeCMDShell("sudo apt-get install bzip2 -y")
	executeCMDShell("sudo apt-get install nmap -y")
	executeCMDShell("sudo apt-get install psmisc -y")
	## search for openvas if needed
	### apt-cache search openvas
	print "Installing OpenVAS packages"
	executeCMDShell("sudo apt-get install openvas -y")
	print "Configuring certificates"
	executeCMDShell("sudo openvas-mkcert")
	print " .... OPENVAS SETUP ...."
	executeCMDShell("sudo openvas-setup")

	### check setup with sudo openvas-check-setup

	## these are only for debug
	##executeCMDShell("sudo openvas-nvt-sync")
	##executeCMDShell("sudo openvas-mkcert-client -n -i"))
	##--- executeCMDShell("sudo openvas-setup")
	##executeCMDShell("sudo openvasmd --rebuild")
	##executeCMDShell("sudo openvas-nvt-sync")
	
	## assume all set up correctly
	print "Resetting password and configuring directories"
	executeCMDShell("sudo openvasmd --user admin --new-password x")
	scriptDirectory = os.path.expanduser('~') + '/scripts'
	if not os.path.exists(scriptDirectory):
		print "Creating directory: %s" %(scriptDirectory)
		os.makedirs(scriptDirectory)
	print "Configuring Python mysql"
	executeCMDShell("sudo apt-get install python-mysqldb -y")
	print "Configuring OMP"
	shutil.copyfile(os.path.expanduser('~') + '/installscripts/omp.config', os.path.expanduser('~') + '/omp.config')
	print " -------------------- COMPLETE ----------------"
	

	
	
	quit()
	


# python anaconda plus editor: https://www.continuum.io/downloads	+ http://damnwidget.github.io/anaconda/
# install GAM into UNIX
# https://github.com/jay0lee/GAM/releases
def installGAM():
	gamInstallDirectory = os.path.expanduser('~')
	gamInstallDirectory += '/' + GAM_DIRECTORY 				# to hard code the directory use: 	gamInstallDirectory = "/home/--USER--"
	gamInstallDirectoryS = gamInstallDirectory + "/"
	scriptsInstallDirectory = os.path.expanduser('~') + "/" + INSTALL_SCRIPT_DIRECTORY		# this must exist!  create manually
	scriptsInstallDirectoryS = scriptsInstallDirectory + "/"
	if not os.path.exists(gamInstallDirectory):
		print "Creating directory: %s" %(gamInstallDirectory)
		os.makedirs(gamInstallDirectory)
	# get GAM package.  						# TO-DO: get latest automatically from GIT
	# package url: https://github.com/jay0lee/GAM/archive/v3.62.tar.gz
	gamPackageURI = "https://github.com/jay0lee/GAM/archive/v3.62.tar.gz"
	gamPackageFilename = "v3.62.tar.gz"			# TO-DO: get this automatically (!)
	print "Downloading package: %s" % (gamPackageURI)
	theFile = urllib2.urlopen(gamPackageURI)
	f = open(gamInstallDirectoryS + gamPackageFilename, 'wb')	# b is for windows systems only
	f.write(theFile.read())
	f.close()
	theCommand = ['tar', '-zxv',  '-C',gamInstallDirectory , '-f', gamInstallDirectoryS + gamPackageFilename]
	executeCMD(theCommand)
	if os.path.exists(gamInstallDirectoryS + gamPackageFilename):
		os.remove(gamInstallDirectoryS + gamPackageFilename)
	## remove the gam command directory so that it is built fresh
	gamCmdDirectory = gamInstallDirectory + 'cmd'		# same heirarchy just append cmd to name, don't want a sub
	gamCmdDirectoryS = gamCmdDirectory + "/"
	if os.path.exists(gamCmdDirectory):
		print "Deleting directory %s" % (gamCmdDirectory)
		shutil.rmtree(gamCmdDirectory)  #, ignore_errors=True
	#---------------------------------------
	# TO-DO: creat the directory and then copy the contents of src, rather than just copy to a new dir name
	#	#if not os.path.exists(gamCmdDirectory):
	#		#print "Creating directory: %s" %(gamCmdDirectory)
	#		#os.makedirs(gamCmdDirectory)
	#----------------------------------------
	# move the specific files needed to the command directory if it is in the wrong place !! manual check !!
	# gam creates -- GAM-3.62 / src / ****  The src directory is the directory with gam.py, but it also needs some other files
	shutil.move(gamInstallDirectoryS + 'GAM-3.62/src',gamCmdDirectory)
	if os.path.exists(gamInstallDirectoryS + 'GAM-3.62'):
		print "Deleting: %s" % (gamInstallDirectoryS + 'GAM-3.62')
		shutil.rmtree(gamInstallDirectoryS + 'GAM-3.62', ignore_errors=True)
	if not os.path.exists(gamCmdDirectoryS + 'nobrowser.txt'):
		print "Creating nobrowser.txt"
		f = open(gamCmdDirectoryS + 'nobrowser.txt', 'wb')
		f.write("nobrowser")
		f.close
	# now copy / upload / get the authentication files.
	# need to be copied manually.		# TO-DO: automate the upload or extract from secure location
	shutil.copyfile(scriptsInstallDirectoryS + 'oauth2service.json', gamCmdDirectoryS  + 'oauth2service.json')
	shutil.copyfile(scriptsInstallDirectoryS + 'client_secrets.json', gamCmdDirectoryS  + 'client_secrets.json')
	# to initiate gam python gam.py info user and then answer 24 - contine
	theCommand = '/usr/bin/python ' + gamCmdDirectoryS + 'gam.py info user'
	# get the gam authentication
	os.system(theCommand)		# TO-DO: replace with subprocess and catch the output
	print "GAM completed"

	
def testInstall():
	gamInstallDirectory = os.path.expanduser('~')
	gamInstallDirectory += '/' + GAM_DIRECTORY 		
	scriptsInstallDirectory = os.path.expanduser('~') + "/" + INSTALL_SCRIPT_DIRECTORY		
	gamPackageURI = "https://github.com/jay0lee/GAM/archive/v3.62.tar.gz"
	gamPackageFilename = "v3.62.tar.gz"			
	gamCmdDirectory = gamInstallDirectory + 'cmd'		
	theCommand = '/usr/bin/python ' + gamCmdDirectory + '/gam.py info user'
	
	if os.path.exists(gamInstallDirectory):
		print "OK: %s" % (gamInstallDirectory)
	else:
		print "To create: %s" % (gamInstallDirectory)
	if os.path.exists(scriptsInstallDirectory):
		print "OK: %s" % (scriptsInstallDirectory)
	else:
		print "FAIL: %s must exist" % (gamInstallDirectory)
		
		
	if os.path.exists(gamCmdDirectory):
		print "OK: %s" % (gamCmdDirectory)
	else:
		print "To create: %s" % (gamCmdDirectory)
		
	if os.path.exists(gamCmdDirectory + "nobrowser.txt"):
		print "OK: %s" % (gamCmdDirectory + "nobrowser.txt")
	else:
		print "To create: %s" %(gamCmdDirectory + "nobrowser.txt")
		
	if os.path.exists(scriptsInstallDirectory + '/oauth2service.json'):
		print "OK: %s" % (scriptsInstallDirectory + '/oauth2service.json')
	else:
		print "FAIL: %s must exist" % (scriptsInstallDirectory + '/oauth2service.json')
	if os.path.exists(scriptsInstallDirectory + '/client_secrets.json'):
		print "OK: %s" % (scriptsInstallDirectory + '/client_secrets.json')
	else:
		print "FAIL: %s must exist" % (scriptsInstallDirectory + '/client_secrets.json')

	

def runGAMTest():
	print "testing"
	gamInstallDirectory = os.path.expanduser('~')
	gamInstallDirectory += '/' + GAM_DIRECTORY 		
	gamCmdDirectory = gamInstallDirectory + 'cmd'		
	theCommand = '/usr/bin/python ' + gamCmdDirectory + '/gam.py info user'
	theResult = os.system(theCommand)
	print "Complete: %s" %(theResult)

def reinstallOpenVAS():
	theCMD = ['sudo', 'apt-get', 'update']
	theCMD = "sudo apt-get update"
	#executeCMDShell(theCMD)
	executeCMDShell("sudo apt-get remove openvas -y")
	executeCMDShell("sudo apt-get install openvas")


def showMenu(theMenu = ''):
	tmp = subprocess.call('clear', shell=True)
	## main
	menu = {}
	menu[' 1']='Install GAM'
	menu[' 2']='Test'
	menu[' 3']='Run GAM info user to test'
	menu[' 4']='Reinstall OpenVAS'
	menu[' 5']='Install OpenVAS on a new Debian Instance'
	menu[' 6']='Install HoneyD on a new Debian Instance'
	menu[' 7']='Install glastopf'
	menu[' 8']='Install Snort'
	menu[' 9']='Set up SSH tunnels'
	menu['Q']='Exit'
	while True:
		options=menu.keys()
		options.sort()
		for entry in options:
			print entry, menu[entry]
		if theMenu == '':
			selection=raw_input("Select -->")
		if theMenu != '':
			selection = theMenu
			theMenu = ''
		print "selection " + selection
		if selection == '1':
			print "Installing GAM"
			installGAM()
		elif selection == '2':
			testInstall()
		elif selection == '3':
			runGAMTest()
		elif selection == '4':
			print "--4--"
			reinstallOpenVAS()
		elif selection =='5':
			print "Installing OpenVAS on a new Debian instance"
			installNewOpenVas()
		elif selection == '6':
			print "Installing HoneyD"
			installHoneyD()
		elif selection == '7':
			installGlastopf()
		elif selection == '8':
			installSnort()
		elif selection == '9':
			setUpTunnels()
		elif selection.upper() == 'Q':
			break
		else:
			print "Error"
	print "exiting"	

	
if len(sys.argv) > 1:
	if sys.argv[1] == '-h':
		print """==============================================
This is GISP Utility installer
Useage:
python utilityinstaller.py

Follow menu
create users with adduser


================================================"""
		quit()
	print "executing command " + str(sys.argv)
	showMenu(sys.argv[1])
else:
	showMenu()
	quit()
	
	

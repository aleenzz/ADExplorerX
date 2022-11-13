import json
import argparse
import sqlite3
import os
import datetime
import re

TemplateHeader = '''<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title></title>
		<style type="text/css">
			table{
				border-collapse: collapse;
			}	
			table tr th{
				border: solid 1px #ccc;
				height: 30px;
				width: 200px;
				background-color: #eee;
			}
			table tr td{
				border: solid 1px #ccc;
				height: 30px;
				text-align: center;
			}
			table tr:hover
			{
				background-color: #eee;
			}
		</style>
	</head>
	<body>
	<table border="0" cellspacing="0" cellpadding="0">
'''
TemplateFooter = '''</table>	
	</body>
</html>
'''

class LiteDb(object):
    _instance = None
 
    def __new__(cls, *args, **kw):
        if cls._instance is None:
            cls._instance = object.__new__(cls)
        return cls._instance
 
    def openDb(self, dbname):
        self.dbname = dbname
        self.conn = sqlite3.connect(self.dbname)
        self.cursor = self.conn.cursor()
 
    def closeDb(self):
        self.cursor.close()
        self.conn.close()
 
    def createTables(self, sql):
        self.cursor.execute(sql)
        self.conn.commit()
        result = [1, None]
        return result
 
    def dropTables(self, sql):
        self.cursor.execute(sql)
        self.conn.commit()
        result = [1, None]
        return result
 
    def executeSql(self, sql, value=None):
        if isinstance(value,list) and isinstance(value[0],(list,tuple)):
            for valu in value:
                self.cursor.execute(sql, valu)
            else:
                self.conn.commit()
                result = self.cursor.fetchall()
        else:
            if value:
                self.cursor.execute(sql, value)
            else:
                self.cursor.execute(sql)
            self.conn.commit()
            result = self.cursor.fetchall()
        return result

class parseObjects:
    def __init__(self):
        self.getObjectClasses = self.getObjectClasses     
        self.getObjectCategory = self.getObjectCategory
        self.attributes = []
    def getObjectClasses(self):
        return list(map(str.casefold, self.attributes.get('objectClass', [])))
    def getObjectCategory(self):
        catDN = self.attributes.get('objectCategory', None)
        if catDN is None:
            return None
        return getObjectDN(catDN[0])
    classes = property(getObjectClasses)
    category = property(getObjectCategory)

def getObjectDN(DN):
    if DN is None:
        return None
    return DN.split(',')[0].split('=')[1].lower()

def get_entry_property(entry, prop, default=None, raw=False):
    try:
        if raw:
            value = entry[prop]
        else:
            value = entry[prop]
    except KeyError:
        return default
    if value == []:
        return default
    try:
        if len(value) == 1 and default != []:
            return value[0]
    except TypeError:
        pass
    return value

def win_timestamp_to_unix(seconds):
    seconds = int(seconds)
    if seconds == 0:
        return 0
    return int((seconds - 116444736000000000) / 10000000)
def isOU(distinguishedName):
    OU_REGEX = re.compile("OU.+?(?=,DC)")
    OUGroup = OU_REGEX.findall(distinguishedName)
    if len(OUGroup) != 0:
        return OUGroup[0]
    return None
def str_human_date(date):
    if isinstance(date, datetime.timedelta):
        nb_sec = int(date.total_seconds())
    else:
        nb_sec = int((-date) / 10000000)
    if nb_sec > 60:
        nb_min = int(nb_sec / 60)
        nb_sec = nb_sec % 60
        if nb_min > 60:
            nb_hour = int(nb_min / 60)
            nb_min = nb_min % 60
            if nb_hour > 24:
                nb_day = int(nb_hour / 24)
                nb_hour = nb_hour % 24
                return f"{nb_day} days, {nb_hour} hours, {nb_min} minutes, {nb_sec} seconds"
            return f"{nb_hour} hours, {nb_min} minutes, {nb_sec} seconds"
        return f"{nb_min} minutes, {nb_sec} seconds"
    return f"{nb_sec} seconds"

def processUsers(conn,parseObjects):
    if not ('user' in parseObjects.classes and 'person' in parseObjects.category):
        return
    distinguishedName = get_entry_property(parseObjects.attributes, 'distinguishedName', default=0)
    ResOU = isOU(distinguishedName)
    sAMAccountName = get_entry_property(parseObjects.attributes, 'sAMAccountName', default=0)
    enabled = get_entry_property(parseObjects.attributes, 'userAccountControl', default=0) & 2 == 0
    lastlogon = datetime.datetime.fromtimestamp(win_timestamp_to_unix(get_entry_property(parseObjects.attributes, 'lastLogon', default=0, raw=True)))
    lastlogontimestamp = datetime.datetime.fromtimestamp(win_timestamp_to_unix(get_entry_property(parseObjects.attributes, 'lastlogontimestamp', default=0, raw=True)))
    pwdlastset = datetime.datetime.fromtimestamp(win_timestamp_to_unix(get_entry_property(parseObjects.attributes, 'pwdLastSet', default=0, raw=True)))
    email = get_entry_property(parseObjects.attributes, 'mail')
    title = get_entry_property(parseObjects.attributes, 'title')
    description = get_entry_property(parseObjects.attributes, 'description')
    conn.executeSql('''INSERT INTO "DomainUser" (distinguishedName,sAMAccountName,enabled,lastlogon,lastlogontimestamp,pwdlastset,email,title,description) VALUES (?,?,?,?,?,?,?,?,?)''',(ResOU,sAMAccountName,enabled,lastlogon,lastlogontimestamp,pwdlastset,email,title,description))
    return

def processGroups(conn,parseObjects):
    if not 'group' in parseObjects.classes:
        return
    distinguishedName = get_entry_property(parseObjects.attributes, 'distinguishedName')
    DN = getObjectDN(distinguishedName)
    conn.executeSql('''INSERT INTO "DomainGroup" (name) VALUES (?)''',[DN])
    return

def processDomainAccountPolicy(conn,parseObjects):
    if not 'domaindns' in parseObjects.classes:
        return
    maxPwdAge = str_human_date(get_entry_property(parseObjects.attributes, 'maxPwdAge'))
    minPwdAge = str_human_date(get_entry_property(parseObjects.attributes, 'minPwdAge'))
    minPwdLength = get_entry_property(parseObjects.attributes, 'minPwdLength')
    lockoutThreshold = get_entry_property(parseObjects.attributes, 'lockoutThreshold')
    lockoutDuration = str_human_date(get_entry_property(parseObjects.attributes, 'lockoutDuration'))
    conn.executeSql('''INSERT INTO "DomainPolicy" (maxPwdAge,minPwdAge,minPwdLength,lockoutThreshold,lockoutDuration) VALUES (?,?,?,?,?)''',(maxPwdAge,minPwdAge,minPwdLength,lockoutThreshold,lockoutDuration))
    return

def processComputers(conn,parseObjects):
    if not get_entry_property(parseObjects.attributes, 'sAMAccountType') == 805306369 or (get_entry_property(parseObjects.attributes, 'userAccountControl', 0) & 0x02 == 0x02):
        return
    sAMAccountName = get_entry_property(parseObjects.attributes, 'sAMAccountName')
    operatingsystem = get_entry_property(parseObjects.attributes, 'operatingSystem')
    enabled = get_entry_property(parseObjects.attributes, 'userAccountControl', default=0) & 2 == 0
    lastlogon = datetime.datetime.fromtimestamp(win_timestamp_to_unix(get_entry_property(parseObjects.attributes, 'lastLogon', default=0, raw=True)))
    lastlogontimestamp = datetime.datetime.fromtimestamp(win_timestamp_to_unix(get_entry_property(parseObjects.attributes, 'lastlogontimestamp', default=0, raw=True)))
    conn.executeSql('''INSERT INTO "DomainComputer" (sAMAccountName,operatingsystem,enabled,lastlogon,lastlogontimestamp) VALUES (?,?,?,?,?)''',(sAMAccountName,operatingsystem,enabled,lastlogon,lastlogontimestamp))
    return

def database_connect(noJsonPath):
    try:
        db = "%s.db"% noJsonPath
        isexistsdb = False
        if os.path.exists(db):
            isexistsdb = True
        conn = LiteDb()
        conn.openDb(db)
        if isexistsdb == False:
            print("[+] init Database")
            initDatabase(conn,noJsonPath)
        return conn
    except Exception as e:
        print("[!] Could not connect to database")
        print(e)
        return False


def domain_parser(conn,noJson):
    with open (noJson,"r") as f:
        for line in f:
            tmp = parseObjects()
            tmp.attributes = json.loads(line)
            processGroups(conn,tmp)
            processComputers(conn,tmp)
            processUsers(conn,tmp)
            processDomainAccountPolicy(conn,tmp)
    return
def initDatabase(conn,noJsonPath):
    conn.createTables('''CREATE TABLE if not exists "DomainGroup" (
	"id"	INTEGER,
	"name"	TEXT,
	PRIMARY KEY("id" AUTOINCREMENT)
    );''')
    conn.createTables('''CREATE TABLE if not exists "DomainUser" (
	"id"	INTEGER,
	"distinguishedName"	TEXT,
	"sAMAccountName"	TEXT,
	"enabled"	TEXT,
	"lastlogon"	TEXT,
	"lastlogontimestamp"	TEXT,
	"pwdlastset"	TEXT,
	"email"	TEXT,
	"title"	TEXT,
	"description"	TEXT,
	PRIMARY KEY("id" AUTOINCREMENT)
    );''')
    conn.createTables('''CREATE TABLE if not exists "DomainPolicy" (
	"id"	INTEGER,
	"maxPwdAge"	TEXT,
	"minPwdAge"	TEXT,
    "minPwdLength"	TEXT,
	"lockoutThreshold"	TEXT,
	"lockoutDuration"	TEXT,
	PRIMARY KEY("id" AUTOINCREMENT)
    );''')
    conn.createTables('''CREATE TABLE if not exists "DomainComputer" (
	"id"	INTEGER,
	"sAMAccountName"	TEXT,
	"operatingsystem"	TEXT,
	"enabled"	TEXT,
	"lastlogon"	TEXT,
	"lastlogontimestamp"	TEXT,
	PRIMARY KEY("id" AUTOINCREMENT)
    );''')
    domain_parser(conn,noJsonPath)

def getHtml(conn,name,data):
    if len(data) == 0:
        return
    result = conn.executeSql('select %s from %s' %(','.join(data),name))
    print(TemplateHeader)
    temp = ""
    for i in data:
        temp += '<th>%s</th>' %i
    temp2 = "<tr>%s</tr>" % temp
    print(temp2)
    for domaingroup in result:
        temp3 = ''
        for j in domaingroup:
            temp3 +='<td>%s</td>' %j
        temp4 = "<tr>%s</tr>" %temp3
        print(temp4)

def main():
    parser = argparse.ArgumentParser(add_help=True, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('noJson', help="Path to the noJson  file.")
    parser.add_argument('-g', '--group',action='store_true',help="Print Domain Group")
    parser.add_argument('-p', '--policy',action='store_true',help="Print Domain Policy")
    parser.add_argument('-u', '--user',action='store_true',help="Print Domain User")
    args = parser.parse_args()
    conn = database_connect(args.noJson)
    if conn == False:
        return
    if args.group == True:
        getHtml(conn,'DomainGroup',['id','name'])
    if args.policy == True:
        getHtml(conn,'DomainPolicy',['id','maxPwdAge','minPwdAge','minPwdLength','lockoutThreshold','lockoutDuration'])
    if args.user == True:
        getHtml(conn,'DomainUser',['id','distinguishedName','sAMAccountName','email','title','description','enabled','lastlogon','pwdlastset'])

if __name__ == '__main__':
    main()
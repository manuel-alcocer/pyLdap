# Libreria para gestión de LDAP

from os import sep
from os.path import isfile, join as joinPath

from base64 import b64encode, b64decode

try:
    from ldap3 import ALL, Connection, Server, ALL_ATTRIBUTES
except ImportError:
    print('Es necesaria la librería ldap3 para python >= 3')
    print('''
Instalassiom en ñu lìnu:

    $ pip --user install ldap3

O usando virtualenv:

    $ sudo apt-get install python3-virtualenv
    $ mkdir -p .virtualenvs/pyldap
    $ virtualenv !$
    $ source .virtualenvs/pyldap/bin/activate
    $ pip3 install ldap3

Y vuelve a ejecutar la aplicación''')
    exit(3)

###
ROOTDN = 'dc=alcocer,dc=gonzalonazareno,dc=org'
PEOPLE_DN = 'ou=people,%s' % ROOTDN

###
MINUID = 2000
LOGINSHELL = '/bin/bash'
HOME_BASE = '/home/nfs/'

# object classes
USERS_OBJECTCLASS = ['top', 'person', 'organizationalPerson', 'inetOrgPerson', 'posixAccount', 'shadowAccount', 'ldapPublicKey']
GRUPO_OBJECTCLASS = ['top', 'posixGroup' ]
COMPUTER_OBJECTCLASS = ['top', 'device', 'ipHost', 'ldapPublicKey']

class ldap:
    def __init__(self, *args, **kwargs):
        self.host = kwargs['server']
        if 'admin' in kwargs:
            self.adminDN = kwargs['admin']
            self.password = kwargs['password']
        self.rootDN = ROOTDN

    def createServer(self):
        self.server = Server(self.host, get_info=ALL)

    def createConn(self, anonymous=False):
        try:
            if not anonymous:
                self.conn = Connection(self.server, self.adminDN, self.password, auto_bind=True)
            else:
                self.conn = Connection(self.server, auto_bind=True)
        except:
            print('Error en en la conexión con el servidor LDAP')
            exit(1)

    def updateValues(self):
        self.getAllUIDN()
        self.getAllGIDN()

    def getAllUIDN(self):
        self.conn.search(PEOPLE_DN, '(objectclass=person)', attributes=['uidNumber'])
        self.uidNumbers = [ person.uidNumber.value for person in self.conn.entries ]

    def getAllGIDN(self):
        self.conn.search(PEOPLE_DN, '(objectclass=person)', attributes=['gidNumber'])
        self.gidNumbers = [ person.gidNumber.value for person in self.conn.entries ]

    def getFreeUIDNumber(self):
        freeuidn = MINUID
        found = False
        while not found:
            if freeuidn in self.uidNumbers or freeuidn in self.gidNumbers:
                freeuidn += 1
            else:
                self.uidNumbers.append(freeuidn)
                self.gidNumbers.append(freeuidn)
                found = True
        return freeuidn

    def insert(self, *args, **kwargs):
        ldapObj = kwargs['ldapObj']
        exists = self.check_ldapObj(ldapObj=ldapObj)
        if not exists:
            print('insertando: %s ....' %ldapObj)
            self.conn.add(ldapObj.DN,ldapObj.OBJECT_CLASSES,ldapObj.attributes)
        else:
            print('ya existe: %s ... saltando al siguiente.' %ldapObj)

        if ldapObj.subObjects:
            for subObj in ldapObj.subObjects:
                exists = self.check_ldapObj(ldapObj=subObj)
                if not exists:
                    print('insertando: %s ...' %subObj)
                    self.conn.add(subObj.DN, subObj.OBJECT_CLASSES, subObj.attributes)

    def delete(self, *args, **kwargs):
        ldapObj = kwargs['ldapObj']
        exists = self.check_ldapObj(ldapObj=ldapObj)
        print('Borrando: %s ...' %ldapObj)
        if not exists:
            print('No existe: %s ... saltando al siguiente' %ldapObj)
        else:
            self.conn.delete(ldapObj.DN)

        if ldapObj.subObjects:
            for subObj in ldapObj.subObjects:
                exists = self.check_ldapObj(ldapObj=subObj)
                if exists:
                    print('borrando: %s ...' %subObj)
                    self.conn.delete(subObj.DN)
                else:
                    print('No existe: %s ... saltando' %subObj)

    def check_ldapObj(self, *args, **kwargs):
        ldapObj = kwargs['ldapObj']
        searchStr = '(&(objectclass=%s)(%s))' %(ldapObj.objectclass,ldapObj.searchAttr)
        return self.conn.search(self.rootDN, searchStr)

    def search(self, *args):
        status = self.conn.search(args[0],args[1], attributes = args[2])
        if status:
            return self.conn.entries[0].sshPublicKey.values[0].decode('utf-8')

    def searchAll(self, *args):
        status = self.conn.search(args[0],args[1], attributes = ALL_ATTRIBUTES)
        if status:
            computerList = [ computer for computer in self.conn.entries ]
            return computerList


class ldapObject(object):
    def __str__(self):
        return self.attributes['cn']


class ldapUser(ldapObject):
    def __init__(self, user_dict, ldapServer):
        self.attributes = {}
        for attribute in user_dict:
            self.attributes[attribute] = user_dict[attribute]
        self.attributes['cn'] = '%s %s' % (user_dict['givenName'], user_dict['sn'])
        uidnumber = ldapServer.getFreeUIDNumber()
        self.attributes['uidNumber'] = uidnumber
        self.attributes['gidNumber'] = uidnumber
        self.attributes['loginShell'] = LOGINSHELL
        self.attributes['homeDirectory'] = joinPath(sep, HOME_BASE, self.attributes['uid'])

        self.OBJECT_CLASSES = USERS_OBJECTCLASS

        self.objectclass = 'Person'
        self.OU = 'People'
        self.searchAttr = 'uid=%s' %self.attributes['uid'] 
        self.DN = 'uid=%s,ou=%s,%s' %(self.attributes['uid'],self.OU, ROOTDN)

        # este objeto del ldap tiene asociada un subojeto
        self.group = groupUser(uid=self.attributes['uid'], gid=self.attributes['gidNumber'])

        self.subObjects = [self.group]

    def check_strings(self, stringAttr):
        try:
            coded = stringAttr.encode('ascii')
            return stringAttr
        except:
            return b64encode(bytes(stringAttr, 'utf-8'))

    def checkAttrs(self):
        for attr in self.attributes:
            self.attributes[attr] = check_strings(self.attributes)

class groupUser(ldapObject):
    def __init__(self, *args, **kwargs):
        self.attributes = {}
        self.attributes['cn'] = kwargs['uid']
        self.attributes['gidNumber'] = kwargs['gid']

        self.OBJECT_CLASSES = GRUPO_OBJECTCLASS

        self.objectclass = 'posixGroup'

        self.OU = 'Group'
        self.searchAttr = 'cn=%s' %self.attributes['cn']
        self.DN = 'cn=%s,ou=%s,%s' %(self.attributes['cn'], self.OU, ROOTDN)

class ldapComputers(ldapObject):
    def __init__(self, computerDict, ldapServer):
        self.attributes = {}
        for attribute in computerDict:
            self.attributes[attribute] = computerDict[attribute]
        self.attributes['cn'] = computerDict['cn']
        self.attributes['ipHostNumber'] = computerDict['ipHostNumber']
        self.attributes['sshPublicKey'] = computerDict['sshPublicKey']

        self.OBJECT_CLASSES = COMPUTER_OBJECTCLASS

        self.subObjects = False

        self.objectclass = 'device'

        self.OU = 'computers'
        self.searchAttr = 'cn=%s' %self.attributes['cn']
        self.DN = 'cn=%s,ou=%s,%s' %(self.attributes['cn'], self.OU, ROOTDN)

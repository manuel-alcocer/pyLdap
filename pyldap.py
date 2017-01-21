#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from getpass import getpass
from json import load

from sys import argv, exit

from os.path import isfile, join as joinPath
from os import sep

from myLdap import ldap, ldapUser, ldapComputers

from datetime import datetime

SERVER = '172.22.200.62'
#SERVER = 'barney.alcocer'

ROOTDN = 'dc=alcocer,dc=gonzalonazareno,dc=org'
ADMIN_DN = 'cn=admin,%s' % ROOTDN

# tablas de traducción  para normalizar el jotasón
OU_OBJ = { 'personas' : 'People', 'computers' : 'computers'}
OBJ_ATTR = { 'nombre' : 'givenName', 'apellidos' : 'sn' ,
             'usuario' : 'uid' , 'clave' : 'sshPublicKey' ,
             'hostname' : 'cn' , 'ipv4' : 'ipHostNumber',
             'correo' : 'mail' }

def readJson(fichero):
    if isfile(fichero):
        try:
            with open(fichero, 'r') as f:
                json_data = load(f)
                return json_data
        except:
            print('Error en el formato del jotasón')
    else:
        print('Error: el fichero: "%s" , no existe' %fichero)
        exit(1)

# inserta en el OU People
def generateAllUsers(jsonPeople, ldapServer):
    usuarios = []
    for person in jsonPeople['People']:
        usuarios.append(ldapUser(person, ldapServer))
    return usuarios

def generateAllComputers(jsonComp, ldapServer):
    ordenadores = []
    for ordenador in jsonComp['computers']:
        ordenadores.append(ldapComputers(ordenador, ldapServer))
    return ordenadores

# inserta lo que haya en el json
def insertAll(ldapObjs, ldapServer):
    for ldapObj in ldapObjs:
        ldapServer.insert(ldapObj=ldapObj)

def deleteAll(ldapObjs, ldapServer):
    for ldapObj in ldapObjs:
        ldapServer.delete(ldapObj=ldapObj)

def normalizeJson(user_dict):
    new_dict = {'People': [], 'computers' : []}
    for OU in user_dict:
        for element in user_dict[OU]:
            new_dict[OU_OBJ[OU]].append({})
            for objattr in element:
                new_dict[OU_OBJ[OU]][-1][OBJ_ATTR[objattr]] = element[objattr]
    return new_dict

def CreateConnection(**kwargs):
    if kwargs['password']:
        PASSWD = getpass('Contraseña de admin: ')
        print('Conectando con el servidor....')
        if 'extra' in kwargs:
            extraOpts = kwargs['extra']
        else:
            extraOpts = None
        servidor = ldap(server=kwargs['server'], admin=kwargs['adminDN'], password=PASSWD)
        servidor.createServer()
        servidor.createConn()
        print('Conexión establecida')
    else:
        servidor = ldap(server=kwargs['server'])
        servidor.createServer()
        servidor.createConn(True)
    return servidor

def fetchUserPK():
    userldap = argv[argv.index('--sshUPK')+1]
    servidor = CreateConnection(server=SERVER, password=False)
    dn = 'uid=%s,ou=People,dc=alcocer,dc=gonzalonazareno,dc=org' %userldap
    objectclass = '(objectclass=person)'
    sshPublicKey = servidor.search(dn, objectclass, 'sshPublicKey')
    return sshPublicKey

def writeKH(computers):
    try:
        with open('/etc/ssh/ssh_known_hosts', 'w') as f:
            for computer in computers:
                f.write('%s,%s %s\n' %(computer.cn.values[0], computer.ipHostNumber.values[0], computer.sshPublicKey.values[0].decode('utf-8')))
    except:
        print('Error escribiendo /etc/ssh/ss_known_hosts, comprueba permisos')
        exit(2)

def createKnownHosts():
    servidor = CreateConnection(server=SERVER, password=False)
    dn='ou=computers,dc=alcocer,dc=gonzalonazareno,dc=org'
    objectclass = '(objectclass=device)'
    computerlist = servidor.searchAll(dn, objectclass)
    writeKH(computerlist)

def populateLdap():
    jsonfile = argv[argv.index('--json')+1]
    user_dict = readJson(jsonfile)
    user_dict = normalizeJson(user_dict)
    # Establecer conexión
    servidor = CreateConnection(server=SERVER, adminDN=ADMIN_DN, password=True)
    servidor.updateValues()
    usuarios = generateAllUsers(user_dict, servidor)
    ordenadores = generateAllComputers(user_dict, servidor)
    if '-i' in argv and '--all' in argv:
        insertAll(usuarios, servidor)
        insertAll(ordenadores, servidor)
    elif '-d' in argv and '--all' in argv:
        deleteAll(usuarios, servidor)
        deleteAll(ordenadores, servidor)
    else:
        print('''
    Error en los parámetros, usa:
        -i --all : para insertarlos todos
        -d --all : para borrarlos todos
''')
        exit(1)

def main():
    if '--json' in argv:
        populateLdap()
    elif '--sshUPK' in argv[1]:
        sshPublicKey = fetchUserPK()
        print(sshPublicKey)
    elif '--makeKH' in argv:
        createKnownHosts()
    else:
        print('necesito argumentos')

if __name__ == '__main__':
    main()

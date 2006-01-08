#!/usr/bin/env python
# HoneySpy -- advanced honeypot environment
# Copyright (C) 2005  Robert Nowotniak
# Copyright (C) 2005  Michal Wysokinski
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


#
# XXX
# THIS CODE NEEDS REFACTORING OR NEEDS TO BE REWRITTEN
#

from twisted.internet import protocol
from random import randint
from os import  fdopen, fsync, getpid,kill
import os
import sys

### Import Polish locale ###
import locale
locale.setlocale(locale.LC_ALL, 'polish')
############################

uname = 'Linux rocket 2.6.12-gentoo-r10 #2 SMP ' \
    + 'Sun Sep 25 13:45:33 CEST 2005 i686 AMD Sempron(tm)' \
    + '2800+ AuthenticAMD GNU/Linux\r\n';
prompt = '[%(cwd)s]$ '



############################################
# Definicje prostych funkcji komend powloki
#
def uptime(shell, args):
    return ' %d:%d:%d up  %d days, %d users,   load average: %d.00, %d.00, %d.00\r\n' \
        % (randint(0,23), randint(0,60), randint(0,60), randint(0,100), \
                randint(0,30), randint(0,30), randint(0,30), randint(0,30));

def exit(shell, args):
    os.kill(shell.getParentPID(),9)

def cd(shell, args):
    if len(args) > 1:
        shell.cwd = args[1]
    else:
        shell.cwd = '~'
    return ''

def echo(shell, args):
    return ' '.join(args[1:]) + '\r\n'

def pwd(shell, args):
    return shell.cwd + '\r\n'

commands = {
    'ls'     : 'ls dziala\r\n',
    'wget'   : 'wget: b',
    'uptime' : uptime,
    'uname'  : uname,
    'exit'   : exit,
    'cd'     : cd,
    'logout' : exit,
    'echo'   : echo,
    'pwd'    : pwd,
    ''       : '',
}

# Funkcja uzywana do logowania danych do HoneySpy'a
#

#
# Our fake shell
#
class ShellSimulationProtocol(protocol.Protocol):
    LOG = None 
    parentPID = None

    def __init__(self,pid):
        self.cmdline = ''
        self.cwd = '/tmp'
        self.prompt = prompt
        self.LOG = fdopen(3, 'w')
        self.parentPID = pid

    def getParentPID(self):
        return self.parentPID

    def logData(self,msg):
        self.LOG.write('['+str(getpid())+'] command: ' + msg + '\r\n')
        self.LOG.flush()

    def executeCommand(self, cmdline):
        self.logData(cmdline)
        global commands
        tokens = cmdline.split()
        if len(tokens) == 0:
            tokens = ['']
        if tokens[0] in commands:
            result = commands[tokens[0]]
            if type(result) == type(''):
                data = result
            else:
                data = result(self, tokens)
        else:
            data = 'bash: '+tokens[0]+': command not found\r\n'
        return data;

    def printPrompt(self):
        self.transport.write(prompt % {'cwd':self.cwd});
    
    def returnPrompt(self):
        return prompt % {'cwd':self.cwd} 

    def connectionMade(self):
        self.printPrompt()
    
    def zeroCommand(self):
        self.cmdline = ""
       
    def dataReceived(self, data):
        if data == '\x03': #^C
            self.executeCommand('exit')
        elif data == '\r':
            data = self.executeCommand(self.cmdline)
            self.transport.write('\r\n' + data)
            self.printPrompt()
            self.zeroCommand()
        else:
             self.cmdline += data
             self.transport.write(data)



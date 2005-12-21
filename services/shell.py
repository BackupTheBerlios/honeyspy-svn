from twisted.internet import protocol
from random import randint
from os import  fdopen, fsync, getpid,kill
import os

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
    'wget'   : 'wget: brąkujacy URL\r\nUżycie: wget [OPCJE]... [URL]...\
                \r\nPolecenie `wget --help wyświetli więcej opcji.\r\n',
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

    def connectionMade(self):
        self.printPrompt()

    def dataReceived(self, data):
        if data == '\x03': #^C
            self.executeCommand('exit')
        elif data == '\r':
            data = self.executeCommand(self.cmdline)
            self.transport.write('\r\n' + data)
            self.printPrompt()
            self.cmdline = ""
        else:
             self.cmdline += data
             self.transport.write(data)



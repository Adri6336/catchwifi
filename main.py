# Find and connect to an open wifi hotspot
from os import system as sys
from os import geteuid as usertype
from rich import print
from random import randint
from time import sleep
from sys import exit

# ============ FUNCTIONS ============

def getNonRoot():
    """
    This function determines the name of a non root user

    :return: String name
    """

    # 1. Get the name of a normal user
    sys('sudo cat /etc/passwd | grep 1000 > normal')
    sys('sudo chmod 755 normal')

    with open('normal', 'r') as file:
        name = file.read().split(':')

    sys('sudo rm normal')

    return name[0]


def info(content, kind='info'):
    """
    This prints info to the terminal in a fancy way

    :param content: This is the string you want to display
    :param kind: bad, info, question; changes color
    :return: None
    """

    if kind == 'info':
        print(f'[bold blue]\[i][/bold blue] [white]{content}[/white]')

    elif kind == 'bad':
        print(f'[bold red][X][/bold red] [white]{content}[/white]')

    elif kind == 'question':
        print(f'[bold yellow]\[?][/bold yellow] [white]{content}[/white]')


def play(name, user, fast=False):
    """
    This plays a wav sound file

    :param name: The name of the wav file
    :return: None
    """
    '''
    if path.isfile(f'./sound/{name}.wav') and fast:
        effect = th(target=lambda: playsound(f'./sound/{name}.wav'))
        effect.start()

    elif path.isfile(f'./sound/{name}.wav') and not fast:
        playsound(f'./sound/{name}.wav')
    '''
    sys(f'sudo -u {user} python3 play.py -a {name} -s {fast} > /dev/null 2>&1')
    sleep(1)


def scan(user):  # Function 1
    '''
    This orders a scan of the environment and displays the results
    if no hotspots are located. This is the main function of the script.
    '''
    # Start

    sys('sudo nmcli dev wifi rescan > /dev/null 2>&1')
    sys('sudo nmcli dev wifi > hotspots')
    sys('sudo chmod 755 hotspots > /dev/null 2>&1')
    with open('hotspots', 'r') as file:
        spots = file.read()
        sys('clear')  # Clears the terminal
        print(f'[white]{spots}[/white]')  # Prints wifi hotspots around you

        # 1. Split file by newline
        spots = spots.split('\n')

        # 2. Determine if there's an open spot
        for spot in spots:
            if 'MODE' in spot:  # Skip first line
                continue
            elif len(spot) == 0:  # Skip last line
                continue

            # Get info from spot
            try:
                spotInfo = clean(spot)
                bssid = spotInfo[0]
                security = spotInfo[2]

            except Exception as e:  # Something is going wrong
                with open('blackbox', 'a') as blackbox:
                    print(f'ERROR: {str(e)}; TUPLE: {spotInfo}\n{str(spots)}')
                    blackbox.write(str(e))  # Save error for later review
                    exit(1)

            # 3. Interpret results of scan
            if '--' in security and not inBlacklist(bssid):  # If the hotspot is open and not in the blacklist
                play('hotspot', user)  # Alert driver that a spot has been located

                if connect(bssid) and internetAccess():
                    if randint(0, 1) == 1:
                        play('gotone', user)
                    else:
                        play('park', user)

                    break

                else:
                    play('failed', user)
                    addToBlacklist(bssid)
                    continue

            elif 'WEP' in security and not inBlacklist(bssid):  # If spot uses WEP
                play('web', user)  # Make a note for the lolz
                addToBlacklist(bssid)  # Ignore going forward

        # 4. Notify driver to move on
        nothing = randint(0, 4)
        if nothing == 0:
            play('nothing1', user)
        elif nothing == 1:
            play('nothing2', user)
        elif nothing == 2:
            play('nothing3', user)
        elif nothing == 3:
            play('nothing4', user)
        elif nothing == 4:
            play('nothing5', user)



def clean(line):
    """
    Cleans a passed nmcli line so that
    it can be more reliably parsed.

    :param line: nmcli dev wifi output line
    :return: tuple of the cleaned list's elements
    """

    # 1. Remove spaces
    splitLine = line.split(' ')

    quit = False
    while not quit:
        try:
            splitLine.remove('')
        except:
            quit = True

    # 2. Get info

    # 2.1 Identify where the BSSID starts
    if splitLine[0] == '*':
        start = 1
    else:
        start = 0

    # 2.2 Count the steps until Infra is encountered
    infra = 0
    for item in splitLine:
        if not item == 'Infra':
            infra += 1
        else:
            break

    # 2.3 Compile the SSID
    place = start + 1
    ssid = ''

    while place < infra:
        ssid += splitLine[place]
        place += 1

    # Define variables and return them as tuple
    bssid = splitLine[start]
    try:
        security = splitLine[infra + 6]
    except:
        print(splitLine)
        exit()

    #print(f'BSSID: {bssid};SSID: {ssid};SEC: {security}')
    return (bssid, ssid, security)


def connect(bssid):
    """
    This connects to a bssid

    :param bssid:
    :return: bool representing connection status
    """
    pass


def inBlacklist(bssid):
    '''
    Determines if bssid is in blacklist

    :Param bssid: string BSSID
    :Return: bool representing membership; true if in, false otherwise
    '''
    try:
        with open('blacklist.txt', 'r') as file:
            content = file.read()
            if bssid in content:
                return True
            else:
                return False
    except:  # Likely cause is that the file does not exist
        return False


def addToBlacklist(bssid):
    '''
    This function adds a bssid to the blacklist

    :Parm: string bssid
    :Return: None
    '''
    with open('blacklist.txt', 'a') as file:
        file.write(bssid + '\n')
        info('Added %s to blacklist' % bssid, kind='bad')
        play('blacklist', user)


def internetAccess():  # Function 3
    '''
    This function determines if the connection has internet by pinging
    Google's DNS

    :Return: bool representing the ability to access internet
    '''

    info('Testing internet access')
    sys('ping -c4 8.8.8.8 > pingInfo')
    sys('sudo chmod 755 pingInfo')
    with open('pingInfo', 'r') as file:
        try:
            content = file.read().split('\n')[7].split(' ')[3]
            if int(content) > 0:  # As long as one ICMP ping was received
                info('Internet access confirmed')
                play('gotone', user)
                return True
            else:
                info('No internet access', kind='bad')
                return False

        except Exception as e:  # Something has gone wrong. Report failure
            info('Error: %s' % str(e))  # These failures don't tend to be an issue
            return False


# ============ START ============
if __name__ == '__main__':

    # 1. Ensure Root
    if not usertype() == 0:
        info('Must run script as root', kind='bad')
        play('root')
        exit(1)  # Report failure

    # 2. Determine who's non-root
    user = getNonRoot()

    # 3. Run main loop
    ct = 1
    while True:
        play('gestart', user)
        scan(user)
        print(f'[white bold]Round: [/white bold][bold red]{str(ct)}[/bold red]')
        play('3sec', user)
        sleep(3)
        ct += 1
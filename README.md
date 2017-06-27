# Deauthenticator
This python script will bring wifi networks around you to a halt.

### About ###
**jam.py** does not need to authenticate with any AP in order to DOS the clients and the AP.
It scans for MAC adresses, then checks which AP has the most clients so it switches the interface
channel to that of the AP and scans again on that channel. Deauthentication packets are then
sent to all MAC addresses on that channel in multiple threads.

### Installation ####
This should be executed on linux with python and Aircrack-ng installed.
It also makes use of screen.

### Further Information ###
This was tested on my Raspberry pi 2B  raspbian wheezy running on battries
inside my bag whilst standing beside....  clients - it was fun. The code
Contains lines that blink a RGB LED attached to my RPi in order to
indicate what it's doing.

Note that the script is still being developed.


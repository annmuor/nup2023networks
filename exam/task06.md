- You're given a binary
  for [Linux](task06.linux)/[OSX M1/M2](task06.armmac)/[OSX Intel](task06.x64mac)/[Windows](task06.exe) that listens TCP
  port 4888 with SNI-enabled SSL/TLS.
- Your goal is to connect to the server with correct parameters and send "getflag" command.
- Look into console output to get the idea why it's not working. Trial and error are expected.
  **P.S. Do chmod 755 for Linux/OSX and [disable Gatekeeper](https://disable-gatekeeper.github.io/) for OSX.**
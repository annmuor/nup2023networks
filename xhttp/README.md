## XHTTP

This is a bit odd HTTP server that likes 'X' letter as much as [Mr. X](https://x.com/x) do.
So for each byte incoming, the server subtracts the value of 'X' from the byte, and for each byte outgoing, the server
adds the value
of 'X' to the byte.

* If the incoming byte is less than 'X' - nothing is subtracted.
* If the outgoing byte is equal or more than \[2'X' - 'X'%10\] - nothing is added.
* For example, if you want a server to read a ' ' - you must send it 'x'
* For example, the server sends you 'x', it meant to be ' '

### Goal

You must browse the website behind this server and find the **flag**.
It's not that easy to do it **manually**, so if I were you, I would write a proxy server for my web browser.

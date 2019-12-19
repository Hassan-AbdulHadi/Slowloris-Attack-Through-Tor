# Multi-threaded Slowloris-attack through Tor
Every penetration-testing tool, script and even device out there can be used both ways (good / evil), I hope no one uses this to harm people.
## What is Slowloris?
Slowloris is an application layer denial of service attack that target -mostly- blocking servers such as apache.
To get a better understanding of this attack read this fine article on [Wikipedia]( https://en.wikipedia.org/wiki/Slowloris_(computer_security)) .
###### How does it really work?
An http request message consists of three things:
- Request line, which contains http method, the URL and http version (e.g. GET /index.php HTTP/1.1) followed by a carriage return and line feed (\r\n). 
- Request headers, which are in a form of key: value pairs (e.g. User-Agent: Mozilla/5.0) each one must be followed by a carriage return and line feed.
- an optional body.

The http headers field must end with a blank line (\ r \ n \ r \ n), but what if we didn't send the blank line? What would the server do? The server would keep the connection opened until its time out. The essence of slowloris attack is to keep the connection open by never sending the blank line, instead we keep sending fake headers and very slowly.
## Motivation:
Why would anyone think of launching such an attack through Tor network? To override Anti-loris mostly, these tools/modules add restrictions to IPs limiting their concurrent requests to a specific number.
## Tor network:
There are various ways by which you can direct your traffic through Tor, One of them is to use Tor's SOCKS proxy. The default installation of Tor comes with a loopback SOCKS proxy that usually listens on port 9050.
## launching Tor's SOCKS proxy:
### Linux:
Go to Tor's default installation directory:

/installation_directory/Browser/TorBrowser/Tor

Run the tor file
Type the following command in your shell
```
./tor
```
If you encounter an error with loading shared libraries copy the shared libraries (files with "lib" prefix and .os extension) in that directory to the /usr/lib directory and run the fowllowing command:
```
ldconfig -v -n /usr/lib 
```
Run the following command in your shell:
```
netstat -l | grep -w LISTEN
```
Or 
```
netstat -l | grep -w 9050
```
You will see a process that listens on port 9050
### Windows:
Go to Tor's default installation directory:

\installation_directory\Browser\TorBrowser\Tor

Run the tor.exe process 
It is worth mentioning that tor.exe is a daemon process so you probably won't see anything appears on your screen.

Run the following command in your CMD 
```
netstat -ao | grep -w LISTENING
```
Or 
```
netstat -ao | grep -w 9050
```
You will see a process that listens on port 9050 

## Usage:
- slowloris.py -A|attack <ip4> <port> [(-L|lines) <X>]
- slowloris.py -C|check <ip4> <port>
- slowloris.py -A|attack -D <domain> <port> [(L|lines) <X>]
- slowloris.py -C|check -D <domain> <port>
- slowloris.py -h|--help
                    
###### Commands & Options:

- -A|attack ..... Launch the actual attack
- -C|check ..... Check what kind of servers you are dealing with
- -D ..... To indicate that you are using a domain name
- -L|lines ..... Number of attack lines (default:500)
            
###### Examples:
- slowloris.py -A 192.168.0.0 80 -L 5000
- slowloris.py -A -D www.example.com 80 -L 5000
- slowloris.py -C 192.168.0.0 80 
- slowloris.py -C -D www.example.com 80

## Other things:
-	Every 5 seconds a new attack line will be created, if you wish to change this behavior go to line 251 in the script
-	If your Tor's SOCKS proxy –for some reason- doesn’t listen on port 9050 go to line 9 in the script 

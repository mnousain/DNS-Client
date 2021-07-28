# My-DNS-Client
This program is a DNS client that can query existing DNS servers for a domain name to IP address translation. This client reads the given ```host-name``` provided by a user and prepares a query message which adheres to DNS protocol specifications. The client creates a UDP socket connection to the server and sends the DNS query message. The client will receive a response from the DNS server. This response will be processed based on the format of the DNS response message and will extract necessary information and display it to the user on the command line.

## How To Run
To compile and run the program:

```my-dns-client.py host-name```

where ```host-name``` is a command line argument

Example:

```my-dns-client.py twitch.tv```

# Bonus question 1: Expires header implementation
# To implement the detection of the expires header i made use of a function i made in the base assignment file proxy.py called extract headers.
# This function returns a dictionary of header keys and directive values.
# Using this function, i can simply check if expires is a key
# However, I needed to implement this check after the max-age check as max-age always takes precendent over the expires. 
# After I have the value in the expires header I transform it into a timestamp so i can compare it to the current time. To do this I imported the email utils library.
# /-------------------------------/
# Bonus question 2: Pre fetching files implementation

# /-------------------------------/
# Bonus question 3: 
# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re
import time
#email for time stamps for expirations
import email.utils
#re for finding links inside html content
# FUNCTION FOR EXTRACTING HEADERS
def extract_headers(response: str):
  headers = {}
  headerSection, _, _ = response.partition("\n\n") #split the headers from the body
  for line in headerSection.split("\n"): 
    if ": " in line:
      key, value = line.split(": ", 1)
      key = key.lower()
      headers[key] = value
  return headers

#FUNCTION FOR EXTRACTING DIRECTIVES IN CASE OF MULTIPLE DIRECTIVES SUCH AS CACHE_CONTROL 
def extract_directives(header: str):
  directives = header.split(", ")
  return directives
# 1MB buffer size
BUFFER_SIZE = 1000000

#BONUS QUESTION 2 FUNCTIONs FOR EXTRACTING LINKS WITHIN THE HTML AND FETCHING THEM
def extract_links(response: str, base_url: str):
  links = set()
  matches = re.findall('(?:href|src)="([^"]+)"', response) #using regex to capture links inside quotes
  for match in matches:
    if not match.startswith("http"):
      match = base_url + match
    links.add(match)
  return links

def pre_fetch_links(links: set, server_socket: socket):
    for link in links:
      print(f"Pre-Fetching: {link}")
      request = f"GET {link} HTTP/1.1\r\nHost: localhost:8080"
      try:
        server_socket.sendall(request.encode())
      except socket.error:
        print ('Pre-fetch forward request to origin failed')
        sys.exit()
      response = server_socket.recv(BUFFER_SIZE)

def cache_response(response: bytes, cache_location: str):
  cacheDir, file = os.path.split(cache_location)
  print ('cached directory ' + cacheDir)
  if not os.path.exists(cacheDir):
    os.makedirs(cacheDir)
  cacheFile = open(cache_location, 'wb')
  # Save origin server response in the cache file
  # ~~~~ INSERT CODE ~~~~
  cacheFile.write(response)
  # ~~~~ END CODE INSERT ~~~~
  cacheFile.close()
  print ('cache file closed')
      
# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Create a server socket, bind it to a port and start listening
try:
  # Create a server socket
  # ~~~~ INSERT CODE ~~~~
  serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  # ~~~~ END CODE INSERT ~~~~
  print ('Created socket')
except:
  print ('Failed to create socket')
  sys.exit()

try:
  # Bind the the server socket to a host and port
  # ~~~~ INSERT CODE ~~~~
  serverSocket.bind((proxyHost, proxyPort))
  # ~~~~ END CODE INSERT ~~~~
  print ('Port is bound')
except:
  print('Port is already in use')
  sys.exit()

try:
  # Listen on the server socket
  # ~~~~ INSERT CODE ~~~~
  serverSocket.listen()
  # ~~~~ END CODE INSERT ~~~~
  print ('Listening to socket')
except:
  print ('Failed to listen')
  sys.exit()

# continuously accept connections
while True:
  print ('Waiting for connection...')
  clientSocket = None

  # Accept connection from client and store in the clientSocket
  try:
    # ~~~~ INSERT CODE ~~~~
    clientSocket, addr = serverSocket.accept()
    # ~~~~ END CODE INSERT ~~~~
    print ('Received a connection')
  except:
    print ('Failed to accept connection')
    sys.exit()

  # Get HTTP request from client
  # and store it in the variable: message_bytes
  # ~~~~ INSERT CODE ~~~~
  message_bytes = clientSocket.recv(BUFFER_SIZE)
  # ~~~~ END CODE INSERT ~~~~
  message = message_bytes.decode('utf-8')
  print ('Received request:')
  print ('< ' + message)

  # Extract the method, URI and version of the HTTP client request 
  requestParts = message.split()
  method = requestParts[0]
  URI = requestParts[1]
  version = requestParts[2]

  print ('Method:\t\t' + method)
  print ('URI:\t\t' + URI)
  print ('Version:\t' + version)
  print ('')

  # Get the requested resource from URI
  # Remove http protocol from the URI
  URI = re.sub('^(/?)http(s?)://', '', URI, count=1)

  # Remove parent directory changes - security
  URI = URI.replace('/..', '')

  # Split hostname from resource name
  resourceParts = URI.split('/', 1)
  hostname = resourceParts[0]
  resource = '/'

  if len(resourceParts) == 2:
    # Resource is absolute URI with hostname and resource
    resource = resource + resourceParts[1]

  print ('Requested Resource:\t' + resource)
  # Check if resource is in cache
  try:
    cacheLocation = './' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation = cacheLocation + 'default'

    print ('Cache location:\t\t' + cacheLocation)

    fileExists = os.path.isfile(cacheLocation)
    
    # Check wether the file is currently in the cache
    cacheFile = open(cacheLocation, "r")
    cacheData = cacheFile.readlines()
    print ('Cache hit! Loading from cache file: ' + cacheLocation)
    # ProxyServer finds a cache hit
    # Send back response to client 
    # ~~~~ INSERT CODE ~~~~
    headers = extract_headers(''.join(cacheData)) # get headers from response to determine caching rules
    file_mtime = os.path.getmtime(cacheLocation)
    current_time = time.time()
    
    #check if cache control is a header
    max_age_present = False
    if "cache-control" in headers:
      ccdirectives = extract_directives(headers["cache-control"])
      maxAge = None
      for directive in ccdirectives:
        if directive.startswith("max-age="):
          maxAge = int(directive.split("=")[1])
          max_age_present = True
        if directive.startswith("no-cache"):
          print("Revalidation required: contacting origin")
          raise err
      if maxAge is not None and (current_time - file_mtime > maxAge):
        print(f'Cache expired! Fetching a fresh copy (stale by {current_time - file_mtime - maxAge} sec)')
        raise err
  
  #BONUS: check if expires is in the headers
    if "expires" in headers and not max_age_present:
      expiration = email.utils.parsedate_to_datetime(''.join(headers["expires"]))
      expires_timestamp = expiration.timestamp()
      if expires_timestamp < current_time:
        print("Cache File expired")
        raise err
    cacheMessage = ''.join(cacheData).encode()
    clientSocket.sendall(cacheMessage)
    cacheData = ''.join(cacheData) 
    # ~~~~ END CODE INSERT ~~~~
    cacheFile.close()
    print ('Sent to the client:')
    print ('> ' + cacheData)
  except:
    # cache miss.  Get resource from origin server
    originServerSocket = None
    # Create a socket to connect to origin server
    # and store in originServerSocket
    # ~~~~ INSERT CODE ~~~~
    originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ~~~~ END CODE INSERT ~~~~
    print ('Connecting to:\t\t' + hostname + '\n')
    try:
      # Get the IP address for a hostname
      address = socket.gethostbyname(hostname)
      # Connect to the origin server
      # ~~~~ INSERT CODE ~~~~
      originServerSocket.connect((hostname, 80))
      # ~~~~ END CODE INSERT ~~~~
      print ('Connected to origin Server')

      originServerRequest = ''
      originServerRequestHeader = ''
      # Create origin server request line and headers to send
      # and store in originServerRequestHeader and originServerRequest
      # originServerRequest is the first line in the request and
      # originServerRequestHeader is the second line in the request
      # ~~~~ INSERT CODE ~~~~
      originServerRequest = method + " " + resource + " " + version
      originServerRequestHeader = "Host: " + hostname
      # ~~~~ END CODE INSERT ~~~~

      # Construct the request to send to the origin server
      request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'

      # Request the web resource from origin server
      print ('Forwarding request to origin server:')
      for line in request.split('\r\n'):
        print ('> ' + line)

      try:
        originServerSocket.sendall(request.encode())
      except socket.error:
        print ('Forward request to origin failed')
        sys.exit()

      print('Request sent to origin server\n')

      # Get the response from the origin server
      # ~~~~ INSERT CODE ~~~~
      originResponse = originServerSocket.recv(BUFFER_SIZE)
      # ~~~~ END CODE INSERT ~~~~

      # Send the response to the client
      # ~~~~ INSERT CODE ~~~~
      clientSocket.sendall(originResponse)
      originResponseTEXT = originResponse.decode()
      #BONUS: CHECK FOR LINKS TO PRE CACHE
      links = extract_links(originResponseTEXT, request)
      pre_fetch_links(links, originServerSocket)
      #check if the response is cachable  
      cachable = True
      #1. Check response code for 302 (dont cache)
      responseLines = originResponseTEXT.split('\r\n')
      statusLine = responseLines[0]
      statusCode = statusLine.split()[1]
      if statusCode == "302":
        cachable = False
        print("302 Response: Will not cache unless directed to by cache-control headers such as max-age")
      headers = extract_headers(originResponseTEXT)
    
      if "cache-control" in headers:
        directives = extract_directives(headers["cache-control"])
        maxAge = None
        for directive in directives:
          if directive.startswith("max-age="):
            print("Response has max-age: Will cache.")
            cachable = True
          if directive.startswith("no-store"):
            print("Response includes no-store: Will not cache.")
            cachable = False
      # ~~~~ END CODE INSERT ~~~~
      if cachable:
        # Create a new file in the cache for the requested file.
        cacheDir, file = os.path.split(cacheLocation)
        print ('cached directory ' + cacheDir)
        if not os.path.exists(cacheDir):
          os.makedirs(cacheDir)
        cacheFile = open(cacheLocation, 'wb')

        # Save origin server response in the cache file
        # ~~~~ INSERT CODE ~~~~
        cacheFile.write(originResponse)
        # ~~~~ END CODE INSERT ~~~~
        cacheFile.close()
        print ('cache file closed')

      # finished communicating with origin server - shutdown socket writes
      print ('origin response received. Closing sockets')
      originServerSocket.close()
       
      clientSocket.shutdown(socket.SHUT_WR)
      print ('client socket shutdown for writing')
    except OSError as err:
      print ('origin server request failed. ' + err.strerror)

  try:
    clientSocket.close()
  except:
    print ('Failed to close client socket')

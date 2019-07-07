
import json
import socket
import copy
import signal
import sys
import threading
import time
import datetime
from time import gmtime, strftime
import logging 
from bs4 import BeautifulSoup
import collections



class LRUCache:
    def __init__(self, capacity):
        self.capacity = capacity
        self.cache = collections.OrderedDict()

    def __getitem__(self, key):
        try:
            value = self.cache.pop(key)
            self.cache[key] = value
            return value
        except KeyError:
            return -1

    def __setitem__(self, key, value):
        try:
            self.cache.pop(key)
        except KeyError:
            if len(self.cache) >= self.capacity:
                self.cache.popitem(last=False)
        self.cache[key] = value




class proxy_server:

    def __init__(self):
        self.users = {}
        # config file
        with open("config.json", "r") as read_file:
            self.config = json.load(read_file)
        self.is_logging_enabled = False
        if(self.config['logging']['enable'] == True):
            self.is_logging_enabled = True
        self.is_cache_enabled = False
        if(self.config['caching']['enable'] == True):
            self.cache_size = self.config['caching']['size']
            self.is_cache_enabled = True
            self.cache = LRUCache(self.cache_size)
        self.is_privacy_enabled = False
        if(self.config['privacy']['enable'] == True):
            self.is_privacy_enabled = True
            self.user_agent = self.config['privacy']['userAgent']
        self.is_restriction_enabled = False
        if(self.config['restriction']['enable'] == True):
            self.is_restriction_enabled = True
            self.targets = self.config['restriction']['targets']
        self.is_HTTPInjection_enabled = False
        if(self.config['HTTPInjection']['enable'] == True):
            self.is_HTTPInjection_enabled = True
            self.HTTPInjection = self.config['HTTPInjection']['post']['body']
        self.accounting = self.config['accounting']['users']
        # logging
        logging.basicConfig(filename=self.config['logging']['logFile'], 
                    format='[%(asctime)s] %(message)s',
                    datefmt='%d/%b/%Y:%H:%M:%S', 
                    filemode='a+')
        self.logger=logging.getLogger() 
        self.logger.setLevel(logging.DEBUG) 
        if(self.is_logging_enabled):
            self.logger.info("Proxy launched") 
        # Create a TCP socket
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if(self.is_logging_enabled):
            self.logger.info("Creating server socket...")
        # Re-use the socket
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # bind the socket to a public host, and a port   
        self.serverSocket.bind(('127.0.0.1', self.config['port']))
        if(self.is_logging_enabled):
            self.logger.info("Binding socket to port {}...".format(self.config['port']))
        self.serverSocket.listen(10) # become a server socket
        self.__clients = {}
        # Shutdown on Ctrl+C
        signal.signal(signal.SIGINT, self.shutdown)


    def shutdown(self, sig, frame):
        self.serverSocket.close()
        sys.exit(0)


    def create_str_for_logging_header(self, header):
        pre_log = '\n----------------------------------------------------------------------\n'
        post_log = '----------------------------------------------------------------------'
        log = header
        log = pre_log + log + post_log
        return log

 
    def split_http_msg(self, text):
        result = []
        words = text.split('\r\n')
        for word in words:
            temp = word.split()
            result.append(temp)
        return result


    def change_hostname(self, text):
        text[0][1] = text[0][1][len(text[1][1])+7:]
        return text


    def delete_proxy_from_request(self, text):
        for i in range(len(text)):
            if(len(text[i]) > 0):
                if(text[i][0] == "Proxy-Connection:"):
                    text.pop(i)
                    break
        return text


    def change_accepted_encoding(self, text):
        for i in range(len(text)):
            if(len(text[i]) > 0):
                if(text[i][0] == "Accept-Encoding:"):
                    text[i][1] = "utf-8"
                    for j in range(len(text[i])-2):
                        text[i].pop(2)
                    break
        return text


    def change_request_to_HTTP_1_0(self, text):
        text[0][2] = text[0][2][:-1] + "0"
        return text


    def http_request_privacy(self, text):
        for i in range(len(text)):
            if(len(text[i]) > 0):
                if(text[i][0] == "User-Agent:"):
                    temp = self.user_agent.split()
                    for j in range(len(temp)):
                        text[i][j+1] = temp[j]
        return text


    def list_to_http_request(self, text):
        for i in range(len(text)):
            text[i] = ' '.join(text[i])
        string = '\r\n'.join(text)
        b = string.encode('utf-8')
        return b


    def is_no_cache(self, text):
        for i in range(len(text)):
            if(len(text[i]) > 0):
                if(text[i][0] == "pragma:" or text[i][0] == "Pragma:"):
                    if(text[i][1] == "no-cache"):
                        return True
        return False


    def response_expire(self, data):
        text = self.split_http_msg(data)
        for i in range(len(text)):
            if(len(text[i]) > 0):
                if(text[i][0] == "expires:" or text[i][0] == "Expires:"):
                    date = ""
                    for j in range(len(text[i])-1):
                        date += text[i][j+1] + " "
                    datetime_object = datetime.datetime.strptime(date[:-1], '%a, %d %b %Y %H:%M:%S %Z')
                    return datetime_object
        return ""


    def cache_response(self, data, data_request):
        expiration = self.response_expire(data[:data.find(b'\r\n\r\n')+2].decode('utf-8'))
        if(expiration != ""):
            self.cache[data_request] = { "response":data, "expire_date":expiration }
        else:
            self.cache[data_request] = { "response":data, "expire_date":datetime.datetime.now() }


    def check_cache(self, data_request):
        if self.cache[data_request] != -1:
            present = datetime.datetime.now()
            if(present < self.cache[data_request]['expire_date']):
                return self.cache[data_request]['response'], False
            else:
                return b'', True
        else:
            return b'', False


    def add_header(self, data, header):
        text = self.split_http_msg(data[:data.find(b'\r\n\r\n')+4].decode("utf-8"))
        text.insert(len(text)-2, list(header.split()))
        text = self.list_to_http_request(text)
        return text


    def notify_admin(self, HOST, data):
        msg = HOST.encode()+b'\r\n'+data
        endmsg = "\r\n.\r\n"
        mailserver = ("mail.ut.ac.ir", 25)
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientSocket.connect(mailserver)
        recv = clientSocket.recv(1024)
        recv = recv.decode()
        heloCommand = 'ehlo mail.ut.ac.ir\r\n'
        clientSocket.send(heloCommand.encode())
        recv1 = clientSocket.recv(1024)
        #add username and password for your email in base64 here
        base64_str = "" + "\r\n" + ""
        authMsg = "AUTH LOGIN\r\n".encode()+base64_str.encode()+"\r\n".encode()
        clientSocket.send(authMsg)
        recv_auth = clientSocket.recv(1024)
        #add sending email address here
        mailFrom = "MAIL FROM: <@ut.ac.ir>\r\n"
        clientSocket.send(mailFrom.encode())
        recv2 = clientSocket.recv(1024)
        #add receving email here
        rcptTo = "RCPT TO: <@yahoo.com>\r\n"
        clientSocket.send(rcptTo.encode())
        recv3 = clientSocket.recv(1024)
        data = "DATA\r\n"
        clientSocket.send(data.encode())
        recv4 = clientSocket.recv(1024)
        subject = "Subject: Restriction msg\r\n\r\n" 
        clientSocket.send(subject.encode())
        clientSocket.send(msg)
        clientSocket.send(endmsg.encode())
        recv_msg = clientSocket.recv(1024)
        quit = "QUIT\r\n"
        clientSocket.send(quit.encode())
        recv5 = clientSocket.recv(1024)
        clientSocket.close()


    def check_Host_for_restriction(self, HOST):
        for i in range(len(self.targets)):
            if(HOST == self.targets[i]['URL']):
                if(self.targets[i]['notify']):
                    return True, True
                return True, False
        return False, False


    def is_index_file(self, data_request):
        text = self.split_http_msg(data_request.decode('utf-8'))
        if(len(text) > 0 and len(text[0]) > 1):
            if(text[0][1] == "/"):
                return True
        return False


    def nav_HTTPInjection(self, data, HTTPInjection_text):
        soup = BeautifulSoup(data)
        new_div = soup.new_tag('div')
        new_div.string=HTTPInjection_text
        soup.html.insert(0, new_div)
        return str(soup).encode('utf-8')


    def parse_request(self, data):
        data = self.split_http_msg(data[:data.find(b'\r\n\r\n')+4].decode("utf-8"))
        data_copy = copy.deepcopy(data)
        data = self.change_hostname(data)
        data = self.delete_proxy_from_request(data)
        data = self.change_accepted_encoding(data)
        data = self.change_request_to_HTTP_1_0(data)
        if(self.is_privacy_enabled):
            data = self.http_request_privacy(data)
        data = self.list_to_http_request(data)
        HOST = data_copy[1][1]  # The server's hostname or IP address
        return HOST, 80, data


    def parse_response(self, data, data_request):
        data_header = self.split_http_msg(data[:data.find(b'\r\n\r\n')+4].decode("utf-8"))
        is_no_cache = self.is_no_cache(data_header)
        if(not is_no_cache):
            self.cache_response(data, data_request)
        return data_header[0][1]


    def check_user_accounting(self, client_address):
        user_has_access = False
        index = -1
        for i in range(len(self.accounting)):
            if(client_address == self.accounting[i]['IP']):
                user_has_access = True
                index = i
                break
        if(user_has_access):
            if((int(self.accounting[index]['volume']) - self.users[client_address]) > 0):
                return ""
            else:
                return "You are past your traffic volume limit"
        else:
            return "You are not allowed access"


    def update_accounting(self, client_address, len_data):
        self.users[client_address] += len_data


    def proxy_thread(self, clientSocket, client_address):
        if(self.is_logging_enabled):
            self.logger.info("Accepted a request from client!")

        data_request = clientSocket.recv(10240)
        if not data_request:
            return

        if(self.is_logging_enabled):
            self.logger.info("Client sent request to proxy with headers:")
        if(self.is_logging_enabled):
            self.logger.info("connect to [127.0.0.1] from localhost [127.0.0.1] {}".format(client_address))
        if(self.is_logging_enabled):
            self.logger.info(self.create_str_for_logging_header(data_request[:data_request.find(b'\r\n\r\n')+4].decode('utf-8')[:-2]))

        HOST, PORT, data_request = self.parse_request(data_request)
        is_restricted, is_notify = self.check_Host_for_restriction(HOST)
        response, check_if_modified_since = self.check_cache(data_request)
        response_cached = False
        if(response != b''):
            response_cached = True
        else:
            if check_if_modified_since:
                expire_date = strftime('%a, %d %b %Y %H:%M:%S %Z', self.cache[data_request]['expire_date'].timetuple())
                check_if_modified_since_header = "If-Modified-Since: " + expire_date + " GMT"
        if not response_cached:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                if(check_if_modified_since):
                    data_request = self.add_header(data_request, check_if_modified_since_header)
                s2.connect((HOST, PORT))
                
                if(self.is_logging_enabled):
                    self.logger.info("Proxy opening connection to server {} [{}]... Connection opened.".format(HOST, socket.gethostbyname(HOST)))
                accounting_msg = self.check_user_accounting(client_address[0])
                if(accounting_msg == ""):
                    s2.sendall(data_request)
                    if(self.is_logging_enabled):
                        self.logger.info("Proxy sent request to server with headers:")
                    if(self.is_logging_enabled):
                        self.logger.info(self.create_str_for_logging_header(data_request[:data_request.find(b'\r\n\r\n')+4].decode('utf-8')[:-2]))
                    
                    data = b''
                    while 1:
                        data_temp = s2.recv(1024)
                        if (len(data_temp) > 0):
                            data += data_temp
                        else:
                            break
                    if(data != b''):
                        self.update_accounting(client_address[0], len(data))
                        status_code = self.parse_response(data, data_request)
                    
                    if(self.is_logging_enabled):
                        self.logger.info("Server sent response to proxy with headers:")
                    if(self.is_logging_enabled):
                        self.logger.info(self.create_str_for_logging_header(data[:data.find(b'\r\n\r\n')+2].decode('utf-8')))
                    
                s2.close()
        else:
            if(self.is_logging_enabled):
                self.logger.info("Proxy sent cached response to client")
            data = response
        if(accounting_msg == ""):
            if(check_if_modified_since and status_code == "304"):
                if(self.is_logging_enabled):
                    self.logger.info("Cached response han not been modified since")
                data = self.cache[data_request]['response']
                self.cache_response(data, data_request)
            if(check_if_modified_since and status_code == "200"):
                if(self.is_logging_enabled):
                    self.logger.info("Cached response got updated")
                self.cache_response(data, data_request)
            if(self.is_HTTPInjection_enabled):
                if(self.is_index_file(data_request)):
                    if(self.is_logging_enabled):
                        self.logger.info("Proxy added navbar in HTML")
                    data = self.nav_HTTPInjection(data[data.find(b'\r\n\r\n')+4:].decode('utf-8'), self.HTTPInjection)
        if(accounting_msg != ""):
            data = accounting_msg.encode('utf-8')
        if(is_restricted):
            if(self.is_logging_enabled):
                self.logger.info("This site is RESTRICTED")
            if(is_notify):
                if(self.is_logging_enabled):
                    self.logger.info("Proxy is notifing the admin")
                self.notify_admin(HOST, data)
            data = b'This site is RESTRICTED!!!'
        clientSocket.send(data)
        
        if(self.is_logging_enabled):
            self.logger.info("Proxy sent response to client with headers:")
        if(self.is_logging_enabled):
            self.logger.info(self.create_str_for_logging_header(data[:data.find(b'\r\n\r\n')+2].decode('utf-8')))
        
        clientSocket.close()


    def run_proxy_server(self):
        while True:
            if(self.is_logging_enabled):
                self.logger.info("Listening for incoming requests...")
            
            (clientSocket, client_address) = self.serverSocket.accept() 

            if client_address[0] not in self.users:
                self.users[client_address[0]] = 0

            if(self.is_logging_enabled):
                self.logger.info("Accepted a request from client!")
            
            d = threading.Thread(name=client_address, target = self.proxy_thread, args=(clientSocket, client_address))
            d.setDaemon(True)
            d.start()



ps = proxy_server()
ps.run_proxy_server()





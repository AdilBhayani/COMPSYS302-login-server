"""
COMPSYS302 - Sofware Design
Author: Adil Bhayani
This program uses the CherryPy web server to connect to implement 
the functionality of the login server based social media network.

This files contains all the cheryypy exposed functions alongside the general
helper functions to call other clients APIs.

This file is the main file and interacts with the database file through the
DatabaseManager.py file. Similarly it also implements encryption, decryption and
hashing through the SecurityManager.py file. The dynamic part of the client side html
for each of the pages is generated through the HtmlGenerator.py file which is then
inserted into a static page template.
"""

# The address we listen for connections on
listen_ip = "0.0.0.0"
listen_port = 10001

#General python built in system imports
import cherrypy
import os, os.path
import hashlib
import urllib2
import binascii
import json
import socket
import sched, time
import markdown
import base64
import codecs
import copy
import sys, traceback
import threading
import hmac, struct
import string, random

#Imports from files that have been created specifically for this project
from ResumableTimer import ResumableTimer
import HtmlGenerator
import DatabaseManager
import SecurityManager

#Name of the database file
DB_STRING = "my_db.db"

class MainApp(object):
    """
    #The MainApp is the main class of the project.
    """
    
    def __init__(self):
        """
        Initialises the Database and varaibles.
        """
        try:
            user_list = self.server_list_Users() #Get the user_list
            DatabaseManager.setup_db(user_list) #Pass it to the DatabaseManager to initialise database
        except:
            pass
        #The following is still initialised even when db initialisation fails
        finally:
            self.loggedIn = False
            self.firstLogin = True
            self.autoReport = False
            self.username = None
            self.hashPass = None
            self.status = "Online"
            self.reportTimer = ResumableTimer(45, self.server_report) #This is the timer responsible for reporting ever 45 seconds
            self.reportTimer.start()
            self.reportTimer.pause()
	
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """
        If they try to navigate somewhere we don't know, catch it here and display 404 page
        """
        Page = file('default.html') #The default page, given when we don't recognise where the request is for
        cherrypy.response.status = 404
        return Page
		
	
    @cherrypy.expose
    def index(self):
        """
        The root page redirects to login
        """
        raise cherrypy.HTTPRedirect('/login')


    @cherrypy.expose
    def login(self):
        """
        #The login page.
        """
        #If the user is logged in they don't need  to signin again.
        if self.loggedIn == True:
            raise cherrypy.HTTPRedirect('/home') #Redirect to home page
        else:
            Page = file('login.html') #Otherwise use the file template to display the page
            return Page


    @cherrypy.expose
    def signin(self, username=None, password=None):
        """
        This page is called by the signin page when the user fills in their login credentials.
        """
        error = self.authoriseUserLogin(username,password) #Check their name and password and send them either to the main page, or back to the main login screen.
        if (error == 0):
            self.username = username
            raise cherrypy.HTTPRedirect('/login_page_2') #Redirect to home on successful login
        else:
            self.loggedIn = False
            self.username = None
            self.firstLogin = True
            raise cherrypy.HTTPRedirect('/login') #Otherwise let them try login again

    @cherrypy.expose
    def login_page_2(self):
        """
        This page is shown once the user passes the first authentication stage.

        """
        if self.loggedIn == True:
            raise cherrypy.HTTPRedirect('/home') #Redirect to home page
        else:
            if self.username is not None:
                secret = DatabaseManager.get_secret_key(self.username)
                if secret is None:
                    secret = self.get_secret(self.username)
                    DatabaseManager.save_secret_key(secret,self.username)
                    link = self.get_barcode_image(self.username,secret)
                    page = open('second_factor.html').read().format(secret_link = link)
                else:
                    page = open('second_factor_empty.html').read().format()
                return page
            else:
                raise cherrypy.HTTPRedirect('/login')


    @cherrypy.expose
    def verify_two_factor(self,the_code=None):
        """
        This page is returned when the user passes the first stage of authentication.

        Part of 2 factor authentication.
        """

        if self.loggedIn and self.username != None:
            raise cherrypy.HTTPRedirect('/home')
        elif the_code != None:
            secret = DatabaseManager.get_secret_key(self.username)
            totp = self.get_totp_token(secret)
            list_dict = self.server_get_List()#Call the get list method of the login server
            try:
                int(the_code)
            except:
                self.loggedIn = False
                self.username = None
                self.firstLogin = True
                raise cherrypy.HTTPRedirect('/login')
            if totp == int(the_code):
                DatabaseManager.update_user_table(list_dict)#Update the db with this list
                self.loggedIn = True
                print "Logged in successfully!" #Display on terminal that user has logged in successfully
                the_thread = threading.Thread(target=self.retrieve_messages) #Sepearate daemon thread to call retrieveMessages from online users
                the_thread.daemon = True
                the_thread.start()
                DatabaseManager.save_status("Online", self.username)
                raise cherrypy.HTTPRedirect('/home')
            else:
                self.loggedIn = False
                self.username = None
                self.firstLogin = True
                raise cherrypy.HTTPRedirect('/login')


        else:
            raise cherrypy.HTTPRedirect('/login')


    @cherrypy.expose
    def home(self,username = None):
        """
        The Home page which is only shown when the user is logged in.

        This function calls HtmlGenerator to get the dynamic html code and then
        adds it to the home page template.
        """
        if self.loggedIn:
            if username == None:
                username = self.username
            usersHtml = HtmlGenerator.get_users_html(username)
            messagesHtml = HtmlGenerator.get_messages_html(self.username,username)
            name = codecs.open("home.html", "r", "utf-8").read()
            page = name.format(status = self.status, loggedUsername = cherrypy.session['username'], userHtml= usersHtml, messagesHtml = messagesHtml, username = username, script = "{ element: document.getElementById('theMessage'), spellChecker: false, }")
            return page
        else:
            self.loggedIn = False
            self.username = None
            self.firstLogin = True
            raise cherrypy.HTTPRedirect("login")

    @cherrypy.expose
    def edit_profile(self):
        """
        Shows the user the page to edit their profile.
        """
        if self.loggedIn:
            page = open('edit_profile.html').read().format(status = self.status, loggedUsername = cherrypy.session['username'])
            return page
        else:
            self.loggedIn = False
            self.username = None
            self.firstLogin = True
            raise cherrypy.HTTPRedirect("login") #Redirects to login if not logged in

    @cherrypy.expose
    def view_profiles(self, username_to_view = None):
        """
        Displays the view_profiles page.

        This function uses the username_to_view parameter to display thats users profile.
        """
        if self.loggedIn:
            if username_to_view == None:
                username_to_view = self.username
            userDetails = self.get_user_details(username_to_view)
            if userDetails == []:
                page = open('view_profiles_default.html').read().format(status = self.status, loggedUsername=cherrypy.session['username'])
            else:
                page = open('view_profiles.html').read().format(status = self.status, loggedUsername=cherrypy.session['username'], fullname=userDetails[2], location=userDetails[5], username=userDetails[1], position=userDetails[3], image_url=userDetails[6], description=userDetails[4])
            return page
        else:
            self.loggedIn = False
            self.username = None
            self.firstLogin = True
            raise cherrypy.HTTPRedirect("login") #Redirects to login page if not logged in
        
    @cherrypy.expose
    def settings(self):
        """
        Displays the settings page.
        """
        if self.loggedIn:
            page = open('settings.html').read().format(status = self.status,loggedUsername = cherrypy.session['username'])
            return page
        else:
            self.loggedIn = False
            self.username = None
            self.firstLogin = True
            raise cherrypy.HTTPRedirect("login") #Redirects to login page if not logged in

    @cherrypy.expose
    def logout(self):
        """
        Logs the user out of their session.
        """
        try:
            if self.loggedIn:
                response = self.server_logoff() #Calls a function to log user off
                if response == "0, Logged off successfully":
                    self.loggedIn = False
                    self.firstLogin = True
                    cherrypy.session['username'] = None
                    cherrypy.session['hashPass'] = None
                    self.reportTimer.pause() #Stops the reporting timer
                    print "Logged off successfully!"
                else:
                    pass #Need to show user that they failed to log off here
        except:
            print "Internal Error"
        finally:
            raise cherrypy.HTTPRedirect("login") #Redirects to login page again

    @cherrypy.expose
    def shutdown(self):
        """
        Stops the cherrypy engine
        """
        self.loggedIn = False
        self.reportTimer.pause()
        cherrypy.engine.exit()

    @cherrypy.expose
    def listAPI(self):
        """
        Returns this clients listAPI to requestor.
        """
        return ('Available APIs:\n/listAPI\n/ping [sender]\n/receiveMessage [sender] [destination] [message] [stamp] [markdown(opt)] [encryption(opt)] [hashing(opt)] [hash(opt)]\n/acknowledge [sender] [stamp] [hashing] [hash]\n/handshake [message] [sender] [destination] [encryption]\n/getProfile [profile_username]\n/receiveFile [sender] [destination] [file] [filename] [content_type] [stamp] [encryption(opt)] [hashing(opt)] [hash(opt)]\n/retrieveMessages [requestor]\n/getStatus [profile_username]\nEncryption 0 1 2\nHashing 0 1 2 3 4')
   
    @cherrypy.expose
    def ping(self, sender=None):
        """
        Returns 0 when this client is pinged.
        """
        if sender != None:
            return ('0')
        else:
            return('1: Missing required field')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveMessage(self):
        """
        Receives a message from another client.

        Ensures that no fields are missing before decrypting and saving the message.
        Returns "0: Successfully received" or an error code.
        """
        try:
            input_dict = cherrypy.request.json
            for key in input_dict:
                input_dict[key] = unicode(input_dict[key])
            if ('sender' not in input_dict or 'destination' not in input_dict or 'message' not in input_dict or 'stamp' not in input_dict):
                return ('1: Missing compulsory Field') #Missing compulsory Field
            checker_result = SecurityManager.encryption_hash_checker(input_dict) 
            if checker_result != None:
                return checker_result
            if ('markdown' in input_dict and unicode(input_dict['markdown']) == u'1'):
                input_dict['message'] = markdown.markdown(input_dict['message'].decode('utf-8'))
            DatabaseManager.save_message(input_dict)
            return ('0: Successfully received')
        except Exception as e:
            print e
            return ('-1: Internal Error')
    
    @cherrypy.expose
    def send_message(self,message,destination = None,the_markdown = 0, hashing = 0, the_hash = None, sender = None):
        """
        Sends a message to a specified destination.

        Creates a payload dictionary and sends with the highest encryption and hashing standard that is supported by both clients.
        """
        if the_markdown == '1':
            the_mardown = 1
        payload = { 'sender': sender, 'destination': destination, 'message': message, 'stamp': round(float(time.time())), 'markdown': the_markdown, 'encryption': 0, 'hashing': hashing, 'hash': None}
        payload_save = copy.deepcopy(payload)
        if self.loggedIn:
            try:
                if sender == None:
                    sender = self.username
                if destination == None or destination == "None" or destination == "undefined":
                    destination = self.username
                
                user = DatabaseManager.get_user(destination)
                if self.check_user_online(user) or self.username == destination:
                    response_list = self.get_user_list_API(destination)
                    accepted_parameters = SecurityManager.get_accepted_parameters(response_list) #Get maximum supported encryption and hashing
                    hashing = accepted_parameters['hashing']
                    encryption = accepted_parameters['encryption']
                    the_hash = SecurityManager.hash_creator(message, unicode(hashing), sender)
                    payload = { 'sender': sender, 'destination': destination, 'message': message, 'stamp': round(float(time.time())), 'markdown': the_markdown, 'encryption': encryption, 'hashing': hashing, 'hash': the_hash}

                    for key in payload:
                        payload_save[key] = payload[key]

                    public_key = DatabaseManager.get_public_key(payload['destination'])
                    payload = SecurityManager.encryptor(payload, public_key)
                    userdata = DatabaseManager.get_user_as_list(destination) #Get the users data so it can send to them
                    req = None
                    if sender == destination:
                        req = urllib2.Request('http://127.0.0.1:' + str(listen_port) + '/receiveMessage' , self.JSON_encode(payload), {'Content-Type': 'application/json'})
                    else:
                        req = urllib2.Request('http://'+ userdata[0]['ip'] + ':' + userdata[0]['port'] + '/receiveMessage', self.JSON_encode(payload), {'Content-Type': 'application/json'})
                    response = urllib2.urlopen(req, timeout=3).read()
                    if ('markdown' in payload_save and unicode(payload_save['markdown']) == u'1'):
                        payload_save['message'] = markdown.markdown(payload_save['message'])

                    if destination != self.username and response.startswith('0'): #Successful response
                        DatabaseManager.save_message(payload_save)
                    elif not response.startswith('0'):
                        payload_save['message'] = "Unsuccessful message! Returned response: " + response
                        DatabaseManager.save_message(payload_save)
                else:
                    self.send_to_other_users(payload) #User is offline, send to all other online users
            except Exception as e:
                print e 
                print "Exception in send_message"
                traceback.print_exc(file=sys.stdout)
                try:
                    payload_save['message'] = "Message Failed To Send! - " + payload_save['message']
                    payload_save['message_status'] = "Not delivered"
                    DatabaseManager.save_message(payload_save) #Still saves the message when it is undelivered but with an error code
                except:
                    print "Exception saving message to database"             
                
        raise cherrypy.HTTPRedirect('/home?username='+ destination)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def getProfile(self):
        """
        Returns the profile of the person requested by another client or an error message.

        Ensures that all required fields are provided and then sends the users details from
        the database.
        """
        try:
            output_dict = {}
            input_dict = cherrypy.request.json
            if 'profile_username' not in input_dict or 'sender' not in input_dict:
                return ('1: Missing compulsory Field')

            data = DatabaseManager.get_profile(input_dict['profile_username'])
            if data == None:
                return "4: Database Error"
            else:
                if data[2] != None and data[2] != "":
                    output_dict['fullname'] = data[2]
                if data[3] != None and data[3] != "":
                    output_dict['position'] = data[3]
                if data[4] != None and data[4] != "":
                    output_dict["description"] = data[4]
                if data[5] != None and data[5] != "":
                    output_dict['location'] = data[5]
                if data[6] != None and data[6] != "":
                    output_dict['picture'] = data[6]
                if data[7] != None and data[7] != "":
                    output_dict["encoding"] = data[7]
                if data[8] != None and data[8] != "":
                    output_dict['encryption'] = data[8]
                if data[9] != None and data[9] != "":
                    output_dict['decryptionKey'] = data[9]  
            return self.JSON_encode(output_dict)
        except:
            return "Internal Error"
   
    @cherrypy.expose
    def add_or_update_profile(self,fullname=None,position=None,description=None,location=None,picture=None):
        """
        Adds or updates the logged in users profile.

        This function is called by the form in "edit_profile.html" and acts as the link
        between the page and the database.
        """
        if self.loggedIn:
            dictionary = {'fullname': fullname, 'position': position, 'description': description, 'location': location, 'picture': picture }
            DatabaseManager.save_profile(dictionary,self.username)
            raise cherrypy.HTTPRedirect("view_profiles")
        else:
            raise cherrypy.HTTPRedirect("login")

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def getStatus(self):
        """
        Returns the logged in users status from the database when requested.

        Ensures that all required fields are provided before accessing the DatabaseManager
        and returning the status of the user if it is found.
        """
        try:
            output_dict = {}
            input_dict = cherrypy.request.json
            if 'profile_username' not in input_dict:
                return ('1: Missing compulsory Field')
            data = DatabaseManager.get_status(input_dict['profile_username'])
            if data == None:
                return "4: Database Error"
            else:
                if data[0] == None:
                    return "4: Database Error"
                else:
                    output_dict['status'] = data[0]
                    return self.JSON_encode(output_dict)
        except:
            pass

    @cherrypy.expose  
    def set_status(self,status=None,destination=None, page=None):
        """
        Updates the status of the logged in user and redirects back to the page they were on.

        Acts as the link between the status in the navbar of html pages and the database.
        """
        if self.loggedIn:
            try:
                if destination == None:
                    destination = self.username
                self.status = status
                self.update_status()
            except:
                pass   
        if page == "edit_profile":
            raise cherrypy.HTTPRedirect('/edit_profile')
        elif page == "view_profiles":
            raise cherrypy.HTTPRedirect('/view_profiles?username_to_view=' + destination)
        elif page == "settings":
            raise cherrypy.HTTPRedirect('/settings')
        else:
            raise cherrypy.HTTPRedirect('/home?username='+ destination)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveFile(self):
        """
        Receives a file from another client and stores it in the database.

        The function ensures the maximum file size is limited to 5MB and all required parameters are present.
        The base64 data of the file is replaced with a link to the location where the file is saved.
        """
        try:
            input_dict = cherrypy.request.json
            for key in input_dict:
                input_dict[key] = unicode(input_dict[key])
            if ('sender' not in input_dict or 'destination' not in input_dict or 'file' not in input_dict or 'filename' not in input_dict or 'content_type' not in input_dict or 'stamp' not in input_dict):
                return ('1: Missing compulsory Field') #Missing compulsory Field
            if len(input_dict['file']) * 3 / 1024 > 5120 * 4:
                return ('1: File size is greater than 5 MB')
            if "message" in input_dict:
                input_dict["message"] = None
            checker_result = SecurityManager.encryption_hash_checker(input_dict, True) 
            if checker_result != None:
                return checker_result

            input_dict = self.save_file_to_folder(input_dict) #Saves the file into the public/received_files folder
            DatabaseManager.save_message(input_dict)#Save the file using save_message function which can also accept files
            return ('0: Successfully received')   
        except:
            return "Internal Error"

    @cherrypy.expose
    def send_file(self,the_file = None,destination = None, hashing = 0, the_hash = None):
        """
        Sends a file to a provided user.

        Generates a payload based on highest encryption standard supported by both clients 
        and sends an encrypted copy while saving an unencrypted copy to database.
        """
        payload = {"sender": self.username, "destination": destination, "file": None, "filename": None, "content_type": None, 'stamp': float(time.time()), 'hash': the_hash, 'hashing': 0, 'encryption': 0 }
        payload_save = copy.deepcopy(payload)
        if self.loggedIn:
            try:
                if destination == None:
                    destination = self.username
                filename = the_file.filename
                content_type = the_file.content_type.value
                encoded_string = base64.b64encode(the_file.file.read())
                payload = {"sender": self.username, "destination": destination, "file": encoded_string, "filename": filename, "content_type": content_type, 'stamp': float(time.time()), 'hashing': 0, 'encryption': 0 }

                user = DatabaseManager.get_user(destination)
                if self.check_user_online(user) or self.username == destination:
                    response_list = self.get_user_list_API(destination)
                    get_accepted_parameters = SecurityManager.get_accepted_parameters(response_list)
                    hashing = get_accepted_parameters['hashing']
                    the_hash = SecurityManager.hash_creator(encoded_string, unicode(hashing), self.username)
                    encryption = get_accepted_parameters['encryption']

                    userdata = DatabaseManager.get_user_as_list(destination)

                    payload = {"sender": self.username, "destination": destination, "file": encoded_string, "filename": filename, "content_type": content_type, 'stamp': float(time.time()), 'hash': the_hash, 'hashing': hashing, 'encryption': encryption }
                    
                    for key in payload:
                        payload_save[key] = payload[key]
                    
                    public_key = DatabaseManager.get_public_key(payload['destination'])
                    payload = SecurityManager.encryptor(payload, public_key)

                    if destination == self.username:
                        req = urllib2.Request('http://127.0.0.1:' + str(listen_port) + '/receiveFile', self.JSON_encode(payload), {'Content-Type': 'application/json'})
                    else:
                        req = urllib2.Request('http://'+ userdata[0]['ip'] + ':' + userdata[0]['port'] + '/receiveFile', self.JSON_encode(payload), {'Content-Type': 'application/json'})
                    response = urllib2.urlopen(req, timeout=5).read()

                    if destination != self.username and response.startswith("0"):
                        payload_save = self.save_file_to_folder(payload_save)
                        DatabaseManager.save_message(payload_save)
                else:
                    self.send_to_other_users(payload) #Sends the message to all online nodes if the target node is offline
            except Exception as e:
                print e
                print "Exception in send_file"
        raise cherrypy.HTTPRedirect("home?username="+destination)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def acknowledge(self):
        """
        Allows another client to acknowledge that a message has been received.

        Returns an error code if parameters are missing or if a database error occurs
        or it confirms the message has been sent successfully on this end and returns 
        a success code.
        """
        try:
            input_dict = cherrypy.request.json
            for key in input_dict:
                input_dict[key] = unicode(input_dict[key])
            if 'sender' not in input_dict or 'stamp' not in input_dict or 'hashing' not in input_dict or 'hash' not in input_dict:
                return ('1: Missing Compulsory Field')
            message = DatabaseManager.get_specific_message(input_dict)
            if message is not None:
                if DatabaseManager.confirm_message_received(message,"Successful"):
                    return('0: Success')
                else:
                    return('4: Database Error')
        except Exception as e:
            print e
            print "Exception in acknowledge"
            return ("-1: Internal Errror")

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def handshake(self):
        """
        Allows another client to initiate a handshake with this client.

        This function decrypts a provided message and returns it to allow
        the other client to verify that the encryption is working successfully
        between it and this client.
        """
        try:
            input_dict = cherrypy.request.json
            for key in input_dict:
                input_dict[key] = unicode(input_dict[key])
                input_dict[key].decode('utf-8')
            if 'message' not in input_dict or 'sender' not in input_dict or 'destination' not in input_dict or 'encryption' not in input_dict:
                return self.JSON_encode({'error':'1: Missing Compulsory Field'})
            checker_result = SecurityManager.encryption_hash_checker(input_dict) #Calls the encryption_hash_checker to decrypt the message
            if checker_result is not None:
                return self.JSON_encode({'error':checker_result})
            output_dict = {'message': input_dict['message'], 'error': '0'}
            return self.JSON_encode(output_dict) #Returns the response and the decrypted message
            
        except Exception as e:
            print e
            print "Exception in handshake"
            return self.JSON_encode({'error':'-1: Internal Error'})

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def retrieveMessages(self):
        """
        Allows a client to request any offline messages that are intended for them.

        Ensures all required fields are present before sending them all messages which
        this client thinks the requestor may not have received.
        """
        try:
            input_dict = cherrypy.request.json
            for key in input_dict:
                input_dict[key] = unicode(input_dict[key])
                input_dict[key].decode('utf-8')
            if 'requestor' not in input_dict:
                return self.JSON_encode({'error':'1: Missing Compulsory Field'})
            unconfirmed_messages_to_send = DatabaseManager.get_unconfirmed_messages_to_send(input_dict.get('requestor')) #Gets all unconfirmed messages intended for requestor
            for message in unconfirmed_messages_to_send:
                try:
                    if message[11] != None and message[11] != "":
                        self.send_stored_file(message) #Sending stored files
                    else:
                        self.send_stored_message(message) #Sending stored messages
                except:
                    pass

        except Exception as e:
            print e 
            print "Exception in retrieveMessages"
    
    @cherrypy.expose
    def get_acknowledgements(self, destination):
        """
        Gets acknowledgments from the destination client that a message.

        This function calls the destination's acknowledge API and changes
        message status to successful if the response starts with 0
        """
        if destination == None:
            destination = self.username
        unconfirmed_messages = DatabaseManager.get_unconfirmed_messages(destination)
        for message in unconfirmed_messages:
            try:
                if message[8] != None and int(message[8]) > 0 and message[9] != None and message[9] != "None":
                    payload = {'sender':message[1],'stamp':message[4],'hashing':message[8], 'hash':message[9]}
                    userdata = DatabaseManager.get_user_as_list(destination)
                    if destination == self.username:
                        req = urllib2.Request('http://127.0.0.1:' + str(listen_port) + '/acknowledge', self.JSON_encode(payload), {'Content-Type': 'application/json'})
                    else:
                        req = urllib2.Request('http://'+ userdata[0]['ip'] + ':' + userdata[0]['port'] + '/acknowledge', self.JSON_encode(payload), {'Content-Type': 'application/json'})
                    response = urllib2.urlopen(req, timeout=1).read()
                    if response.startswith("0") and destination != self.username:
                        DatabaseManager.confirm_message_received(message,"Successful")
                    else:
                        print response

            except Exception as e:
                print "E"
                print e

    def get_hotp_token(self,secret, intervals_no):
        """
        Gets hotp tokens when provided with the secret and an interval value from the totp function.

        """
        key = base64.b32decode(secret, True)
        msg = struct.pack(">Q", intervals_no)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        o = ord(h[19]) & 15
        h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
        return h

    def get_totp_token(self,secret):
        """
        Returns a time based token which should match that on the google authenticator app.
        """
        return self.get_hotp_token(secret, intervals_no=int(time.time())//30)

    def get_secret(self,username):
        """
        Gets a new secret by concatenating part of the username with a random string.
        """
        return base64.b32encode(username[:4] + self.random_key_gen())[:16]

    def random_key_gen(self):
        """
        Generates a random sequence of letters.
        """
        alphabet = string.letters
        random_string = ""
        for i in range(9):
            random_string += random.choice(alphabet)
        return random_string

    def get_barcode_image(self, username,secret):
        """
        Gets the barcode of the secret code using chart APIs.
        """
        url = "https://chart.googleapis.com/chart?chs=200x200&chld=M%7C0&cht=qr&chl=otpauth%3A%2F%2Ftotp%2F" + username + "%3Fsecret%3D" + secret + "%26issuer%3JaduuMessage"
        return url

    def get_user_list_API(self,username_to_view):
        """
        Calls the username_to_views listAPI and returns it as a list.

        Allows other functions to call this function to understand what API's
        are accepted by the other client.If the other client does not return a 
        reponse none is returned. This helps to work with substandard clients.
        """
        try:
            user = DatabaseManager.get_user(username_to_view) 
            if self.check_user_online(user):
                if username_to_view == self.username:
                    req = urllib2.Request('http://127.0.0.1:' + str(listen_port) + '/listAPI')
                else:
                    req = urllib2.Request('http://'+ user[3] + ':' + user[4] + '/listAPI')
                response = urllib2.urlopen(req, timeout=1).read()
                if response != None and len(response) != 0:
                    response_list = response.split("\n")
                    return response_list
            else:
                return None
        except:
            return None

    def get_user_details(self,username_to_view):
        """
        Gets the profile details of the user.

        Gets the profile from a user or searches database to find an
        older profile page from the database if the client is offline.
        """
        try:
            usersData = DatabaseManager.load_profile(username_to_view)
            if usersData == None:
                success = self.get_profile_from_user(username_to_view)
                if success == True:
                    usersData = DatabaseManager.load_profile(username_to_view)
                    usersData = list(usersData)
                    usersData = self.finalise_profile(usersData) 
                    return usersData
                else:
                    return []
            else:
                self.get_profile_from_user(username_to_view)
                usersData = DatabaseManager.load_profile(username_to_view)
                usersData = list(usersData)
                usersData = self.finalise_profile(usersData) 
                return usersData
        except:
            return []
    
    def get_all_profiles(self):
        """
        Gets statuses and profiles from all users online.
        """
        print "Updating all profiles and statuses"
        usernames = DatabaseManager.get_users_list()
        for username in usernames:
            self.get_status_from_user(username[0])
            self.get_profile_from_user(username[0])
        print "Updated profiles and statuses successfully!"

    def retrieve_messages(self):
        """
        Retrieves messages that are meant to be for this client.

        This function works in a background daemon thread which starts
        when the user first logs in.
        """
        print "Retrieving Messages from users"
        usernames = DatabaseManager.get_users_list()
        for username in usernames:
            self.get_messages_from_user(username[0])
        print "Retrieved messages function executed successfully!"

        self.reportTimer.resume()
        self.get_all_profiles()

    def finalise_profile(self, usersData):
        """
        Finalises a users profile and ensures that the data does not contain substandard fields.

        This ensures that the profile page does not break if the returned profile contains broken
        html or any unwanted code.
        """
        if (usersData[6] == None or len(usersData[6]) == 0 or ("http://" not in usersData[6] and "https://" not in usersData[6])):
            usersData[6] = "http://placehold.it/380x500"

        if (usersData[4] != None and ("http://:" in usersData[4] or "https://" in usersData[4])):
            usersData[4] = "No links in profile info please!"
        
        for i in range (1,len(usersData)):
            if (usersData[i] == None or len(usersData[i]) == 0):
                usersData[i] = ""

        if len(usersData[1]) > 7: 
            usersData[1] = (usersData[1][:7] + '..') 
        if len(usersData[2]) > 18:
            usersData[2] = (usersData[2][:18] + '..')
        if len(usersData[3]) > 21:
            usersData[3] = (usersData[3][:21] + '..')
        if len(usersData[4]) > 50: 
            usersData[4] = (usersData[4][:50] + '..') 
        if len(usersData[5]) > 35:
            usersData[5] = (usersData[5][:35] + '..') 
        return usersData

    def get_status_from_user(self, username_to_view):
        """
        Gets the status from a specified user by calling their /getStatus

        This function creates the payload and makes the request. When the response is received
        the status is saved in the database for offline viewing.
        """
        if self.loggedIn:
            try:
                payload = { 'profile_username': username_to_view}
                user = DatabaseManager.get_user(username_to_view)
                if self.check_user_online(user):
                    if user[1] != self.username:
                        req = urllib2.Request('http://'+ user[3] + ':' + user[4] + '/getStatus', self.JSON_encode(payload), {'Content-Type': 'application/json'})
                    else:
                         req = urllib2.Request('http://127.0.0.1:' + user[4] + '/getStatus', self.JSON_encode(payload), {'Content-Type': 'application/json'})
                    response = urllib2.urlopen(req, timeout=1).read()
                    if response != None and len(response) != 0:
                        input_dict = self.JSON_decode(response)
                        success = DatabaseManager.save_status(input_dict['status'], username_to_view)
                        return success
                else:
                    return None
                    
            except:
                return None
    def check_user_online(self,user):
        """
        Checks if the user has last reported in past 2 minutes.

        This function is called by many other functions to determine whether the user
        is online.
        """
        if user == None:
            return False
        else:
            if time.time() - float(user[5]) > 120: #User is offline
                return False
            else:
                return True
    
    def get_profile_from_user(self, username_to_view):
        """
        Calls the targets /getProfile and saves it in database if successful.

        The profile once saved in the database can then be accessed offline too.
        """
        if self.loggedIn:
            try:
                payload = { 'profile_username': username_to_view}
                payload['sender'] = self.username
                user = DatabaseManager.get_user(username_to_view)
                if self.check_user_online(user):
                    req = urllib2.Request('http://'+ user[3] + ':' + user[4] + '/getProfile', self.JSON_encode(payload), {'Content-Type': 'application/json'})
                    response = urllib2.urlopen(req, timeout=1).read()
                    if response != None and len(response) != 0:
                        input_dict = self.JSON_decode(response)
                        success = DatabaseManager.save_profile(input_dict, username_to_view)
                        return success
                else:
                    return None
            except:
                return None

    def get_messages_from_user(self,username):
        """
        Calls another clients /retrieveMessages to ask for any messages that are intended for logged in user.

        This function is called for all users when this client's user first logs in.
        Hence allowing the client to get all messages intended for the this clients user.
        """
        try:
            payload = {'requestor': self.username}
            user = DatabaseManager.get_user(username)
            if self.check_user_online(user):
                req = urllib2.Request('http://'+ user[3] + ':' + user[4] + '/retrieveMessages', self.JSON_encode(payload), {'Content-Type': 'application/json'})
                response = urllib2.urlopen(req, timeout=1).read()
                if not response.startswith("0"):
                    print response
                else:
                    print "Successful response from: " + user[1]
        except:
            pass

    def save_file_to_folder(self,input_dict):
        """
        This function saves the files base64 to a directory.

        This function is called right before saving file to database. It replaces
        the file element from the base64 data to the path to the created file.
        """
        path = "public/received_files/"
        if not os.path.exists(path):
            os.makedirs(path)
        full_path = os.path.join(path, input_dict['filename'])
        counter = 1
        while (os.path.isfile(full_path)):
            path_array = full_path.rsplit(".", 1)
            if counter > 1:
                full_path = path_array[0][:-1] + str(counter) + "." + path_array[1]
            else:
                full_path = path_array[0] + str(counter) + "." + path_array[1]
            counter += 1

        with open(full_path, 'wb') as file_to_save:
            file_to_save.write(input_dict['file'].decode('base64'))
        input_dict['file'] = full_path.replace("public", "/static")
        return input_dict 

    def send_stored_file(self,message):
        """
        Allows this client to send stored files that are intended for someone else to them.

        This function is called for all files that are intended for the requestor. 
        The file is converted back into base64 and send to the requestor of the file.
        """
        payload = { 'sender': message[1], 'destination': message[2], 'stamp': message[4], 'encryption': 0, 'hashing': message[8], 'hash': message[9], 'file': message[11], 'filename': message[12], 'content_type': message[13]}
        try:
            payload['file'] = payload['file'].replace("/static", "public")
            with open(payload['file'], "rb") as f:
                data = f.read()
                payload['file'] = data.encode("base64")
            userdata = DatabaseManager.get_user_as_list(message[2])
            if userdata is not None:
                req = urllib2.Request('http://'+ userdata[0]['ip'] + ':' + userdata[0]['port'] + '/receiveFile', self.JSON_encode(payload), {'Content-Type': 'application/json'})
                response = urllib2.urlopen(req, timeout=3).read()
                if response.startswith("0"):
                    DatabaseManager.confirm_message_received(message,"Successful")
                else:
                    print response
        except Exception as e:
                print e

    def send_stored_message(self,message):
        """
        Sends a message from the database that is intended for the requestor.

        This function is called for all messages that are intended for the requestor.
        """
        payload = { 'sender': message[1], 'destination': message[2], 'message': message[3], 'stamp': message[4], 'markdown': int(message[5]), 'encryption': 0, 'hashing': int(message[8]), 'hash': message[9]}
        try:
            userdata = DatabaseManager.get_user_as_list(message[2])
            if userdata is not None:
                req = urllib2.Request('http://'+ userdata[0]['ip'] + ':' + userdata[0]['port'] + '/receiveMessage', self.JSON_encode(payload), {'Content-Type': 'application/json'})
                response = urllib2.urlopen(req, timeout=3).read()
                if response.startswith("0"):
                    DatabaseManager.confirm_message_received(message,"Successful")
                else:
                    print response
        except Exception as e:
                print e

    def send_to_other_users(self,the_payload):
        """
        Sends a message to all online users if the target is offline.

        This function is called only when the target is offline. Messages and
        files are sent to all online users in the hope that they will forward to 
        the target.
        """
        all_users = DatabaseManager.get_all_users()
        the_payload['sender'] = self.username
        sent_to_other_user = False
        for user in all_users:
            try:
                if self.username != user[1] and self.check_user_online(user):
                    if the_payload.get('file') == None or the_payload.get('file') == "":
                        req = urllib2.Request('http://'+ str(user[3]) + ':' + str(user[4]) + '/receiveMessage', self.JSON_encode(the_payload), {'Content-Type': 'application/json'})
                    else:
                        req = urllib2.Request('http://'+ str(user[3]) + ':' + str(user[4]) + '/receiveFile', self.JSON_encode(the_payload), {'Content-Type': 'application/json'})

                    response = urllib2.urlopen(req, timeout=1).read()
                    if response.startswith('0'):
                        sent_to_other_user = True
                    else:
                        print response
            except Exception as e:
                print e
                print "Error sending offline message to: " + user[1]
        if not sent_to_other_user:
            the_payload['message_status'] = "Offline message unsent" #If noone accepted the message mark as unsent
        if the_payload.get('file') != None and the_payload.get('file') != "":
            the_payload = self.save_file_to_folder(the_payload)
        if ('markdown' in the_payload and unicode(the_payload['markdown']) == u'1'):
                the_payload['message'] = markdown.markdown(the_payload['message'])
        DatabaseManager.save_message(the_payload)
        



    def authoriseUserLogin(self, username, password):
        """
        Authorises the login when the user first reports.
        """
        try:
            response = self.server_report(username,password)
            if response == "0, User and IP logged":
                self.firstLogin = False
                self.autoReport = True
                self.username = username
                self.hashPass = hashlib.sha256((password+'COMPSYS302-2017').encode('utf-8')).hexdigest()
                cherrypy.session['username'] = username
                cherrypy.session['hashPass'] = hashlib.sha256((password+'COMPSYS302-2017').encode('utf-8')).hexdigest()
                return 0
            else:
                print response #Print the response if it is not 0
                return 1
        except:
            return 1

    def server_list_API(self):
        """
        Gets the list_API from the server
        """
        try:
            url = "https://cs302.pythonanywhere.com/listAPI"
            response = urllib2.urlopen(url).read()
            return response
        except:
            return "API list unavailable"

    def server_list_Users(self):
        """
        Gets the list of users from the server.
        """
        try:
            url = "https://cs302.pythonanywhere.com/listUsers"
            response = urllib2.urlopen(url).read()
            return response.split(",")
        except:
            return []

    def server_report(self, username = None, password = None):
        """
        Reports to the server.

        This function is called every 45 seconds using a timer set during
        initialisation.
        """
        print "Attempting to report"
        if username is None:
            username = self.username
        if password is None:
            password = self.hashPass
        if self.loggedIn or self.firstLogin:
            try:
                if (password != self.hashPass):
                    hashPass = hashlib.sha256((password+'COMPSYS302-2017').encode('utf-8')).hexdigest()
                else:
                    hashPass = password
                final_ip = ""
                ipJson = json.loads(urllib2.urlopen("http://ip.jsontest.com/").read())
                ip = ipJson['ip']
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                if local_ip.startswith("10.10"):
                    final_ip = local_ip
                    location = "0"
                elif local_ip.startswith("172.2"):
                    final_ip = local_ip
                    location = "1"
                else:
                    final_ip = ip
                    location = "2"
                pubkey = SecurityManager.RSA_get_public_key()
                url = "https://cs302.pythonanywhere.com/report?username=" + username + "&password=" + hashPass + "&location=" + location + "&ip=" + final_ip + "&port=" + str(listen_port) + "&pubkey=" + pubkey +"&enc=0"
                response = urllib2.urlopen(url).read()
                if self.loggedIn and response == "0, User and IP logged":
                    print "Reported successfully!"
                    list_dict = self.server_get_List()
                    DatabaseManager.update_user_table(list_dict)
                    self.get_all_profiles()
                    self.reportTimer.resume()
                return response
            except:
                return "Internal error calling report"

    def server_logoff(self):
        """
        Log off from the server.

        This function is called whenever the application exits or 
        when user clicks log off.
        """
        url = "https://cs302.pythonanywhere.com/logoff?username=" + self.username + "&password=" + self.hashPass + "&enc=0"
        response = urllib2.urlopen(url).read()
        DatabaseManager.save_status("Offline",self.username)
        return response
    
    def server_get_List(self):
        """
        Gets the list from the server.
        """
        try:
            url = "https://cs302.pythonanywhere.com/getList?username=" + self.username + "&password=" + self.hashPass + "&enc=0" + "&json=1"
            response = urllib2.urlopen(url).read()
            online_list_dict = self.JSON_decode(response)
            return online_list_dict
        except:
            return "Internal error calling get_list"

    
    def JSON_encode(self,dictionary):
        """Returns JSON data from a dictionary"""
        return json.dumps(dictionary)

    
    def JSON_decode(self,input_data):
        """Returns a dictionary from JSON data"""
        return json.loads(input_data)

    def update_status(self):
        """Updates the status of the user"""
        user = DatabaseManager.get_user(self.username)
        DatabaseManager.save_status(self.status,self.username)

    def rapidClose(self):
        """Logs off from the server upon application exit"""
        self.reportTimer.pause()
        if self.loggedIn:
            print self.server_logoff()

if __name__ == '__main__':
    """Initialisation of cherrypy"""
    conf = {
        '/': {
            'tools.sessions.on': True,
            'tools.staticdir.root': os.path.abspath(os.getcwd()),
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': './public'
        }
    }
    cherrypy.config.update({'server.socket_host': listen_ip,
                             'server.socket_port': listen_port,
                             'engine.autoreload.on': True})
    main_app = MainApp()
    cherrypy.engine.subscribe('stop', main_app.rapidClose)
    cherrypy.quickstart(main_app, '/', conf)
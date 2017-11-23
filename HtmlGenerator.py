"""
COMPSYS302 - Sofware Design
Author: Adil Bhayani

This file is responsible for the generation of the dynamic sections of the home page.

The file generates both the messages for the selected user and the users list and their
statuses on the side bar.
"""

import sched, time
import DatabaseManager


def get_both_list(toLoggedInUser, fromLoggedInUser):
    """
    This function takes the list of messages to and from the logged in user and organises them.

    The function takes two sorted lists and merges them in  approximately O(n). This is done to
    ensure that messages are kept in order.
    """
    bothList = []
    j = 0
    i = 0
    smallerList = []
    largerList = []
    if len(toLoggedInUser) > len(fromLoggedInUser): #Determine which list is smaller
        smallerList = fromLoggedInUser
        largerList = toLoggedInUser
    else:
        smallerList = toLoggedInUser
        largerList = fromLoggedInUser
    while i < (len(smallerList)) and j < (len(largerList)): #Merge
        if float(smallerList[i][4]) < float(largerList[j][4]):
            if (smallerList[i] not in bothList):
                bothList.append(smallerList[i])
            i += 1
        else:
            if (largerList[j] not in bothList):
                bothList.append(largerList[j])
            j += 1
    if i < len(smallerList):
        for k in range (i,len(smallerList)):
            if (smallerList[k] not in bothList):
                bothList.append(smallerList[k])
    elif j < len (largerList):
        for k in range (j,len(largerList)):
            if (largerList[k] not in bothList):
                bothList.append(largerList[k])
    return bothList

def get_users_html(username):
    """
    This function generates the users panel on the left side of the home page.

    The function makes a call to the database to retrieve the users details and 
    creates html accordingly.
    """
    usersData = DatabaseManager.get_all_users()
    stringBuilder = ""
    for user in usersData:
        imageUrl = DatabaseManager.get_user_profile_image(user[1])
        status = DatabaseManager.get_status(user[1])
        if status != None and status[0] != None:
            status = status[0]
        else:
            status = None
        try:
            if time.time() - float(user[5])< 120: #User os online
                stringBuilder = stringBuilder + """\n<span class="glyphicon glyphicon-one-fine-green-dot pull-left"></span>"""
            else:
                stringBuilder = stringBuilder + """\n<span class="glyphicon glyphicon-one-fine-red-dot pull-left"></span>"""
        except: #User has never been online
            stringBuilder = stringBuilder + """\n<span class="glyphicon glyphicon-one-fine-black-dot pull-left"></span>"""

        stringBuilder = stringBuilder + """<div class="media conversation" style="padding: 2px; height: 70px;">
            <a class="pull-right" href="/view_profiles?username_to_view="""
            
        stringBuilder = stringBuilder + user[1] + """">
                <img onclick="saveScrollLocations()" class="media-object" data-src="holder.js/64x64" alt="64x64" style="width: 50px; height: 50px;"  """
                
        if imageUrl == None:
            stringBuilder = stringBuilder + """src="/static/img/500x500.png">"""
        else:
            stringBuilder = stringBuilder + """src=" """ + imageUrl + """">"""

        stringBuilder = stringBuilder + """</a>
            <div class="media-body">
                <h5 onclick="saveScrollLocations()" class="media-heading" """

        if user[1] == username:
            stringBuilder = stringBuilder + """ id="selected_message">"""
        else:
            stringBuilder = stringBuilder + """>"""
        if user[1] == username:
            stringBuilder = stringBuilder + """<a id="selected_message" href="/home?username=""" + user[1] +"\">"
        else:
            stringBuilder = stringBuilder + """<a href="/home?username=""" + user[1] +"\">"
        stringBuilder = stringBuilder + user[1] + """</a></h5>
                <small>Last online: """
        try:        
            stringBuilder = stringBuilder + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(user[5]))) + "<br>Status - "
        except:
            stringBuilder = stringBuilder + user[5] + "<br>Status - "
        if status != None:
            stringBuilder = stringBuilder + status     
        stringBuilder = stringBuilder + """</small>
            </div>
        </div>\n"""
    return stringBuilder #Return the html string with all users details in it

def get_messages_html(sender,username):
    """
    This function takes the logged in user and gets all messages/ files that were sent between them.

    This function gets the list of messages from a user and another to the user, then after merging them
    renders the html for the messages box and returns it.
    """
    sender = sender
    messagesList = DatabaseManager.get_messages(sender,username)
    toLoggedInUser = messagesList[0]
    fromLoggedInUser = messagesList[1]

    bothList = get_both_list(toLoggedInUser,fromLoggedInUser) #Merge the lists
    client_user_image_url = DatabaseManager.get_user_profile_image(sender)
    other_user_image_url = DatabaseManager.get_user_profile_image(username)
    if client_user_image_url == None:
        client_user_image_url = "/static/img/500x500.png"
    if other_user_image_url == None:
        other_user_image_url = "/static/img/500x500.png"
    stringBuilder = ""
    for message in bothList:
        stringBuilder = stringBuilder + """\n<div class="media msg">
                <a class="pull-right" href="#">
                    <img class="media-object" data-src="holder.js/64x64" style="width: 32px; height: 32px;" src=" """
        if message[1] == sender:
            stringBuilder = stringBuilder + client_user_image_url             
        else:
            stringBuilder = stringBuilder + other_user_image_url
            
        stringBuilder = stringBuilder +  """ ">
                </a>
                <div class="media-body">
                    <small class="pull-right time"><i class="fa fa-clock-o"></i> """
        try:
            stringBuilder = stringBuilder + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(message[4]))) + " - " + message[14] +"""</small>
                    <h5 class="media-heading">"""
        except:
            stringBuilder = stringBuilder + """- </small>
            <h5 class="media-heading">"""
        stringBuilder = stringBuilder + message[1] + """</h5>"""

        if message[3] != None:
            stringBuilder = stringBuilder + """
                        <small class="col-lg-10">"""
            stringBuilder = stringBuilder + message[3] + """</small>
                    </div>
                </div>\n"""
        else:
            if message[13].startswith("audio"):
                stringBuilder = stringBuilder + """<audio controls>
                        <source src=\""""
                stringBuilder = stringBuilder + message[11] + """"/>
                        Audio content not supported on this browser
                    </audio>"""
            elif message[13].startswith("image"):
                stringBuilder = stringBuilder + """<img style="max-width: 300px; max-height: 300px;" src=\""""
                stringBuilder = stringBuilder + message[11] + """"alt=\"""" + message[12] + """"/>"""

            elif message[13].startswith("video"):
                stringBuilder = stringBuilder + """<video width="300" controls>
                    <source src=\""""
                stringBuilder = stringBuilder + message[11] + """" type=\"""" + message[13] + """" alt=\"""" + message[12] + """">
                Video content not supported on this browser
                </video>"""
            else:
                stringBuilder = stringBuilder + """<a href=\"""" + message[11] + """" download>"""+ message[12] + """</a>"""
            stringBuilder = stringBuilder + """</div>
            </div>\n"""

    return stringBuilder #Return the messages html
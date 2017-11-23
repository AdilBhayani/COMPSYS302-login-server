"""
This file manages the interaction with the database.

The functions defined in this file either save values to the database
or retrieves and returns values when requested by the MainFile.
"""

import sqlite3


DB_STRING = "my_db.db"

def setup_db(user_list):
    """
    Setup the database, create tables if not present and initialise user data.
    """
    try:   
        user_table_check = create_database_tables()

        if (user_table_check == 1):
            print "Database could not be initialised!"
        else:
            print "Database has been initialised successully!"
            initialise_user_data(user_list)
    except:
        pass

def create_database_tables():
    """
    Try to make the tables if they dont already exist.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    try:
        queryCurs.execute('''CREATE TABLE IF NOT EXISTS Users (id INTEGER PRIMARY KEY, username TEXT, location TEXT, ip TEXT, port TEXT, login_time TEXT, public_key TEXT)''')
        queryCurs.execute('''CREATE TABLE IF NOT EXISTS Messages (id INTEGER PRIMARY KEY, sender TEXT, destination TEXT, message TEXT, stamp TEXT, markdown TEXT, encoding TEXT, encryption TEXT, hashing TEXT, hash TEXT, decryption_key TEXT, file TEXT, filename TEXT, content_type TEXT, message_status TEXT)''')
        queryCurs.execute('''CREATE TABLE IF NOT EXISTS UsersProfiles (id INTEGER PRIMARY KEY, username TEXT, fullname TEXT, position TEXT, description TEXT, location TEXT, picture TEXT, encoding TEXT, encryption TEXT, decryptionKey TEXT, status TEXT, secret_key TEXT) ''')
    except:
        conn.close()
        return 1
    conn.commit()
    conn.close()
    return 0	

def initialise_user_data(user_list):
    """
    Initialise each users data if it doesn't exist.
    """
    try:
        conn = sqlite3.connect(DB_STRING)
        queryCurs = conn.cursor()
        for username in user_list:
            queryCurs.execute("SELECT rowid FROM Users WHERE username = ?", (username,))
            data = queryCurs.fetchone()
            if data is None:
                print "Data is none for: " + username
                queryCurs.execute('''INSERT INTO Users (username, location, ip, port, login_time) VALUES (?,?,?,?,?)''', (username, "-", "-", "-", "-"))
                print "Username: " + username + " added to Users table"
        conn.commit()
        conn.close()
        print 'Initialisation of Users done successfully!'
    except:
        pass

def update_user_table(list_dict):
    """
    Updates the user table with new values.
    """
    print "Updating User table"
    try:
        conn = sqlite3.connect(DB_STRING)
        queryCurs = conn.cursor()
        counter = 0
        while str(counter) in list_dict:
            online_user = list_dict[str(counter)]
            queryCurs.execute("SELECT rowid FROM Users WHERE username = ?", (online_user['username'],))
            data = queryCurs.fetchone()
            if data == None:
                counter += 1
                continue
            else:
                queryCurs.execute('''UPDATE Users SET username=?, location=?, ip=?, port=?, login_time=?, public_key=? WHERE rowid=?''', [online_user['username'], online_user['location'], online_user['ip'], online_user['port'], online_user['lastLogin'], online_user.get('publicKey'), data[0]])
            counter += 1
        conn.commit()
        conn.close()
        print "Updated User table successfully!"
    except:
        print "Internal Error"

def load_profile(username_to_view):
    """
    Loads a profile from a user and returns it.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute('SELECT * FROM UsersProfiles WHERE username = ?', (username_to_view,))
    usersData = queryCurs.fetchone()
    conn.commit()
    conn.close()
    return usersData

def save_status(status,username_to_view):
    """
    Saves a provided status to a users profile.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()

    queryCurs.execute("SELECT rowid FROM UsersProfiles WHERE username = ?", (username_to_view,))
    data = queryCurs.fetchone()
    if data == None:
        queryCurs.execute('''INSERT INTO UsersProfiles (username, status) VALUES (?,?)''', (username_to_view, status))
    else:
        queryCurs.execute('''UPDATE UsersProfiles SET username=?, status=? WHERE rowid=?''', [username_to_view, status, data[0]])

    conn.commit()
    conn.close()
    return True

def save_profile(my_dict, username_to_view):
    """
    Saves new data to a users profile.
    """
    if isinstance(my_dict, unicode):
        my_dict = ast.literal_eval(my_dict)
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute("SELECT rowid FROM UsersProfiles WHERE username = ?", (username_to_view,))
    data = queryCurs.fetchone()
    if data == None:
        queryCurs.execute('''INSERT INTO UsersProfiles (username, fullname, position, description, location, picture) VALUES (?,?,?,?,?,?)''', (username_to_view, my_dict.get('fullname'), my_dict.get('position'), my_dict.get('description'), my_dict.get('location'), my_dict.get('picture')))
    else:
        queryCurs.execute('''UPDATE UsersProfiles SET username=?, fullname=?, position=?, description=?, location=?, picture=? WHERE rowid=?''', [username_to_view, my_dict.get('fullname'), my_dict.get('position'), my_dict.get('description'), my_dict.get('location'), my_dict.get('picture'), data[0]])
    conn.commit()
    conn.close()
    return True


def save_message(my_dict):
    """
    Saves a message if it is not a duplicate.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    if my_dict.get('message_status') == None:
        my_dict['message_status'] = "Unconfirmed"
    
    queryCurs.execute("SELECT rowid FROM Messages WHERE sender = ? and destination = ? and stamp = ? and hash = ?", (my_dict.get('sender'), my_dict.get('destination'), my_dict.get('stamp'), my_dict.get('hash'),))
    data = queryCurs.fetchone()
    if data == None:
        queryCurs.execute('''INSERT INTO Messages (sender, destination, message, stamp, markdown, encoding, encryption, hashing, hash, decryption_key, file, filename, content_type, message_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (my_dict.get('sender'), my_dict.get('destination'), my_dict.get('message'), my_dict.get('stamp'), my_dict.get('markdown'), my_dict.get('encoding'), my_dict.get('encryption'), my_dict.get('hashing'), my_dict.get('hash'), my_dict.get('decryptionKey'), my_dict.get('file'), my_dict.get('filename'), my_dict.get('content_type'), my_dict.get('message_status')))
    
    conn.commit()
    conn.close()
    return True

def get_users_list():
    """
    Returns a list of all user's usernames.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute("SELECT username FROM Users")
    usernames = queryCurs.fetchall()
    conn.commit()
    conn.close()
    return usernames

def get_user(username_to_view):
    """
    Gets all fields from a users profile.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute("SELECT * FROM Users WHERE username = ?", (username_to_view,))
    user = queryCurs.fetchone()
    conn.commit()
    conn.close()
    return user       

def get_all_users():
    """
    Gets all fields from all users.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute('SELECT * FROM Users')
    usersData = queryCurs.fetchall()
    conn.commit()
    conn.close()
    return usersData

def get_user_as_list(destination):
    """
    Gets the users data as a list.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute("SELECT * FROM Users WHERE username='{a}'".format(a=destination))
    userdata = [dict(zip(['id', 'username', 'location', 'ip', 'port', 'login_time'], row)) for row in queryCurs.fetchall()]
    conn.commit()
    conn.close()
    return userdata


def get_status(profile_username):
    """
    Gets the users status from the database.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute("SELECT status FROM UsersProfiles WHERE username = ?", (profile_username,))
    data = queryCurs.fetchone()
    conn.commit()
    conn.close()
    return data

def get_secret_key(profile_username):
    """
    Gets the secret key for 2FA if it exists.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute("SELECT secret_key FROM UsersProfiles WHERE username = ?", (profile_username,))
    data = queryCurs.fetchone()
    conn.commit()
    conn.close()
    if data is None:
        return None
    return data[0]

def save_secret_key(key,profile_username):
    """
    Saves a secret key to the users profile.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute("SELECT rowid FROM UsersProfiles WHERE username = ?", (profile_username,))
    data = queryCurs.fetchone()
    if data == None:
        queryCurs.execute('''INSERT INTO UsersProfiles (username, secret_key) VALUES (?,?)''', (profile_username, key))
    else:
        queryCurs.execute('''UPDATE UsersProfiles SET secret_key = ? WHERE rowid=?''', [key, data[0]])
    conn.commit()
    conn.close()
    return True

def get_public_key(username):
    """
    Gets the public key of a user from the database.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute("SELECT public_key FROM Users WHERE username = ?", (username,))
    data = queryCurs.fetchone()
    conn.commit()
    conn.close()
    if data != None:
        return data[0]
    return None

def get_profile(profile_username):
    """
    Gets a profile of a specified user.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute("SELECT * FROM UsersProfiles WHERE username = ?", (profile_username,))
    data = queryCurs.fetchone()
    conn.commit()
    conn.close()
    return data

def get_user_profile_image(user):
    """
    Gets just the profile image of the specified user.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute("SELECT picture FROM UsersProfiles WHERE username = ?", (user,))
    imageUrl = queryCurs.fetchone()
    conn.commit()
    conn.close() 
    if imageUrl != None and imageUrl[0] != None and ("http://" in imageUrl[0] or "https://" in imageUrl[0]):
        return imageUrl[0]
    else:
        return None

def get_messages(sender,username):
    """
    Gets all messages between two users.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute("SELECT * FROM Messages WHERE destination = ? and sender = ? ORDER by stamp", (sender,username))
    toLoggedInUser = queryCurs.fetchall()
    queryCurs.execute("SELECT * FROM Messages WHERE destination = ? and sender = ? ORDER by stamp   ", (username,sender))
    fromLoggedInUser = queryCurs.fetchall()
    conn.commit()
    conn.close()
    return [toLoggedInUser, fromLoggedInUser]

def get_unconfirmed_messages(destination):
    """
    Gets all the messages which have not been confirmed to be received or sent.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute("SELECT * FROM Messages WHERE (destination = ? OR sender = ?) AND message_status = ? ORDER by stamp", (destination,destination,"Unconfirmed"))
    unconfirmed_messages = queryCurs.fetchall()
    conn.commit()
    conn.close()
    return unconfirmed_messages

def get_unconfirmed_messages_to_send(destination):
    """
    Gets all messages which have not been confirmed to send.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute("SELECT * FROM Messages WHERE destination = ? AND message_status = ? ORDER by stamp", (destination,"Unconfirmed"))
    unconfirmed_messages = queryCurs.fetchall()
    conn.commit()
    conn.close()
    return unconfirmed_messages

def confirm_message_received(message,message_status):
    """
    Gets all messages which have not been confirmed to be received.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute('''UPDATE Messages SET message_status=? WHERE rowid=?''', [message_status, message[0]])
    conn.commit()
    conn.close()
    return True

def get_specific_message(input_dict):
    """
    Retireves a specific message to relay out for offline messages.
    """
    conn = sqlite3.connect(DB_STRING)
    # Create a query cursor on the db connection
    queryCurs = conn.cursor()
    queryCurs.execute("SELECT * FROM Messages WHERE sender = ? and stamp = ? and hashing = ? and hash = ?", (input_dict.get('sender'),input_dict.get('stamp'),input_dict.get('hashing'),input_dict.get('hash')))
    message = queryCurs.fetchone()
    conn.commit()
    conn.close()
    return message

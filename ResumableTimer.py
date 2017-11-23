"""
This file contains the ResumableTimer class which is used to regularly report to the login server.
"""

import threading, time

class ResumableTimer:
    """
    The ResumableTimer class.

    By calling methods within this class the timer can be started or stopped.
    """
    def __init__(self, my_time, callback):
        """
        Initialisation of of the timer.
        """
        self.callback = callback
        self.my_time = my_time
        self.my_timer = threading.Timer(my_time, callback)

    def start(self):
        """
        Start the timer.
        """
        self.my_timer.start()

    def pause(self):
        """
        Pause the timer.
        """
        self.my_timer.cancel()

    def resume(self):
        """
        Restart the timer.
        """
        self.my_timer = threading.Timer(self.my_time,self.callback)
        self.my_timer.start()
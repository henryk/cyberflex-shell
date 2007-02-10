from generic_application import Application

class Passport_Application(Application):
    DRIVER_NAME = "Passport"
    
    
    AID_LIST = [
        "a0000002471001"
    ]
    
    def hello_cmd(self):
        "Print a friendly greeting. For test purposes."
        print "Hello world"
    
    COMMANDS = {
        "hello": hello_cmd,
    }

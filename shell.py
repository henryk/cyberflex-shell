# -*- coding: iso-8859-1 -*-

import os, re, binascii, sys, exceptions, traceback, inspect

try:
    import readline
except ImportError:
    pass


class Shell:
    """This class handles a shell with all the usual goodies: history, 
    tab-completion, start-up script. The readline module will be used when
    available to provide some of the functionality."""
    
    def __init__(self, basename):
        """Creates a new shell object with the specified basename. The 
        basename will be used when constructing the history and start-up script
        filenames: ~/.basename.history and ~/.basenamerc.
        
        Note that the start-up script will not be called at instantiation time
        but when starting the main-loop. This is so that you can register your
        own commands first."""
        
        if sys.modules.has_key("readline"):
            histfile = os.path.join(os.environ["HOME"], ".%s.history" % basename)
            try:
                readline.read_history_file(histfile)
            except IOError:
                pass
            import atexit
            atexit.register(readline.write_history_file, histfile)
            del histfile
            
            readline.parse_and_bind("tab: complete")
            ## FIXME basenamerc
        else:
            print >>sys.stderr, "Warning: No readline module available. Most functionality will be missing."
        
        self._commandsets = [] ## This contains command sets, it's a list of (object, dictionary) tuples
        self.basename = basename
        self.env = {}
        
        self.register_commands(self)
    
    def _make_cmdset(target, commands):
        """Convenience function for code shared between register_commands 
        and unregister_commands."""
        
        if commands is None:
            if isinstance(target, dict):
                new_target = None
                new_commands = target
            elif hasattr(target, "COMMANDS"):
                new_target = target
                new_commands = target.COMMANDS
            else:
                raise TypeError, "target must be either an object with a COMMANDS attribute or a dictionary, not %s" % type(target)
        else:
            if isinstance(commands, dict):
                new_target = target
                new_commands = commands
            else:
                raise TypeError, "commands must be a dictionary, not %s" % type(commandset)
        
        return (new_target, new_commands)
    _make_cmdset = staticmethod(_make_cmdset)
    
    def register_commands(self, target, commands=None):
        """Register an object to provide commands.
        When commands is None or not given then target must either be
        an object with a COMMANDS attribute or a dictionary mapping command
        strings to functions. When commands is given then target can be any
        object and commands must be a dictionary mapping command strings to
        functions."""
        
        new_commandset = self._make_cmdset(target, commands)
        current_commands = self.get_command_mapping()
        
        for (command,function) in new_commandset[1].items():
            if not hasattr(function, "__doc__"):
                print >>sys.stderr, "Warning: function %s does not have a docstring, bug author" % function
            old_commandset = current_commands.get(command)
            if old_commandset is not None:
                print >>sys.stderr, "Warning: command '%s' already defined from %s, new definition from %s" % (
                    command, old_commandset[0] or "Anonymous list", new_target or "Anonymous list"
                )
        
        self._commandsets.append( new_commandset )
    
    def unregister_commands(self, target, command=None):
        """Unregister an object to provide commands.
        You should provide the same parameters as in the call to 
        register_commands()."""
        
        old_commandset = self._make_cmdset(target, commands)
        return self._commandsets.remove( old_commandset )
    
    def get_command_mapping(self):
        """Returns a dictionary that maps commands to their commandsets."""
        commands = {}
        for cmdset in self._commandsets:
            for (command, function) in cmdset[1].items():
                commands[command] = cmdset
        return commands
    
    def has_command(self, name):
        """Returns whether this shell knows about a specified command."""
        for cmdset in self._commandsets:
            for (command, function) in cmdset[1].items():
                if command == name:
                    return True
        return False
    
    def help(self, name):
        """Return a dictionary with help about command named name. The dictionary
        keys are:  name, formatted_parameters, description, long_description"""
        
        for cmdset in self._commandsets:
            for (command, function) in cmdset[1].items():
                if command == name:
                    parts = function.__doc__.split("\n", 1)
                    if len(parts) != 2:
                        parts = [ e.strip() for e in (parts + ["",""])[:2] ]
                    
                    (argnames, varargs, varkw, defaults) = \
                        inspect.getargspec(function)
                    if argnames[0] == "self": ## Any better way?
                        argnames = argnames[1:]
                    
                    len_mandatory = len(argnames) - \
                        len(defaults or [])
                    argstring = " ".join(
                        [(i < len_mandatory and "%s" or "[%s]")
                            % argnames[i] for i in range(len(argnames))]
                    )
                    
                    return { "name": command,
                        "formatted_parameters": argstring,
                        "description": parts[0],
                        "long_description": parts[1]
                    }
        
        raise ValueError, "No such command '%s'" % name
    
    def cmd_exit(self):
        "Exit the shell."
        sys.exit(0)
    
    def cmd_set(self, name=None, value=None):
        "Set a variable or print current settings."
    
    SHORT_HELP_FORMATSTRING = "%(name)-20s %(description)s"
    LONG_HELP_FORMATSTRING = "%(description)s\nSynopsis: %(name)s %(formatted_parameters)s\n%(long_description)s"
    def cmd_help(self, command=None):
        "Print help, either for all commands or for a specific one."
        if command is None:
            command_list = self.get_command_mapping().keys()
            for command in command_list:
                print self.SHORT_HELP_FORMATSTRING % self.help(command)
        else:
            if self.has_command(command):
                print self.LONG_HELP_FORMATSTRING % self.help(command)
            else:
                print "No such command '%s'" % command
    
    COMMANDS = {
        "exit": cmd_exit,
        "set": cmd_set,
        "help": cmd_help
    }
    
if __name__ == "__main__":
    s = Shell("foobar")
    
    

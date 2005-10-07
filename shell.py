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
        self.env = {"print_backtrace": "true"}
        
        self.register_commands(self)
        self.fallback = None
        self.pre_hook = []
        self.post_hook = []
        self.prompt = ""
    
    def get_prompt(self):
        return self.prompt
    def set_prompt(self, prompt):
        self.prompt = prompt
    
    def register_pre_hook(self, function):
        self.pre_hook.append(function)
    
    def register_post_hook(self, function):
        self.post_hook.append(function)
    
    def unregister_pre_hook(self, function):
        self.pre_hook.remove(function)
    
    def unregister_post_hook(self, function):
        self.post_hook.remove(function)
    
    
    
    def run(self):
        """Runs a loop to read commands and execute them. This function does 
        not (normally) return."""
        
        line = ""
        
        while True:
            try:
                line = raw_input("%s> " % self.prompt)
            except EOFError:
                print ## line break (there probably was none after the prompt)
                break
            except KeyboardInterrupt:
                print ## only clear the current command
            
            try:
                self.parse_and_execute(line)
            except Exception:
                exctype, value = sys.exc_info()[:2]
                if exctype == exceptions.SystemExit:
                    raise exctype, value
                print "%s: %s" % (exctype, value)
                if self.env.get("print_backtrace", "") != "":
                    traceback.print_tb(sys.exc_info()[2])
    
    _commandregex = re.compile(r'\s*(\w+)(\s+\S.*)?')
    _argumentregex = re.compile(r"""\s*(?:"((?:[^"]|\"|\\)*)"|'([^']*)'|(\S+))(\s+\S.*)?""")
    def parse_and_execute(self, line):
        """Parses a command line and executes the associated function."""
        match = self._commandregex.match(line)
        if not match:
            return
        else:
            command =  match.group(1)
            argstring = match.group(2) and match.group(2).strip() or ""
            
            function = None
            object = None
            args = []
            command_mapping = self.get_command_mapping()
            
            if command_mapping.has_key(command):
                command_set = command_mapping[command]
                object = command_set[0] ## Implicit first argument, if set
                function = command_set[1][command] ## The actual function to call
                
                if object is not None:
                    args.append(object)
                
            else:
                if self.fallback is None:
                    print "Unknown command '%s'. Try 'help' to list known commands." % command
                else:
                    ## Fall back to the fallback function/method
                    ## It will receive the command executed as first parameter
                    args.append(command)
                    function = self.fallback
                    object = None ## fallback must be a function or a bound method
            
            if function is not None:
                (argnames, varargs, varkw, defaults) = \
                        inspect.getargspec(function)
                
                ## maximum number of arguments the function accepts
                args_possible = len(argnames) - len(args)
                ## minimum number of argument the function accepts
                args_needed = args_possible - (defaults and len(defaults) or 0)
                
                args_so_far = 0
                
                while len(argstring) > 0:
                    match = self._argumentregex.match(argstring)
                    if not match:
                        break
                    else:
                        args_so_far = args_so_far + 1
                        current_arg = match.group(1) or match.group(2) or match.group(3) or ""
                        argstring = match.group(4) or ""
                        args.append(current_arg)
                
                if args_so_far < args_needed:
                    print "The %s command takes at least %i arguments. You gave %i." % (command, args_needed, args_so_far)
                    return
                if args_so_far > args_possible:
                    print "The %s command takes at most %i arguments. You gave %i." % (command, args_possible, args_so_far)
                    return
                
                return function(*args)


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
    
    SETTINGS_FORMATSTRING="%s=%s"
    def cmd_set(self, name=None, value=None):
        "Set a variable or print current settings."
        
        if name == None and value == None:
            for (name, value) in self.env.items():
                print self.SETTINGS_FORMATSTRING % (name, value)
        elif name is not None and value is not None:
            self.env[name] = value
        else:
            raise ValueError, "Need either name and value, or no parameters at all."
    
    def cmd_unset(self, name):
        """Unset a variable."""
        if self.env.has_key(name):
            del self.env[name]

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
        "unset": cmd_unset,
        "help": cmd_help
    }
    
if __name__ == "__main__":
    s = Shell("foobar")
    s.run()
    

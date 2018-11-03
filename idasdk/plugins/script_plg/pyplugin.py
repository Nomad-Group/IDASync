import ida_idaapi, ida_kernwin

class myplugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "This is a sample Python plugin"
    help = "This is help"
    wanted_name = "My Python plugin"
    wanted_hotkey = "Alt-F8"

    def init(self):
        ida_kernwin.msg("init() called!\n")
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        ida_kernwin.msg("run() called with %d!\n" % arg)
        return (arg % 2) == 0

    def term(self):
        ida_kernwin.msg("term() called!\n")

def PLUGIN_ENTRY():
    return myplugin_t()


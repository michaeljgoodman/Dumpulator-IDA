import sys
import idaapi
import idautils
import idc
import ida_kernwin
from ida_kernwin import Choose
import ida_enum
import ida_bytes
import ida_netnode

from dumpulator import Dumpulator

__AUTHOR__ = 'Micycle'

PLUGIN_NAME = "dumpulate"
PLUGIN_HOTKEY = 'Alt+Shift+d'
VERSION = '0.0.0'


major, minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (major > 6)


#--------------------------------------------------------------------------
# Global settings
#--------------------------------------------------------------------------
def global_settings():
    global DUMP_FILE
    DUMP_FILE = ida_kernwin.ask_file(1, "*", "Enter the name of dump file:")
    print("You have selected " + DUMP_FILE)
    global dp
    dp = Dumpulator(DUMP_FILE)
    return 




#--------------------------------------------------------------------------
# Number of Args Form
#--------------------------------------------------------------------------
class arg_num_select_t(ida_kernwin.Form):
    """Simple form to select how many args to initialise"""
    def __init__(self):
        self.__n = 0
        F = ida_kernwin.Form
        F.__init__(self,
r"""BUTTON YES* Select
BUTTON CANCEL Cancel
Creating Function Arg Array

{FormChangeCb}
{cStr1} 
<##Number of args      :{iArgCount}>



""", {      'FormChangeCb': F.FormChangeCb(self.OnFormChange),
            'cStr1': F.StringLabel("<span style='float:left;'>How many arguments will you be passing?<span>", tp=F.FT_HTML_LABEL),
            'iArgCount': F.StringInput(),
        })

        
    def OnFormChange(self, fid):
        return 1

    @staticmethod
    def show():
        f = arg_num_select_t()
        f, args = f.Compile()
        # Show form
        ok = f.Execute()
        if ok == 1:
            arg_count = f.iArgCount.value
            f.Free()
            print("Initiated " + arg_count + " args in array")
            return arg_count
        else:
            f.Free()
            return None
#--------------------------------------------------------------------------
# Arg chooser Form
#--------------------------------------------------------------------------
class arg_select_t(ida_kernwin.Form):
    """Simple form to select argument"""
    def __init__(self):
        self.__n = 0
        F = ida_kernwin.Form
        F.__init__(self,
r"""BUTTON YES* Select
BUTTON CANCEL Cancel
Choose which argument to set

{FormChangeCb}
{cStr1} 
<##Argument      :{iArgNum}>



""", {      'FormChangeCb': F.FormChangeCb(self.OnFormChange),
            'cStr1': F.StringLabel("<span style='float:left;'>Which argument would you like to set?<span>", tp=F.FT_HTML_LABEL),
            'iArgNum': F.StringInput(),
        })

        
    def OnFormChange(self, fid):
        return 1

    @staticmethod
    def show():
        f = arg_select_t()
        f, args = f.Compile()
        # Show form
        ok = f.Execute()
        if ok == 1:
            arg_choice = f.iArgNum.value
            f.Free()
            print("Setting argument " + arg_choice)
            return arg_choice
        else:
            f.Free()
            return None
#--------------------------------------------------------------------------
# Dumpulator functions
#--------------------------------------------------------------------------
def emulate_func():
    """
    Emulate your function
    """

    idaapi.msg("Emulating function:\n")


    dp.call(CALL_ADDRESS, func_args)
    
    for arg in func_args:
        try:
            print("Address " + str(arg) + ": " + dp.read_str(arg))
        except:
            print("Address " + str(arg) + " could not be stringified")

    return True


def set_temp_addr_arg():
    """
    Set argument to a temp address
    """
    argument_selection = (int(arg_select_t.show()) - 1)
    if ((argument_selection)>len(func_args)):
        print("Argument " + str(argument_selection) + " doesn't exist...")
    else:
        func_args[argument_selection] = dp.allocate(256)
        print("Allocated temporary space for argument " + str(argument_selection+1) + ". Address set to " + str(hex(func_args[argument_selection])))

    return True

def set_arg():
    """
    Set argument to selected address
    """
    global first_arg
    #value = parse_highlighted_value("ERROR: Not a valid value selection\n")
    #value = copy_bytes_py3()
    value = idc.get_screen_ea()

    argument_selection = (int(arg_select_t.show()) - 1)
    if ((argument_selection)>len(func_args)):
        print("Argument " + str(argument_selection) + " doesn't exist...")
    else:
        print("Setting argument " + str(argument_selection+1) + " to " + str(hex(value)))
        func_args[argument_selection] = value

    return True

def run_single_arg():
    """
    Run with dumpulator single argument
    """
    global first_arg
    #value = parse_highlighted_value("ERROR: Not a valid value selection\n")
    #value = copy_bytes_py3()
    value = idc.get_screen_ea()
    if value is None:
        return False
    first_arg = value
    idaapi.msg("running with %s as single arg\n" % value)
    print(hex(value))

    

    temp_addr = dp.allocate(256)

    dp.call(CALL_ADDRESS, [temp_addr, first_arg])
    

    decrypted = dp.read_str(temp_addr)

    print(f"decrypted: '{decrypted}'")

    return True
    
def set_call_addr():
    """
    Set call address
    """
    value = idc.get_screen_ea()

    if value is None:
        return False
    global CALL_ADDRESS
    CALL_ADDRESS = value

    idaapi.msg("call address is set: %s\n" % value)
    print(hex(value))

    global func_args
    func_arg_num = arg_num_select_t.show()
    func_args = [0] * int(func_arg_num)
    
    return True
#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class dumpulate_Plugin_t(idaapi.plugin_t):
    """
    IDA Plugin for Dumpulate
    """
    comment = "Dumpulate"
    help = ""
    wanted_name = PLUGIN_NAME
    # We only want a hotkey for the actual hash lookup
    wanted_hotkey = ''
    flags = idaapi.PLUGIN_KEEP

    #--------------------------------------------------------------------------
    # Plugin Overloads
    #--------------------------------------------------------------------------
    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """
        global p_initialized

        # Check if already initialized 
        if p_initialized is False:
            p_initialized = True
            ## Print a nice header
            print("You've taken your dump... It's time to play with it")
            # initialize the menu actions our plugin will inject
            self._init_action_run_single_arg()
            self._init_action_set_call_addr()
            self._init_action_set_temp_addr_arg()
            self._init_action_set_arg()
            self._init_action_emulate_func()
            # initialize plugin hooks
            self._init_hooks()
            return idaapi.PLUGIN_KEEP


    def run(self, arg):
        """
        This is called by IDA when the plugin is run from the plugins menu
        """
        global_settings()
        


    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """
        
        # unhook our plugin hooks
        self._hooks.unhook()
        # unregister our actions & free their resources
        self._del_action_run_single_arg()
        self._del_action_set_call_addr()
        self._del_action_set_temp_addr_arg()
        self._del_action_set_arg()
        self._del_action_emulate_func
        # done
        idaapi.msg("%s terminated...\n" % self.wanted_name)


    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------
    ACTION_RUN_SINGLE_ARG  = "dumpulate:runsinglearg"
    ACTION_SET_CALL_ADDR = "dumpulate:setcalladdr"
    ACTION_SET_TEMP_ADDR_ARG = "dumpulate:settempaddrarg"
    ACTION_SET_ARG = "dumpulate:setarg"
    ACTION_EMULATE_FUNC = "dumpulate:emulatefunc"
    
    def _init_action_run_single_arg(self):
        """
        Register the run single arg action with IDA.
        """
        action_desc = idaapi.action_desc_t(
            self.ACTION_RUN_SINGLE_ARG,         # The action name.
            "Dumpulate run with single arg",                     # The action text.
            IDACtxEntry(run_single_arg),        # The action handler.
            None,                  # Optional: action shortcut
            "Run with single arg"   # Optional: tooltip
            
        )
        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _init_action_set_call_addr(self):
        """
        Register the set call address action with IDA.
        """
        action_desc = idaapi.action_desc_t(
            self.ACTION_SET_CALL_ADDR,         # The action name.
            "Dumpulate Set Call Address",                     # The action text.
            IDACtxEntry(set_call_addr),        # The action handler.
            None,                  # Optional: action shortcut
            "Set call address"   # Optional: tooltip
            
        )
        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _init_action_set_temp_addr_arg(self):
        """
        Register the set temp addr arg action with IDA.
        """
        action_desc = idaapi.action_desc_t(
            self.ACTION_SET_TEMP_ADDR_ARG,         # The action name.
            "Dumpulate Allocate Temp For Argument",                     # The action text.
            IDACtxEntry(set_temp_addr_arg),        # The action handler.
            None,                  # Optional: action shortcut
            "Allocate temporary address space for arg"   # Optional: tooltip
            
        )
        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _init_action_set_arg(self):
        """
        Register the set arg action with IDA.
        """
        action_desc = idaapi.action_desc_t(
            self.ACTION_SET_ARG,         # The action name.
            "Dumpulate Set Argument",                     # The action text.
            IDACtxEntry(set_arg),        # The action handler.
            None,                  # Optional: action shortcut
            "Set arg to selected address"   # Optional: tooltip
            
        )
        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _init_action_emulate_func(self):
        """
        Register the set arg action with IDA.
        """
        action_desc = idaapi.action_desc_t(
            self.ACTION_EMULATE_FUNC,         # The action name.
            "Dumpulate Emulate Function",                     # The action text.
            IDACtxEntry(emulate_func),        # The action handler.
            None,                  # Optional: action shortcut
            "Emulate your function"   # Optional: tooltip
            
        )
        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_set_call_addr(self):
        idaapi.unregister_action(self.ACTION_SET_CALL_ADDR)

    def _del_action_run_single_arg(self):
        idaapi.unregister_action(self.ACTION_RUN_SINGLE_ARG)

    def _del_action_set_temp_addr_arg(self):
        idaapi.unregister_action(self.ACTION_SET_TEMP_ADDR_ARG)

    def _del_action_set_arg(self):
        idaapi.unregister_action(self.ACTION_SET_ARG)

    def _del_action_emulate_func(self):
        idaapi.unregister_action(self.ACTION_EMULATE_FUNC)

    #--------------------------------------------------------------------------
    # Initialize Hooks
    #--------------------------------------------------------------------------

    def _init_hooks(self):
        """
        Install plugin hooks into IDA.
        """
        self._hooks = Hooks()
        self._hooks.ready_to_run = self._init_hexrays_hooks
        self._hooks.hook()


    def _init_hexrays_hooks(self):
        """
        Install Hex-Rays hooks (when available).
        NOTE: This is called when the ui_ready_to_run event fires.
        """
        if idaapi.init_hexrays_plugin():
            idaapi.install_hexrays_callback(self._hooks.hxe_callback)


#------------------------------------------------------------------------------
# Plugin Hooks
#------------------------------------------------------------------------------
class Hooks(idaapi.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup):
        """
        A right click menu is about to be shown. (IDA 7)
        """
        inject_actions(widget, popup, idaapi.get_widget_type(widget))
        return 0

    def hxe_callback(self, event, *args):
        """
        HexRays event callback.
        We lump this under the (UI) Hooks class for organizational reasons.
        """

        #
        # if the event callback indicates that this is a popup menu event
        # (in the hexrays window), we may want to install our menu
        # actions depending on what the cursor right clicked.
        #

        if event == idaapi.hxe_populating_popup:
            form, popup, vu = args

            
            idaapi.attach_action_to_popup(
                form,
                popup,
                dumpulate_Plugin_t.ACTION_RUN_SINGLE_ARG,
                "Dumpulate - run single arg",
                idaapi.SETMENU_APP,
            )

            idaapi.attach_action_to_popup(
                form,
                popup,
                dumpulate_Plugin_t.ACTION_SET_CALL_ADDR,
                "Dumpulate - set call address",
                idaapi.SETMENU_APP,
            )

            idaapi.attach_action_to_popup(
                form,
                popup,
                dumpulate_Plugin_t.ACTION_SET_TEMP_ADDR_ARG,
                "Dumpulate - set temp addr arg",
                idaapi.SETMENU_APP,
            )

            idaapi.attach_action_to_popup(
                form,
                popup,
                dumpulate_Plugin_t.ACTION_SET_ARG,
                "Dumpulate - set argument",
                idaapi.SETMENU_APP,
            )

            idaapi.attach_action_to_popup(
                form,
                popup,
                dumpulate_Plugin_t.ACTION_EMULATE_FUNC,
                "Dumpulate - emulate function",
                idaapi.SETMENU_APP,
            )

        # done
        return 0

#------------------------------------------------------------------------------
# Prefix Wrappers
#------------------------------------------------------------------------------
def inject_actions(form, popup, form_type):
    """
    Inject actions to popup menu(s) based on context.
    """

    #
    # disassembly window
    #

    if (form_type == idaapi.BWN_DISASMS) or (form_type == idaapi.BWN_PSEUDOCODE):
        # insert the action entry into the menu
        #

        idaapi.attach_action_to_popup(
            form,
            popup,
            dumpulate_Plugin_t.ACTION_RUN_SINGLE_ARG,
            "Dumpulate run with single arg",
            idaapi.SETMENU_APP
        )

        idaapi.attach_action_to_popup(
            form,
            popup,
            dumpulate_Plugin_t.ACTION_SET_CALL_ADDR,
            "Dumpulate set call address",
            idaapi.SETMENU_APP
        )

        idaapi.attach_action_to_popup(
            form,
            popup,
            dumpulate_Plugin_t.ACTION_SET_TEMP_ADDR_ARG,
            "Dumpulate set temp addr arg",
            idaapi.SETMENU_APP
        )

        idaapi.attach_action_to_popup(
            form,
            popup,
            dumpulate_Plugin_t.ACTION_SET_ARG,
            "Dumpulate set argument",
            idaapi.SETMENU_APP
        )

        idaapi.attach_action_to_popup(
            form,
            popup,
            dumpulate_Plugin_t.ACTION_EMULATE_FUNC,
            "Dumpulate Emulate Function",
            idaapi.SETMENU_APP
        )

    # done
    return 0

#------------------------------------------------------------------------------
# IDA ctxt
#------------------------------------------------------------------------------

class IDACtxEntry(idaapi.action_handler_t):
    """
    A basic Context Menu class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        self.action_function()
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return idaapi.AST_ENABLE_ALWAYS


#--------------------------------------------------------------------------
# Plugin Registration
#--------------------------------------------------------------------------

# Global flag to ensure plugin is only initialized once
p_initialized = False

# Register IDA plugin
def PLUGIN_ENTRY():
    return dumpulate_Plugin_t()

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


#temp stuff for big dumpy boi
dp = Dumpulator("StringEncryptionFun_x64.dmp")


major, minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (major > 6)


#--------------------------------------------------------------------------
# Global settings
#--------------------------------------------------------------------------
def global_settings():
    print("No settings yet.")
    return 



#--------------------------------------------------------------------------
# dumpulate functions
#--------------------------------------------------------------------------
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
    if CALL_ADDRESS:
        dp.call(CALL_ADDRESS, [temp_addr, first_arg])
    else:
        idaapi.msg("Please set a call address first...")

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
        # done
        idaapi.msg("%s terminated...\n" % self.wanted_name)


    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------
    ACTION_RUN_SINGLE_ARG  = "dumpulate:setarg"
    ACTION_SET_CALL_ADDR = "dumpulate:setcalladdr"
    
    def _init_action_run_single_arg(self):
        """
        Register the set arg action with IDA.
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
        Register the set arg action with IDA.
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

    def _del_action_set_call_addr(self):
        idaapi.unregister_action(self.ACTION_SET_CALL_ADDR)

    def _del_action_run_single_arg(self):
        idaapi.unregister_action(self.ACTION_RUN_SINGLE_ARG)

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
                "Dumpulate - set arg",
                idaapi.SETMENU_APP,
            )

            idaapi.attach_action_to_popup(
                form,
                popup,
                dumpulate_Plugin_t.ACTION_SET_CALL_ADDR,
                "Dumpulate - set call address",
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
            "Dumpulate set arg",
            idaapi.SETMENU_APP
        )

        idaapi.attach_action_to_popup(
            form,
            popup,
            dumpulate_Plugin_t.ACTION_SET_CALL_ADDR,
            "Dumpulate set call address",
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

import os, sys
_tk_base = os.path.join(sys._MEIPASS, "tcl")
if os.path.isdir(_tk_base):
    tcl = os.path.join(_tk_base, "tcl8.6")
    tk = os.path.join(_tk_base, "tk8.6")
    if os.path.isdir(tcl):
        os.environ["TCL_LIBRARY"] = tcl
    if os.path.isdir(tk):
        os.environ["TK_LIBRARY"] = tk

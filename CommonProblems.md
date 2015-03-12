# WinDBG Debugger: "Oops! internal error 40038" or IDA freezes starting a session #

It's a known bug in WinDBG :( The (at least) public version of WinDBG doesn't support setting more than 1.000 breakpoints. Try removing some of them or change to another debugger module if possible.

**Note:** I will try to workaround this with, for example, "proximity tracing": instead of setting a breakpoint in every function in the database, MyNav will set a breakpoint in every entry point of the program and, when hitted, will set also the breakpoints for the callees of the function where the breakpoint was hitted. However, this would only work for the first session :(

# The "No data to save" message #

Verify the following points:

  1. You have selected a debugger (like Local Linux/Win32 Debugger or WinDBG, for example).
  1. You removed every breakpoint set or you have just the breakpoints you want.

Typically, this message means that no breakpoint set have been hitted and, as so, there is nothing to save.

# `ImportError`: No module named `_`sqlite3 #

Probably, you're using IDAQ in some 64 bits Linux distro and you compiled Python yourself. MyNav needs to have the Python's SQLite3 module (it's distributed with Python since 2.5).

# IDA hangs with the message dialog "Running python script" #

Add the following line to your $IDA\_DIR/python/init.py script:

```
set_script_timeout(0)
```

This bug is fixed in the current Mercurial version (Change ff660de5c8e1)

# Cannot import name `GraphViewer` #

MyNav requires IDA version 5.6 or 5.7, prior versions doesn't have support for GraphViewer so they aren't supported.
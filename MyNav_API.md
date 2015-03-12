# Python scripting with MyNav #

While MyNav may be usefull as is, sometimes, we need to perform some special tasks not implemented in the current version. In order to accomplish them using the MyNav API we may use this option and a Python script will be executed registering as global variables the following objects:

  * mynav: The current "mynav" object of type CMyNav (see mynav.py).
  * mybrowser: A module object for the "mybrowser" module.
  * myexport: A module object for the "myexport" module.

# Example python scripts using mynav API #

## Add entry and target points ##
The following sample script adds every function with a name like "**recv**" as data entry point and every function with a name like "**str**" or "**cpy**" as target points.

```
def addDefaultEntryPoints():
    for f in Functions():
        if GetFunctionName(f).find("recv") > -1:
            mynav.addPoint(f, "E") # Add the current function as entry point

def addDefaultTargetPoints():
    for f in Functions():
        if GetFunctionName(f).find("str") > -1 or GetFunctionName(f).find("cpy") > -1:
            mynav.removePoint(f, "T") # Add the current function as target point

if __name__ == "__main__":
    addDefaultEntryPoints()
    addDefaultTargetPoints()
```

## Show Windows Control Panel related function's graph ##

This script shows all the control panel related functions in a graph. Open in IDA the file shell32.dll, wait until the initial analysis finishes and run the following script:

```
def showCplFunctions():
    l = []
    for f in Functions():
        if GetFunctionName(f).find("CPL") > -1 and GetFunctionName(f).find("?") == -1 and \
           GetFunctionName(f).find("CPLD") == -1:
			l.append(f)
    
    if len(l):
        g = mybrowser.PathsBrowser("Control Panel Functions", l, [], [])
        g.Show()

if __name__ == "__main__":
	showCplFunctions()
```

## Show code refs to one function in a graph ##

The following script shows in a graph the callers of the selected function and the relationships among them:

```
from idautils import CodeRefsFrom

def showCodeRefsTo(ea):
    l = list(CodeRefsTo(ea, 1))
    #l.append(ea)

    if len(l) > 0:
        g = mybrowser.PathsBrowser("Code Refs to", l, [], [])
        g.Show()
    else:
        info("No code refs to the current point!")

if __name__ == "__main__":
    showCodeRefsTo(ScreenEA())
```
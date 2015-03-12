# Menu Items: All MyNav features #

In MyNav there are a lot of menu items and somewhat hidden options to accomplish many tasks. The following is a comprehensive list of every menu item and every option or utility.

# Browse Function #

Open a function's browser showing all code references to functions from the selected function.

Related video tutorial:

  * [Analyzing Windows Kernel32.dll!CreateFileA function](http://joxeankoret.com/video/navigator.htm)

# New session #

Start a new differential debugging session (refer to the section "Differential debugging" in the [features page](Features.md) for more details). If no breakpoint is set the user will be asked to set a breakpoint in every discovered function in the database.

Related video tutorial:

  * [Analyzing Adobe Acrobat Reader's JavaScript plugin](http://joxeankoret.com/video/acrobatjs.htm)

# Trace in session #

Normal sessions started with the command "New session" are functions level sessions, i.e., the unique information recorded is what functions were executed. Trace sessions are instruction level sessions: when you already have a function level session you select this option to trace every instruction belonging to the functions related to the session.

Related video tutorial:

> [Analyzing Adobe Acrobat Reader's JavaScript plugin](http://joxeankoret.com/video/acrobatjs.htm)

# Trace this function #

Like "trace in session" but you only trace the function at cursor.

# Configure timeout #

When recording a session you have 2 ways to tell MyNav the session is over: Stop the program or configure a timeout. For example, if you're debugging a server application you don't want to start and stop it every time you want to test a feature so you can configure a timeout, record a session and it will be considered finished when the timeout is reached.

# Configure CPU recording #

Due to performance, by default, MyNav sets trace brekapoints to record sessions (either function or trace level sessions) and only records the $PC. If you set CPU recording to true every processor register's value will be stored in the SQLite database.

# Show session #

Select this option to see in a graph a previously recorded function level session.

# Show trace session #

Select this option to colorize every instruction executed in a previously recorded trace session.

# Session's function list #

Select this option if you prefer to see a previously recorded function level session in a normal list like the normal IDA's "Functions List".

# Clear trace session #

Trace level sessions are shown coloring executed instructions. Select this option to clear the color.

# Set/Clear all breakpoints #

Add (or remove) a breakpoint in every function discovered in the database.

# Select/Deselect hints from session #

Add (or remove) every breakpoint recorded in a function level session.

# Delete a session #

Delete a function level session.

# Delete ALL sessions #

Delete all sessions (either function or trace sessions).

# Add/Remove target or entry point #

Add (or remove) the function at the cursor as data entry point (functions where you can input data to the application, like socket\_recv, etc...) or target point (vulnerable functions or functions where you want to reach code execution for some reason).

# Show advanced options #
## Show entry points ##

Show in a graph every function added as entry point and the relationships (if any) between them.

## Show target points ##

Show in a graph every function added as target point and the relationships (if any) between them.

## Show code paths between points ##

Show in a graph the relationships between functions selected as entry points and target points.

## Show code paths between 2 functions ##

Show in a graph the relationships between 2 functions. A dialog box is shown to select the functions.

## Show all functions in this segment ##

Show in a graph every function in the current (at the cursor) segment and the relationships between them.
USE WITH CAUTION!

## Show all breakpoints graph ##

Show in a graph every function where a breakpoint is set (either manually or by MyNav) and the relationships between them.

# New advanced session #
## Trace code paths between points ##

Set a breakpoint in every function between entry points and target points and start a new function level session.

## Trace code paths 2 functions ##

Set a breakpoint in every function between 2 functions and start a new function level session. A dialog box will be shown to select the 2 functions.

# Advanced selection/deselection options #
## Function's childs ##

Add (or remove) a breakpoint in the function at the cursor and every function called from here.

## Code paths between points ##

Add (or remove) a breakpoint in every function between entry points and target points.

## Code paths between 2 functions ##

Add (or remove) a breakpoint in every function between 2 functions. A dialog box will be shown to select the 2 functions.

## All functions in this segment ##

Add (or remove) a breakpoint in every function in the current (at the cursor) segment.

# Advanced utilities #

## Search string in session ##

When CPU recording is enabled every register's value is recorded as well as ASCII strings pointed directly from a register's value. With this option you can see, in a graph, in what functions some string where used/accessed. Leave the field in blank to show a graph with every recorded string.

## Export database's functions ##

Export to one SQLite database every function with a name different to "j**_" and "sub_**".
See the section "Function's names importer/exporter" in the [features page](Features.md) for more details.

Related video tutorials:

  * [Exporting and importing symbols](http://joxeankoret.com/video/exportimport.htm)

## Import database's functions ##

Try to import from one SQLite database every function matching those in the current IDA's database.
See the section "Function's names importer/exporter" in the [features page](Features.md) for more details.


Related video tutorials:

  * [Exporting and importing symbols](http://joxeankoret.com/video/exportimport.htm)

## Search new functions in this segment ##

Use this option to try to search for functions not discovered by IDA during initial analysis.

## Analyze the current segment ##

Equivalent to the following python code:

```
    AnalyzeArea(SegStart(here()), SegEnd(here()))
```

## Analyze complete program ##

Equivalent to the following python code:

```
    AnalyzeArea(MinEA(), MaxEA())
```

Usefull, for example, when you added new segments to the database in a debugging session with the command "Take memory snapshot".

## Analyze this segment and search new functions ##

Analyze the current segment and search for new functions not discovered by IDA.

# Run a python script #

While MyNav may be usefull as is, sometimes, we need to perform some special tasks not implemented in the current version. In order to accomplish them using the MyNav API we may use this option and a Python script will be executed registering as global variables the following objects:

  * The current "mynav" object of type CMyNav (see mynav.py).
  * mybrowser: A module object for the "mybrowser" module.
  * myexport: A module object for the "myexport" module.
MyNav Project: http://mynav.googlecode.com
==========================================

Summary
=======

MyNav is an Open Source plugin for IDA Pro which aims to help reverse engineers doing the most typical tasks.

License
=======

MyNav is licensed under the GPL v2.

Features
========

As of version 1.0, MyNav supports the following features:

    - Differential debugging.
    - Function's browser.
    - Code paths searching.
        - Entry points and target points definition.
    - Function's names importer and exporter.

Differential debugging
======================

Differential debugging in MyNav is implemented using breakpoints. The breakpoints can be set at the 1st instruction of the selected functions (for normal sessions) or in every instruction (for trace sessions). The breakpoints can be either normal breakpoints or trace breakpoints: With trace breakpoints only the $PC register is recorded and with normal breakpoints every register's value is recorded.

Function's Browser
==================

The function's browser shows in a navigable GUI every function called from the selected function either showing API calls or not. As simply as it is.

Code Paths Searching
====================

This feature allows to search code paths between either 2 functions or "points". Points are functions selected by the reverse engineer as either "entry points" (points where you can input data to the application) or "target points" (points where you can reach code execution).

Function's names importer/exporter
==================================

This feature allows to export every function in the database with a name different to "sub_*" or "j_*" to one SQLite database to be imported later in another database. For every function the following data is recorded (in order to be used later for matching the exact function in other databases):

    - Number of basic blocks, number of edges, indegree and outdegree.
    - Mnemonics, number of instructions and size (in bytes) of the function.

Menu Items: All MyNav features
==============================

In MyNav there are a lot of menu items and somewhat hidden options to accomplish many tasks. The following is a comprehensive list of every menu item and every option or utility.

MyNav: Browse Function
======================

Open a function's browser showing all code references to functions from the selected function.

MyNav: New session
==================

Start a new differential debugging session (refer to the section "Differential debugging" for more details). If no breakpoint is set the user will be asked to set a breakpoint in every discovered function in the database.

Related video tutorial: 

   Analyzing Adobe Acrobat Reader's JavaScript plugin 
   http://joxeankoret.com/video/acrobatjs.htm

MyNav: Trace in session
=======================

Normal sessions started with the command "New session" are functions level sessions, i.e., the unique information recorded is what functions were executed. Trace sessions are instruction level sessions: when you already have a function level session you select this option to trace every instruction belonging to the functions related to the session.

Related video tutorial: 

   Analyzing Adobe Acrobat Reader's JavaScript plugin 
   http://joxeankoret.com/video/acrobatjs.htm

MyNav: Trace this function
==========================

Like "trace in session" but you only trace the function at cursor.

MyNav: Configure timeout
========================

When recording a session you have 2 ways to tell MyNav the session is over: Stop the program or configure a timeout. For example, if you're debugging a server application you don't want to start and stop it every time you want to test a feature so you can configure a timeout, record a session and it will be considered finished when the timeout is reached.

MyNav: Configure CPU recording
==============================

Due to performance, by default, MyNav sets trace brekapoints to record sessions (either function or trace level sessions) and only records the $PC. If you set CPU recording to true every processor register's value will be stored in the SQLite database.

MyNav: Show session
===================

Select this option to see in a graph a previously recorded function level session.

MyNav: Show trace session
=========================

Select this option to colorize every instruction executed in a previously recorded trace session.

MyNav: Session's function list
==============================

Select this option if you prefer to see a previously recorded function level session in a normal list like the normal IDA's "Functions List".

MyNav: Clear trace session
==========================

Trace level sessions are shown coloring executed instructions. Select this option to clear the color.

MyNav: Set/Clear all breakpoints
================================

Add (or remove) a breakpoint in every function discovered in the database.

MyNav: Select/Deselect hints from session
=========================================

Add (or remove) every breakpoint recorded in a function level session.

MyNav: Delete a session
=======================

Delete a function level session.

MyNav: Delete ALL sessions
==========================

Delete all sessions (either function or trace sessions).

MyNav: Add/Remove target or entry point
=======================================

Add (or remove) the function at the cursor as data entry point (functions where you can input data to the application, like socket_recv, etc...) or target point (vulnerable functions or functions where you want to reach code execution for some reason).

MyNav: Show advanced options -> Show entry points
=================================================

Show in a graph every function added as entry point and the relationships (if any) between them.

MyNav: Show advanced options -> Show target points
==================================================

Show in a graph every function added as target point and the relationships (if any) between them.

MyNav: Show advanced options -> Show code paths between points
==============================================================

Show in a graph the relationships between functions selected as entry points and target points.

MyNav: Show advanced options -> Show code paths between 2 functions
===================================================================

Show in a graph the relationships between 2 functions. A dialog box is shown to select the functions.

MyNav: Show advanced options -> Show all functions in this segment
==================================================================

Show in a graph every function in the current (at the cursor) segment and the relationships between them.
USE WITH CAUTION!

MyNav: Show advanced options -> Show all breakpoints graph
==========================================================

Show in a graph every function where a breakpoint is set (either manually or by MyNav) and the relationships between them.

MyNav: New advanced session -> Trace code paths between points
==============================================================

Set a breakpoint in every function between entry points and target points and start a new function level session.

MyNav: New advanced session -> Trace code paths 2 functions
===========================================================

Set a breakpoint in every function between 2 functions and start a new function level session. A dialog box will be shown to select the 2 functions.

MyNav: Advanced selection/deselection options -> Function's childs
==================================================================

Add (or remove) a breakpoint in the function at the cursor and every function called from here.

MyNav: Advanced selection/deselection options -> Code paths between points
==========================================================================

Add (or remove) a breakpoint in every function between entry points and target points.

MyNav: Advanced selection/deselection options -> Code paths between 2 functions
===============================================================================

Add (or remove) a breakpoint in every function between 2 functions. A dialog box will be shown to select the 2 functions.

MyNav: Advanced selection/deselection options -> All functions in this segment
==============================================================================

Add (or remove) a breakpoint in every function in the current (at the cursor) segment.

MyNav: Advanced utilities -> Search string in session
=====================================================

When CPU recording is enabled every register's value is recorded as well as ASCII strings pointed directly from a register's value. With this option you can see, in a graph, in what functions some string where used/accessed. Leave the field in blank to show a graph with every recorded string.

See the following snapshot to get an idea: http://img52.imageshack.us/i/mynav7.png/

MyNav: Advanced utilities -> Export database's functions
========================================================

Export to one SQLite database every function with a name different to "j_*" and "sub_*".
See the section "Function's names importer/exporter" for more details.

MyNav: Advanced utilities -> Export database's functions
========================================================

Try to import from one SQLite database every function matching those in the current IDA's database.
See the section "Function's names importer/exporter" for more details.

MyNav: Advanced utilities -> Search new functions in this segment
=================================================================

Use this option to try to search for functions not discovered by IDA during initial analysis.

MyNav: Advanced utilities -> Analyze the current segment
========================================================

Equivalent to the following python code: 

    AnalyzeArea(SegStart(here()), SegEnd(here()))

MyNav: Advanced utilities -> Analyze complete program
=====================================================

Equivalent to the following python code: 

    AnalyzeArea(MinEA(), MaxEA())

Usefull, for example, when you added new segments to the database in a debugging session with the command "Take memory snapshot".

MyNav: Advanced utilities -> Analyze this segment and search new functions
==========================================================================

Analyze the current segment and search for new functions not discovered by IDA.

MyNav: Run a python script
==========================

While MyNav may be usefull as is, sometimes, we need to perform some special tasks not implemented in the current version. In order to accomplish them using the MyNav API we may use this option and a Python script will be executed registering as global variables the following objects: 

    mynav: The current "mynav" object of type CMyNav (see mynav.py).
    mybrowser: A module object for the "mybrowser" module.
    myexport: A module object for the "myexport" module.

Example python script using mynav API
=====================================

def addDefaultEntryPoints():
    for f in Functions():
        if GetFunctionName(f).find("recv") > -1:
            mynav.addPoint(f, "E") # Add the current function as entry point

def addDefaultTargetPoints():
    for f in Functions():
        if GetFunctionName(f).find("str") > -1 or GetFunctionName(f).find("cpy") > -1:
            mynav.removePoint(f, "T") # Add the current function as target point

Contact
=======

The author of MyNav is Joxean Koret. You can contact me using any of the following e-mail addresses:

    <admin[AT]joxeankoret[DOT]com>
    <joxeankoret[AT]yah00[DOT]es>


# Features #

As of version 1.0.1, MyNav supports the following features:

  * Differential debugging.
  * Function's browser.
  * Code paths searching.
    * Entry points and target points definition.
  * Function's names importer and exporter.

# Differential debugging #

Differential debugging in MyNav is implemented using breakpoints. The breakpoints can be set at the 1st instruction of the selected functions (for normal sessions) or in every instruction (for trace sessions). The breakpoints can be either normal breakpoints or trace breakpoints: With trace breakpoints only the $PC register is recorded and with normal breakpoints every register's value is recorded.

# Function's Browser #

The function's browser shows in a navigable GUI every function called from the selected function either showing API calls or not. As simply as it is.

# Code Paths Searching #

This feature allows to search code paths between either 2 functions or "points". Points are functions selected by the reverse engineer as either "entry points" (points where you can input data to the application) or "target points" (points where you can reach code execution).

# Function's names importer/exporter #

This feature allows to export every function in the database with a name different to "sub**_" or "j_**" to one SQLite database to be imported later in another database. For every function the following data is recorded (in order to be used later for matching the exact function in other databases):

  * Number of basic blocks, number of edges, indegree and outdegree.
  * Mnemonics, number of instructions and size (in bytes) of the function.
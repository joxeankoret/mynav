MyNav is a plugin for IDA Pro to help reverse engineers in the most typical task like discovering what functions are responsible of some specifical tasks, finding paths between "interesting" functions and data entry points.

# Features #

  * Differential debugging: Record traces of debugged processes and save them for later analysis and for discovering the specific code responsible of some feature.
  * Function's browser: Navigate through functions looking relationships among them, data string references, API calls and discovering code paths between functions.
  * Code path searching: Automatic code path searching facilities between 2 specific functions or between data entry points (points where we can input data to the application) and target points (functions where you want to reach code execution as for example vulnerable functions).

# Notes #

MyNav requires IDA Pro version >= 5.6. IDA 5.5, 5.2, etc... are not supported.
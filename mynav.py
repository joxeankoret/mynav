#!/usr/bin/python

"""
MyNav, a tool 'similar' to BinNavi
Copyright (C) 2010 Joxean Koret

Itsaslapurraren izenean, beti gogoan izango zaitugu.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
"""

import os
import sys
import time
import random
import sqlite3

from idc import (GetBptQty, GetBptEA, GetRegValue, FindText, NextAddr, GetDisasm, GetMnem,
                 GetFunctionName, MakeFunction, ItemSize, GetBptAttr, AskFile, StopDebugger)
from idaapi import (GraphViewer, dbg_can_query, askyn_c, asklong, FlowChart, get_func, info,
                   get_dbg_byte, get_idp_name, DBG_Hooks, run_requests,
                   request_run_to)
from idautils import GetRegisterList
import mybrowser
import myexport

APPLICATION_NAME = "MyNav"
VERSION = 0x01020200

COLORS = [0xfff000, 0x95AFCD, 0x4FFF4F, 0xc0ffff, 0xffffc0, 0xc0cfff, 0xc0ffcf, 0x95AFFD]

reload(sys)
sys.setdefaultencoding('utf8')
def mynav_print(msg):
    print "[%s] %s" % (APPLICATION_NAME, msg)

class FunctionsGraph(GraphViewer):
    def __init__(self, title, session):
        GraphViewer.__init__(self, title)
        self.result = session
        self.nodes = {}

    def OnRefresh(self):
        try:
            self.Clear()
            dones = []
            
            for hit in self.result:
                if not hit in dones:
                    ea = int(hit[0])
                    name = GetFunctionName(ea)
                    self.nodes[ea] = self.AddNode((ea, name))
            
            for n1 in self.nodes:
                l1 = map(GetFunctionName, list(CodeRefsTo(n1, 1)))
                l2 = map(GetFunctionName, list(DataRefsTo(n1)))
                
                for n2 in self.nodes:
                    if n1 != n2:
                        name = GetFunctionName(n2)
                        if name in l1 or name in l2:
                            self.AddEdge(self.nodes[n2], self.nodes[n1])

            return True
        except:
            print "***Error", sys.exc_info()[1]

    def OnGetText(self, node_id):
        ea, label = self[node_id]
        return label

    def OnDblClick(self, node_id):
        ea, label = self[node_id]
        Jump(ea)
        
        return True

class CMyNav:
    def __init__(self):
        # Initialize basic properties
        self.db = None
        self.filename = None
        self.debugMode = False
        self.sessions = {}
        self.records = {}
        self.timeout = 0
        self.step_mode = False
        self.step_functions = []
        random.seed(time.time())
        self.current_color = random.choice(COLORS)
        self.current_name = None
        self.default_name = "Session1"
        self.current_session = []
        self.current_session_cpu = []
        self.save_cpu = False
        self.endpoints = []
        self.temporary_breakpoints = []
        
        self.dbg_path = ""
        self.dbg_arguments = ""
        self.dbg_directory = ""
        self.on_exception = None
        
        self._loadDatabase()

    def __del__(self):
        if self.db is not None:
            self.db.close()

    def _createSchema(self):
        """ Try to create the schema or silently exit if some error ocurred. """
        try:
            sql = """CREATE TABLE NODES (
                            NODE_ID INTEGER PRIMARY KEY,
                            FUNC_ADDR VARCHAR(50),
                            STATUS INTEGER)"""
            cur = self.db.cursor()
            cur.execute(sql)
        except:
            pass
        
        try:
            sql = """CREATE TABLE GRAPHS (
                            GRAPH_ID INTEGER PRIMARY KEY,
                            NAME VARCHAR(50),
                            SHOW_STRINGS INTEGER,
                            SHOW_APIS INTEGER,
                            RECURSION_LEVEL INTEGER,
                            FATHER VARCHAR(50))"""
            cur = self.db.cursor()
            cur.execute(sql)
        except:
            pass
        
        try:
            sql = """CREATE TABLE GRAPH_NODES (
                            GRAPH_NODES_ID INTEGER PRIMARY KEY,
                            GRAPH_ID INTEGER,
                            NODE_ID INTEGER)"""
            cur = self.db.cursor()
            cur.execute(sql)
        except:
            pass
        
        try:
            sql = """CREATE TABLE POINTS (
                            POINT_ID INTEGER PRIMARY KEY,
                            FUNC_ADDR VARCHAR(50),
                            TYPE VARCHAR(50))"""
            cur = self.db.cursor()
            cur.execute(sql)
        except:
            pass
        
        try:
            sql = """CREATE TABLE SETTINGS (
                            SETTING_ID INTEGER PRIMARY KEY,
                            NAME VARCHAR(50),
                            VALUE VARCHAR(50))"""
            cur = self.db.cursor()
            cur.execute(sql)
        except:
            pass
        
        try:
            sql = """CREATE TABLE RECORDS (
                            RECORD_ID INTEGER PRIMARY KEY,
                            NAME VARCHAR(50),
                            DESCRIPTION VARCHAR(255),
                            TIMESTAMP DATETIME,
                            TYPE VARCHAR(50))"""
            cur = self.db.cursor()
            cur.execute(sql)
        except:
            pass
        
        try:
            sql = """CREATE TABLE RECORD_DATA (
                            RECORD_DATA_ID INTEGER PRIMARY KEY,
                            RECORD_ID INTEGER,
                            LINE_ID INTEGER,
                            FUNC_ADDR VARCHAR(50),
                            TIMESTAMP DATETIME)"""
            cur.execute(sql)
        except:
            pass
            
        try:
            sql = """CREATE TABLE CPU_STATE (
                            CPU_STATE_ID INTEGER PRIMARY KEY,
                            RECORD_DATA_ID INTEGER,
                            LINE_ID INTEGER,
                            REG_NAME VARCHAR(50),
                            REG_VALUE VARCHAR(255),
                            MEMORY VARCHAR(255),
                            TEXT VARCHAR(255))"""
            cur.execute(sql)
        except:
            pass
        
        try:
            sql = """CREATE VIEW SESSIONS_STRINGS
                    AS
                    SELECT rec.name session,
                           data.func_addr address,
                           cpu.text text, 
                           cpu.reg_name register, 
                           cpu.reg_value value,
                           rec.record_id id
                      FROM CPU_STATE cpu,
                           RECORDS rec,
                           RECORD_DATA data
                     WHERE CPU.TEXT IS NOT NULL 
                       AND LENGTH(CPU.TEXT) > 6
                       AND DATA.record_id = REC.record_id
                       AND CPU.record_data_id = DATA.record_data_id """
            cur.execute(sql)
        except:
            pass
        
        cur.close()
        self.db.commit()

    def _loadDatabase(self):
        """ Connect to the SQLite database and create the schema if needed """
        self.filename = "%s.sqlite" % GetInputFilePath()
        self.db = sqlite3.connect(self.filename)
        self.db.text_factory = str
        self._createSchema()

    def _debug(self, msg):
        """ Print a message if debugMode is enabled """
        if self.debugMode:
            mynav_print(msg)

    def saveSession(self, name, session, cpu):
        """ Save a session """
        if self.step_mode:
            mtype = 1
        else:
            mtype = 0
        
        cur = self.db.cursor()
        sql = "insert into records (name, description, timestamp, type) values (?, ?, ?, ?)"
        cur.execute(sql, (name, "", time.time(), mtype))
        
        i = 0
        id = cur.lastrowid
        total = len(session)
        
        for event in session:
            pct = i * 100 / total
            temp = "Saved " + str(pct) + "%"
            
            sql = """insert into record_data (record_id, line_id, func_addr, timestamp)
                                      values (?, ?, ?, ?)"""
            cur.execute(sql, (id, i, event[0], event[1]))
            m_id = cur.lastrowid
            
            if self.save_cpu:
                j = 0
                for name, val, mem, txt in cpu[i]:
                    sql = """insert into cpu_state (record_data_id, line_id, reg_name, reg_value,
                                                    memory, text)
                                              values (?, ?, ?, ?, ?, ?) """
                    cur.execute(sql, (m_id, j, name, "0x%08x" % val, mem, txt))
                    j += 1
            i += 1
        
        self.db.commit()
        
        return id

    def readSetting(self, setting):
        """ Read some configuration setting """
        cur = self.db.cursor()
        sql = "select value from settings where name = ?"
        cur.execute(sql, (setting,))
        val = None
        for row in cur.fetchall():
            val = row[0]
        cur.close()
        return val

    def saveSetting(self, setting, value):
        """ Save a configuration setting """
        old_value = self.readSetting(setting)
        if not old_value:
            sql = """ insert into settings (value, name) values (?, ?)"""
        else:
            sql = """ update settings set value = ? where name = ?"""
        
        cur = self.db.cursor()
        cur.execute(sql, (value, setting))
        self.db.commit()
        return True

    def addPoint(self, ea, strtype):
        """ Add the function ea as point. strtype can be either 'E' for entry point or 'T' for target point """
        new_ea = GetFunctionAttr(ea, FUNCATTR_START)
        if not new_ea:
            new_ea = ea
        
        cur = self.db.cursor()
        sql = """ insert into points (func_addr, type) values (?, ?) """
        cur.execute(sql, (new_ea, strtype))
        self.db.commit()
        cur.close()
        
        return True

    def removePoint(self, ea, strtype):
        """ Remove the function ea as point. strtype can be either 'E' for entry point or 'T' for target point """
        new_ea = GetFunctionAttr(ea, FUNCATTR_START)
        if not new_ea:
            new_ea = ea
        cur = self.db.cursor()
        sql = """ delete from points where func_addr = ? and type = ? """
        cur.execute(sql, (new_ea, strtype))
        self.db.commit()
        cur.close()
        
        return True

    def removeDataEntryPoint(self, ea):
        """ Remove data entry point ea """
        self.removePoint(ea, "E")

    def removeTargetPoint(self, ea):
        """ Remove target point ea """
        self.removePoint(ea, "T")

    def addDataEntryPoint(self, ea):
        """ Add a data entry point """
        self.addPoint(ea, "E")
    
    def addTargetPoint(self, ea):
        """ Add a target point """
        self.addPoint(ea, "T")
    
    def addCurrentAsDataEntryPoint(self):
        """ Add current function as entry point """
        self.addDataEntryPoint(ScreenEA())
    
    def addCurrentAsTargetPoint(self):
        """ Add current function as target point """
        self.addTargetPoint(ScreenEA())

    def removeCurrentDataEntryPoint(self):
        """ Remove current entry point """
        self.removeDataEntryPoint(ScreenEA())

    def removeCurrentTargetPoint(self):
        """ Remove current target point """
        self.removeTargetPoint(ScreenEA())

    def getAllPointsList(self):
        """ Return a list with all entry and target points """
        cur = self.db.cursor()
        sql = """ select func_addr from points """
        cur.execute(sql, (strtype, ))
        
        l = []
        for row in cur.fetchall():
            l.append(row[0])
        cur.close()
        
        return l

    def getPointsList(self, strtype):
        """ Return a list with all either entry or target points. strtype can be either 'E' or 'T' """
        cur = self.db.cursor()
        sql = """ select func_addr from points where type = ? """
        cur.execute(sql, (strtype, ))
        
        l = []
        for row in cur.fetchall():
            l.append(int(row[0]))
        cur.close()
        
        return l

    def getDataEntryPointsList(self):
        l = self.getPointsList('E')
        return l

    def getTargetPointsList(self):
        l = self.getPointsList('T')
        return l

    def getPoint(self, strtype, p):
        """ Read from database an specific point """
        cur = self.db.cursor()
        sql = """ select 1 from points where type = ? and func_addr = ?"""
        cur.execute(sql, (strtype, p))
        
        l = []
        for row in cur.fetchall():
            l.append(int(row[0]))
        cur.close()
        
        return l

    def addRemoveTargetPoint(self):
        ea = GetFunctionAttr(ScreenEA(), FUNCATTR_START)
        if self.getPoint("T", ea):
            self.removeCurrentTargetPoint()
            mynav_print("Target point 0x%08x removed" % ea)
        else:
            self.addCurrentAsTargetPoint()
            mynav_print("Target point 0x%08x added" % ea)

    def addRemoveEntryPoint(self):
        ea = GetFunctionAttr(ScreenEA(), FUNCATTR_START)
        if self.getPoint("E", ea):
            self.removeCurrentDataEntryPoint()
            mynav_print("Data entry point 0x%08x removed" % ea)
        else:
            self.addCurrentAsDataEntryPoint()
            mynav_print("Data entry point 0x%08x added" % ea)

    def saveCurrentSession(self, name):
        return self.saveSession(name, self.current_session, self.current_session_cpu)

    def showTargetPoints(self):
        tps = self.getTargetPointsList()
        if len(tps) == 0:
            info("No target entry point selected!")
            return False
        
        g = mybrowser.PathsBrowser("Target points graph", tps, [], [])
        g.Show()
        
        return True

    def showDataEntryPoints(self):
        eps = self.getDataEntryPointsList()
        if len(eps) == 0:
            info("No entry point selected!")
            return False
        
        g = mybrowser.PathsBrowser("Entry points graph", eps, [], [])
        g.Show()
        
        return True

    def showPointsGraph(self):
        """ Show a graph with all entry and target points and the relationships between them """
        eps = self.getDataEntryPointsList()
        if len(eps) == 0:
            info("No entry point selected!")
            return False
        
        tps = self.getTargetPointsList()
        if len(tps) == 0:
            info("No target point selected!")
            return False
        
        l = eps
        l.extend(tps)
        
        g = mybrowser.PathsBrowser("Entry and target points graph", l, [], [])
        g.Show()
        
        return True

    def getCodePathsBetweenPoints(self):
        eps = self.getDataEntryPointsList()
        if len(eps) == 0:
            mynav_print("No entry point selected!")
            return None
        
        tps = self.getTargetPointsList()
        if len(tps) == 0:
            mynav_print("No target point selected!")
            return None
        
        mynav_print("Searching code paths between all the points, it will take a while...")
        l = []
        for p1 in eps:
            for p2 in tps:
                tmp = mybrowser.SearchCodePath(p1, p2)
                l.extend(tmp)
        
        if len(l) == 0:
            info("No data to show :(")
            return None
        
        return l, eps, tps
    
    def showCodePathsBetweenPoints(self):
        ret = self.getCodePathsBetweenPoints()
        if ret:
            l, eps, tps = ret
            if l:
                g = mybrowser.PathsBrowser("Code paths graph", l, eps, tps)
                g.Show()

    def selectCodePathsBetweenPoints(self):
        l = self.getCodePathsBetweenPoints()
        if l:
            for p in l:
                for x in p:
                    self.addBreakpoint(x)

    def deselectCodePathsBetweenPoints(self):
        l = self.getCodePathsBetweenPoints()
        if l:
            for p in l:
                for x in p:
                    DelBpt(p)

    def selectDataEntryPoints(self):
        eps = self.getDataEntryPointsList()
        for p in eps:
            self.addBreakpoint(p)

    def deselectDataEntryPoints(self):
        eps = self.getDataEntryPointsList()
        for p in eps:
            DelBpt(p)

    def tracePoints(self):
        self.preserveBreakpoints()
        self.selectCodePathsBetweenPoints()
        self.newSession()
        self.restoreBreakpoints()

    def selectTargetPoints(self):
        tps = self.getTargetPointsList()
        for p in tps:
            self.addBreakpoint(p)

    def deselectTargetPoints(self):
        tps = self.getTargetPointsList()
        for p in tps:
            DelBpt(p)

    def getSessionsList(self, mtype=0, all=False):
        if not all:
            sql = "select * from records where type=?"
        else:
            sql = "select * from records"
        
        cur = self.db.cursor()
        
        if not all:
            cur.execute(sql, (mtype, ))
        else:
            cur.execute(sql)
        
        l = []
        for row in cur.fetchall():
            s = "%s: %s %s %s" % (row[0], row[1], row[2], time.asctime(time.gmtime(row[3])))
            l.append(s)
        cur.close()
        
        return l

    def showSessions(self, mtype=0, all=False, only_first=True):
        """ Show the session's list """
        
        l = self.getSessionsList(mtype)
        chooser = Choose([], "Active Sessions", 3)
        chooser.width = 50
        chooser.list = l
        c = chooser.choose()
        
        if c > 0:
            if only_first:
                c = l[c-1].split(":")[0]
            else:
                c = [c]
        else:
            c = None
        
        return c

    def showSessionsGraph(self):
        id = self.showSessions()
        if id is not None:
            self.showGraph(id)

    def showSessionsFunctions(self):
        id = self.showSessions()
        if id is not None:
            if self.loadSession(id):
                results = []
                for hit in self.current_session:
                    ea = int(hit[0])
                    tmp_item = {}
                    tmp_item["func_name"] = GetFunctionName(ea)
                    tmp_item["xref"] = ea
                    
                    if tmp_item not in results:
                        results.append( tmp_item )
                
                if results:
                    ch2 = mybrowser.UnsafeFunctionsChoose2("%s (Functions List)" % self.current_name, self)
                    for item in results:
                        ch2.add_item(mybrowser.UnsafeFunctionsChoose2.Item(item))
                    r = ch2.show()

    def loadSession(self, id):
        cur = self.db.cursor()
        sql = "select name from records where record_id = ?"
        cur.execute(sql, (int(id), ))
        self.current_name = cur.fetchone()[0]
        self.default_name = "Trace: " + str(self.current_name)
        cur.close()
        
        sql = "select func_addr, timestamp from record_data where record_id = ?"
        cur.execute(sql, (int(id), ))
        
        self.current_session = []
        for row in cur.fetchall():
            self.current_session.append([row[0], row[1]])
        
        return len(self.current_session) > 0

    def showGraph(self, id=None, name=None):
        """ Show a graph for one specific recorded session """
        
        if id is not None:
            if not self.loadSession(id):
                mynav_print("No records found for session %s" % id)
                return
        
        g = FunctionsGraph("%s - Session %s - %s" % (APPLICATION_NAME, self.current_name, time.ctime()), self.current_session)
        g.Show()

    def addBreakpoint(self, f):
        val = self.readSetting("save_cpu")
        if val is None:
            val = 0
        
        if int(val) == 1:
            save_cpu = True
        else:
            save_cpu = False
        
        DelBpt(int(f))
        AddBpt(int(f))
        
        if not save_cpu:
            SetBptAttr(f, BPTATTR_FLAGS, BPT_TRACE)

    def setBreakpoints(self, trace=True):
        """ Set a breakpoint in every function """
        mynav_print("Setting breakpoints. Please, wait...")
        val = self.readSetting("save_cpu")
        if val is None:
            val = True
        else:
            if int(val) == 0:
                val = True
            else:
                val = False
        
        for f in list(Functions()):
            self.addBreakpoint(f)
        
        mynav_print("Done")

    def clearBreakpoints(self):
        """ Clear all breakpoints """
        mynav_print("Removing breakpoints. Please, wait...")
        i = 0
        while 1:
            ea = GetBptEA(i)
            if ea == BADADDR:
                break
            DelBpt(ea)
        mynav_print("Done")

    def getRegisters(self):
        l = []
        
        try:
            for x in idaapi.dbg_get_registers():
                name = x[0]
                try:
                    addr = idc.GetRegValue(name)
                except:
                    break
                
                bytes = None
                """try:
                    if get_dbg_byte(addr) != 0xFF:
                        for i in range(16):
                            bytes += "%02x " % get_byte(addr+i)
                        bytes = bytes.strip(" ")
                except:
                    bytes = None"""
                
                try:
                    strdata = GetString(int(addr), -1, ASCSTR_C)
                except:
                    try:
                        strdata = "Unicode: " + GetString(int(addr), -1, ASCSTR_UNICODE)
                    except:
                        strdata = None
                
                l.append([name, addr, bytes, strdata])
        except:
            print "getRegisters()", sys.exc_info()[1]

        return l

    def recordBreakpoint(self):
        try:
            
            pc = self.getPC()
            t2 = time.time()
            self.current_session.append([pc, t2])
            if self.save_cpu:
                self.current_session_cpu.append(self.getRegisters())
            
            self._debug("Hit %s:%08x" % (GetFunctionName(pc), pc))
            if self.step_mode:
                SetColor(pc, 1, self.current_color)
            
            """if not all:
                DelBpt(pc)"""
            DelBpt(pc)
            """
            if self.endRecording(pc):
                mynav_print("Session's endpoint reached")
            """
        except:
            print "recordBreakpoint:", sys.exc_info()[1]

    def stop(self):
        StopDebugger()

    def startRecording(self, all=False):
        """ Start recording breakpoint hits """
        """if not dbg_can_query():
            info("Select a debugger first!")
            return False"""
        
        StartDebugger(self.dbg_path, self.dbg_arguments, self.dbg_directory)
        
        t = time.time()
        if self.timeout != 0:
            mtimeout = min(self.timeout, 10)
        else:
            mtimeout = 10
        last = -1
        
        while 1:
            #WFNE_CONT|WFNE_SUSP
            code = GetDebuggerEvent(WFNE_ANY|WFNE_CONT|WFNE_SUSP, mtimeout)
            
            if code == BREAKPOINT or code == STEP and last != BREAKPOINT:
                pc = GetEventEa()
                t2 = time.time()
                self.current_session.append([pc, t2])
                if self.save_cpu:
                    self.current_session_cpu.append(self.getRegisters())
                self._debug("Hit %s:%08x" % (GetFunctionName(pc), pc))
                if self.step_mode:
                    SetColor(pc, 1, self.current_color)
                
                if not all:
                    DelBpt(pc)
                if self.endRecording(pc):
                    mynav_print("Session's endpoint reached")
                    break
            elif code == INFORMATION:
                #print "INFORMATION"
                pass
            elif GetProcessState() != DSTATE_RUN:
                if GetEventExceptionCode() != 0 and self.on_exception is not None:
                    self.on_exception(GetEventEa(), GetEventExceptionCode())
                break
            elif code in [EXCEPTION, 0x40]:
                #print "**EXCEPTION", hex(GetEventEa()), hex(GetEventExceptionCode())
                if self.on_exception is not None:
                    self.on_exception(GetEventEa(), GetEventExceptionCode())
            elif code not in [DBG_TIMEOUT, PROCESS_START, PROCESS_EXIT, THREAD_START,
                              THREAD_EXIT, LIBRARY_LOAD, LIBRARY_UNLOAD, PROCESS_ATTACH,
                              PROCESS_DETACH, STEP]:
                print "DEBUGGER: Code 0x%08x" % code
            
            last = code
            if time.time() - t > self.timeout and self.timeout != 0:
                mynav_print("Timeout, exiting...")
                break

    def endRecording(self, ea):
        """ End recording breakpoint hits """
        return ea in self.endpoints

    def intersectHits(self, rec1, rec2):
        """ Return the intersection of 2 recorded sessions """
        pass

    def showIntersectionGraph(self, inter):
        """ Show a graph with the given intersection """
        pass

    def showUniqueInGraph(self, rec1, rec2):
        """ Show a graph with the nodes uniques in rec1 and not in rec2 """
        pass

    def getPC(self):
        try:
            pc = GetEventEa()
            return pc
        except:
            print "getPc", sys.exc_info()[1]

    def start(self, do_show=True, session_name=None):
        if session_name is None:
            name = AskStr(self.default_name, "Enter new session name")
        else:
            name = session_name
        
        if name:
            if GetBptEA(0) == BADADDR:
                res = AskYN(1, "There is no breakpoint set. Do you want to set breakpoints in all functions?")
                if res == 1:
                    self.setBreakpoints()
                elif res == -1:
                    return
            
            val = self.readSetting("timeout")
            if val is not None:
                self.timeout = int(val)
            
            val = self.readSetting("save_cpu")
            if val is None:
                self.save_cpu = False
            elif int(val) == 1:
                self.save_cpu = True
            else:
                self.save_cpu = False
            
            self.current_name = name
            self.current_session = []
            self.current_session_cpu = []
            try:
                mynav_print("Starting debugger ...")
                self.startRecording()
            except:
                print sys.exc_info()[1]
                mynav_print("Cancelled by user")
            
            mynav_print("Saving current session ...")
            id = None
            if len(self.current_session) > 0:
                id = self.saveCurrentSession(name)
                if not self.step_mode and do_show:
                    if len(self.current_session) > 100:
                        if askyn_c(1, "There are %d node(s), it will take a long while to show the graph. Do you want to show it?" % len(self.current_session)) == 1:
                            self.showGraph()
                    else:
                        self.showGraph()
                
                self.current_session = []
                self.current_session_cpu = []
            else:
                mynav_print("No data to save")
            
            mynav_print("OK, all done")
            return id

    def newSession(self):
        self.step_mode = False
        self.start()

    def clearSessions(self):
        if AskYN(0, "Are you sure to delete *ALL* saved sessions?") == 1:
            cur = self.db.cursor()
            cur.execute("delete from records")
            cur.execute("delete from record_data")
            cur.execute("delete from cpu_state")
            self.db.commit()
            cur.close()
            mynav_print("Done")

    def deleteSession(self):
        l = self.showSessions(all=True, only_first=False)
        
        if l is not None:
            for id in l:
                cur = self.db.cursor()
                cur.execute("delete from records where record_id = ?", (str(id),))
                cur.execute("delete from record_data where record_id = ?", (str(id),))
                cur.execute("delete from cpu_state where record_data_id = ?", (str(id),))
                self.db.commit()
                cur.close()
                mynav_print("Deleted session %s" % str(id))

    def loadBreakpointsFromSession(self):
        l = self.showSessions(only_first=False)
        if l is not None:
            for c in l:
                self.loadSession(c)
                self.clearBreakpoints()
                for addr in self.current_session:
                    self.addBreakpoint(int(addr[0]))
                mynav_print("Done loading " + str(c))

    def loadBreakpointsFromSessionInverse(self):
        l = self.showSessions(only_first=False)
        if l is not None:
            for c in l:
                self.loadSession(c)
                #self.setBreakpoints()
                for addr in self.current_session:
                    DelBpt(int(addr[0]))
                mynav_print("Done unloading " + str(c))

    def preserveBreakpoints(self):
        self.temporary_breakpoints = []
        i = 0
        while 1:
            ea = GetBptEA(i)
            if ea == BADADDR:
                break
            self.temporary_breakpoints.append(ea)
            i += 1
    
    def restoreBreakpoints(self):
        for bpt in self.temporary_breakpoints:
            self.addBreakpoint(bpt)
        self.temporary_breakpoints = []

    def traceInSession(self):
        c = self.showSessions(mtype=0)
        if c is not None:
            if not self.loadSession(c):
                return
            
            self.preserveBreakpoints()
            
            self.step_mode = True
            self.current_color = random.choice(COLORS)
            self.step_functions = []
            for addr in self.current_session:
                for ea in FuncItems(int(addr[0])):
                    self.addBreakpoint(ea)
            
            self.start()
            
            self.clearBreakpoints()
            self.restoreBreakpoints()

    def clearTraceSession(self):
        l = self.showSessions(mtype=1, only_first=False)
        if l is not None:
            for c in l:
                self.loadSession(c)
                for addr in self.current_session:
                    SetColor(int(addr[0]), 1, 0xFFFFFFFF)

    def showTraceSession(self):
        c = self.showSessions(mtype=1)
        if c is not None:
            self.loadSession(c)
            self.current_color = random.choice(COLORS)
            for addr in self.current_session:
                SetColor(int(addr[0]), 1, self.current_color)

    def showSimplifiedTraceSession(self):
        pass

    def setBreakpointsInFunction(self, func):
        pass

    def traceInFunction(self):
        self.step_mode = True
        self.current_color = random.choice(COLORS)
        ea = ScreenEA()
        self.step_functions = [ea]
        self.preserveBreakpoints()
        self.clearBreakpoints()
        for x in FuncItems(ea):
            self.addBreakpoint(x)
        
        self.start()
        self.clearBreakpoints()
        self.restoreBreakpoints()

    def doNothing(self):
        pass

    def getGraphList(self):
        cur = self.db.cursor()
        sql = """select graph_id || ':' || name from graphs"""
        cur.execute(sql)
        
        l = []
        for row in cur.fetchall():
            l.append(row[0])
        cur.close()
        
        return l

    def showSavedGraphs(self):
        l = self.getGraphList()
        chooser = Choose([], "Active Sessions", 3)
        chooser.width = 50
        chooser.list = l
        c = chooser.choose()
        
        if c > 0:
            c = l[c-1].split(":")[0]
        else:
            c = None
        
        return c

    def showBrowser(self):
        mybrowser.ShowFunctionsBrowser(mynav=self)
    
    def loadSavedGraphNodes(self, graph_id):
        cur = self.db.cursor()
        sql = """ select func_addr, status
                    from graph_nodes gn,
                         graphs g,
                         nodes n
                   where gn.graph_nodes_id = g.graph_id
                     and gn.node_id = n.node_id
                     and g.graph_id = ?"""
        cur.execute(sql, (graph_id, ))
        n = []
        h = []
        for row in cur.fetchall():
            if int(row[1]) == 1:
                n.append(int(row[0]))
            else:
                h.append(int(row[0]))
        cur.close()
        
        return n, h

    def saveGraph(self, father, max_level, show_runtime_functions, show_string, hidden, result):
        pass

    def loadSavedGraphData(self, graph_id):
        cur = self.db.cursor()
        sql = """ select name, father, recursion_level, show_strings, show_apis
                    from graphs
                   where graph_id = ? """
        cur.execute(sql, (graph_id,))
        ea = level = strings = runtime = None
        for row in cur.fetchall():
            name = row[0]
            ea = int(row[1])
            level = int(row[2])
            strings = int(row[3]) == 1
            runtime = int(row[4]) == 1
        cur.close()
        
        return name, ea, level, strings, runtime

    def loadSavedGraph(self, graph_id):
        nodes, hidden = self.loadSavedGraphNodes(graph_id)
        name, ea, level, strings, runtime = self.loadSavedGraphData(graph_id)
        mybrowser.ShowGraph(name, ea, nodes, hidden, level, strings, runtime, self)

    def openSavedGraph(self):
        g = self.showSavedGraphs()
        if g:
            self.loadSavedGraph(g)

    def showBrowser2(self):
        mybrowser.ShowFunctionsBrowser(show_runtime=True, mynav=self)

    def traceFromThisFunction(self):
        self.preserveBreakpoints()
        self.selectFunctionChilds()
        self.newSession()
        self.restoreBreakpoints()

    def deselectFunctionChilds(self):
        self.selectFunctionChilds(False)

    def selectFunctionChilds(self, badd=True):
        self.done_functions = []
        self.addChildsBpt(ScreenEA(), badd)
        if badd:
            mynav_print("Added a total of %d breakpoints" % len(self.done_functions))
        self.done_functions = []

    def addChildsBpt(self, ea, badd=True):
        if not ea in self.done_functions:
            if badd:
                mynav_print("Adding breakpoint at 0x%08x:%s" % (ea, GetFunctionName(ea)))
            self.done_functions.append(ea)
            if badd:
                self.addBreakpoint(ea)
            else:
                DelBpt(ea)
        
        refs = mybrowser.GetCodeRefsFrom(ea)
        for ref in refs:
            if ref in self.done_functions:
                continue
            self.done_functions.append(ref)
            if badd:
                mynav_print("Adding breakpoint at 0x%08x:%s" % (ref, GetFunctionName(ref)))
                self.addBreakpoint(ref)
            else:
                DelBpt(ref)
            
            self.addChildsBpt(ref, badd)

    def selectCodePaths(self):
        nodes = mybrowser.SearchCodePathDialog(ret_only=True)
        if nodes is not None:
            if len(nodes) > 0:
                for node in nodes:
                    mynav_print("Adding breakpoint at 0x%08x:%s" % (node, GetFunctionName(node)))
                    self.addBreakpoint(node)
                return True
        return False

    def traceCodePaths(self):
        self.preserveBreakpoints()
        if self.selectCodePaths():
            self.newSession()
        self.restoreBreakpoints()

    def deselectCodePaths(self):
        nodes = mybrowser.mybrowser.SearchCodePathDialog(ret_only=True)
        if len(nodes) > 0:
            for node in nodes:
                DelBpt(node)

    def selectExtendedCodePaths(self):
        nodes = mybrowser.mybrowser.SearchCodePathDialog(ret_only=True, extended=True)
        if len(nodes) > 0:
            for node in nodes:
                mynav_print("Adding breakpoint at 0x%08x:%s" % (node, GetFunctionName(node)))
                self.addBreakpoint(node)

    def deselectExtendedCodePaths(self):
        nodes = mybrowser.mybrowser.SearchCodePathDialog(ret_only=True, extended=True)
        if len(nodes) > 0:
            for node in nodes:
                DelBpt(node)
    
    def configureTimeout(self):
        val = self.readSetting("timeout")
        if val is None:
            val = 0
        
        val = asklong(int(val), "Timeout for the session")
        if val is not None:
            self.saveSetting("timeout", val)

    def propagateBreakpointChanges(self):
        count = GetBptQty()
        for i in range(0, count):
            f = GetBptEA(i)
            DelBpt(f)
            self.addBreakpoint(f)
        mynav_print("Changes applied")

    def configureSaveCPU(self):
        changed = False
        val = self.readSetting("save_cpu")
        if val is None:
            val = 0
        else:
            val = int(val)
        
        if val == 1:
            val = askyn_c(1, "Do you want to *DISABLE* CPU recording?")
            if val == 1:
                self.saveSetting("save_cpu", 0)
                changed = True
        else:
            val = askyn_c(1, "Do you want to *ENABLE* CPU recording?")
            if val == 1:
                self.saveSetting("save_cpu", 1)
                changed = True
        
        if changed:
            if askyn_c(1, "Do you want to apply changes to the currently set breakpoints?"):
                self.propagateBreakpointChanges()

    def showSegmentsGraph(self):
        ea = ScreenEA()
        l = list(Functions(SegStart(ea), SegEnd(ea)))
        
        if len(l) > 0:
            g = mybrowser.PathsBrowser("Current segment's function's graph", l, [], [])
            g.Show()
        else:
            info("No function in this segment!")

    def showBreakpointsGraph(self):
        l = []
        count = GetBptQty()
        for i in range(0, count):
            l.append(GetBptEA(i))
        
        if len(l) > 0:
            g = mybrowser.PathsBrowser("Breakpoints graph", l, [], [])
            g.Show()
        else:
            info("No breakpoint set!")

    def doDiscoverFunctions(self):
        ea = ScreenEA()
        old_ea = ea
        start_ea = SegStart(ea)
        #print "Start at 0x%08x" % start_ea
        end_ea = SegEnd(ea)
        #print "End at 0x%08x" % end_ea
        #ea2 = MaxEA()
        t = time.time()
        val = 1000
        
        while ea != BADADDR and ea < end_ea:
            tmp = ea
            val = min(1000, end_ea - ea)
            ea = FindText(tmp, SEARCH_REGEX|SEARCH_DOWN, val, 0, "# End of| endp|align |END OF FUNCTION")
            
            if time.time() - t > 60:
                val = askyn_c(1, "The process is taking too long. Do you want to continue?")
                if val is None:
                    return False
                elif val != 1:
                    return False
                else:
                    t = time.time()
            
            if ea != BADADDR and ea < end_ea:
                ea += ItemSize(ea)
                if ea != BADADDR and ea < end_ea:
                    txt = GetDisasm(ea)
                    
                    if txt.startswith("align ") or txt.startswith("db ") or txt.endswith(" endp") \
                       or txt.find("END OF FUNCTION") > -1:
                        ea = ea + ItemSize(ea)
                    
                    if ea < end_ea:
                        if GetMnem(ea) != "" and GetFunctionName(ea) == "":
                            mynav_print("Creating function at 0x%08x" % ea)
                            MakeFunction(ea, BADADDR)
            else:
                break
        return True

    def realDoDiscoverFunctions(self):
        ea = ScreenEA()
        start_ea = SegStart(ea)
        end_ea = SegEnd(ea)
        total = len(list(Functions(start_ea, end_ea)))
        times = 0
        while times <= 5:
            times += 1
            mynav_print("Doing pass %d" % times)
            if not self.doDiscoverFunctions():
                break
            
            tmp = len(list(Functions(start_ea, end_ea)))
            mynav_print("Total of %d function(s) in database" % tmp)
            total = tmp - total
            if total > 0:
                mynav_print("  Total of %d new function(s)" % total)
                total = tmp
            else:
                break
            
        mynav_print("Done")

    def getSessionsForString(self, txt, id=None):
        sql = "select * from sessions_strings where text like '%' || ? || '%'"
        if id is not None and False:
            sql += " and id = ?"
        cur = self.db.cursor()
        
        if id is None or True:
            cur.execute(sql, (txt,))
        else:
            cur.execute(sql, (txt, id))
        
        l = []
        for row in cur.fetchall():
            l.append([row[0], row[1], row[2]])
        cur.close()
        return l

    def searchStringInSessions(self, id=None):
        txt = AskStr("String to search", "")
        if txt is not None:
            #id = self.showSessions()
            id = None
            l = self.getSessionsForString(txt, id)
            if len(l) > 0:
                mybrowser.ShowStringsGraph(l)

    def newAdvancedSession(self):
        chooser = Choose([], "Advanced Session", 3)
        chooser.width = 50
        chooser.list = ["Trace code paths between 2 functions", "Trace code paths between points"]
        c = chooser.choose()
        
        if c > 0:
            if c == 1:
                self.traceCodePaths()
            elif c == 2:
                self.tracePoints()
        else:
            c = None
        
        return c

    def showAdvanced(self):
        chooser = Choose([], "Show Advanced Graphs", 3)
        chooser.width = 50
        chooser.list = ["Show entry points", "Show target points", "Show code paths between points",
                        "Show code paths between 2 functions", "Show all function in this segment",
                        "Show all breakpoints graph"]
        c = chooser.choose()
        
        if c > 0:
            if c == 1:
                self.showDataEntryPoints()
            elif c == 2:
                self.showTargetPoints()
            elif c == 3:
                self.showCodePathsBetweenPoints()
            elif c == 4:
                mybrowser.SearchCodePathDialog()
            elif c == 5:
                self.showSegmentsGraph()
            elif c == 6:
                self.showBreakpointsGraph()
        else:
            c = None
        
        return c

    def showSessionsManager(self):
        ch2 = mybrowser.SessionsManager("%s (Functions List)" % self.current_name, self)
        results = self.getSessionsList()
        for item in results:
            print "Adding item", item
            ch2.add_item(item)
        
        r = ch2.show()

    def selectFunctionsInSegment(self):
        ea = ScreenEA()
        for f in list(Functions(SegStart(ea), SegEnd(ea))):
            self.addBreakpoint(f)
        mynav_print("Done")

    def deselectFunctionsInSegment(self):
        ea = ScreenEA()
        for f in list(Functions(SegStart(ea), SegEnd(ea))):
            DelBpt(f)
        mynav_print("Done")

    def selectAdvanced(self):
        chooser = Choose([], "Select advanced", 3)
        chooser.width = 50
        chooser.list = ["Function's child", "Code paths between points", "Code paths between 2 functions",
                        "All functions in this segment"]
        c = chooser.choose()
        
        if c > 0:
            if c == 1:
                self.selectFunctionChilds()
            elif c == 2:
                self.selectCodePathsBetweenPoints()
            elif c == 3:
                self.selectCodePaths()
            elif c == 4:
                self.selectFunctionsInSegment()
        else:
            c = None
        
        return c

    def deselectAdvanced(self):
        chooser = Choose([], "Deselect advanced", 3)
        chooser.width = 50
        chooser.list = ["Function's child", "Code paths between points", "Code paths between 2 functions", "All functions in this segment"]
        c = chooser.choose()
        
        if c > 0:
            if c == 1:
                self.deselectFunctionChilds()
            elif c == 2:
                self.deselectCodePathsBetweenPoints()
            elif c == 3:
                self.deselectCodePaths()
            elif c == 4:
                self.deselectFunctionsInSegment()
        else:
            c = None
        
        return c

    def searchAdvanced(self):
        chooser = Choose([], "Advanced options", 3)
        chooser.width = 50
        chooser.list = ["Search string in session", "Export database's functions",
                        "Import database's functions", "Search new functions in this segment",
                        "Analyze current segment",
                        "Analyze complete program", "Analyze this segment and search new functions"]
        c = chooser.choose()
        
        if c > 0:
            if c == 1:
                self.searchStringInSessions()
            elif c == 2:
                x = myexport.CFunctionsMatcher()
                x.export()
            elif c == 3:
                msg = "WARNING! This process can discover a lot of function names but it may generate incorrect results too.\n"
                msg += "Do you want to continue?"
                if askyn_c(1, msg) == 1:
                    x = myexport.CFunctionsMatcher()
                    x.doImport()
            elif c == 4:
                msg = "WARNING! This process can discover a lot of new functions but it may generate incorrect results.\n"
                msg += "Do you want to continue?"
                if askyn_c(1, msg) == 1:
                    self.realDoDiscoverFunctions()
            elif c == 5:
                AnalyzeArea(SegStart(here()), SegEnd(here()))
            elif c == 6:
                AnalyzeArea(MinEA(), MaxEA())
            elif c == 7:
                AnalyzeArea(SegStart(here()), SegEnd(here()))
                msg = "WARNING! This process can discover a lot of new functions but it may generate incorrect results.\n"
                msg += "Do you want to continue?"
                if askyn_c(1, msg) == 1:
                    self.realDoDiscoverFunctions()
                AnalyzeArea(SegStart(here()), SegEnd(here()))
        else:
            c = None
        
        return c

    def runScript(self):
        res = AskFile(0, "*.py", "Select python script to run")
        if res is not None:
            g = globals()
            g["mynav"] = self
            g["mybrowser"] = mybrowser
            g["myexport"] = myexport
            execfile(res, g)
    
    def mynav_print(self, msg):
        mynav_print(msg)

    def registerMenus(self):
        #idaapi.add_menu_item("Edit/Plugins/", "MyNav: Deselect extended code paths between 2 functions", None, 0, self.deselectExtendedCodePaths, None)
        #idaapi.add_menu_item("Edit/Plugins/", "MyNav: Select extended code paths between 2 functions", None, 0, self.selectExtendedCodePaths, None)
        #idaapi.add_menu_item("Edit/Plugins/", "MyNav: Show extended code paths between 2 functions", None, 0, mybrowser.mybrowser.SearchCodePathDialog, (False, True))
        #idaapi.add_menu_item("Edit/Plugins/", "MyNav: Show sessions union", "", 0, self.doNothing, None)
        #idaapi.add_menu_item("Edit/Plugins/", "MyNav: Show sessions intersection", "", 0, self.doNothing, None)
        #idaapi.add_menu_item("Edit/Plugins/", "MyNav: Show simplified step trace session", "Ctrl+Alt+F6", 0, self.showSimplifiedTraceSession, None)
        #idaapi.add_menu_item("Edit/Plugins/", "MyNav: Trace code paths between 2 functions", None, 0, self.traceCodePaths, None)
        #idaapi.add_menu_item("Edit/Plugins/", "-", None, 0, self.doNothing, None)
        idaapi.add_menu_item("Edit/Plugins/", "-", None, 0, self.doNothing, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Delete ALL sessions", "", 0, self.clearSessions, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Delete a session", "", 0, self.deleteSession, ())
        idaapi.add_menu_item("Edit/Plugins/", "-", None, 0, self.doNothing, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Advanced deselection options", "", 0, self.deselectAdvanced, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Advanced selection options", "", 0, self.selectAdvanced, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Deselect hits from session", "Ctrl+Shift+Alt+F9", 0, self.loadBreakpointsFromSessionInverse, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Select hits from session", "Ctrl+Alt+F9", 0, self.loadBreakpointsFromSession, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Clear all breakpoints", "", 0, self.clearBreakpoints, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Set all breakpoints", "Alt+F9", 0, self.setBreakpoints, ())
        idaapi.add_menu_item("Edit/Plugins/", "-", None, 0, self.doNothing, ())
        """
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Remove target point", None, 0, self.removeCurrentTargetPoint, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Remove entry point", None, 0, self.removeCurrentDataEntryPoint, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Add target point", None, 0, self.addCurrentAsTargetPoint, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Add entry point", None, 0, self.addCurrentAsDataEntryPoint, ())
        """
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Add/Remove target point", None, 0, self.addRemoveTargetPoint, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Add/Remove entry point", None, 0, self.addRemoveEntryPoint, ())
        idaapi.add_menu_item("Edit/Plugins/", "-", None, 0, self.doNothing, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Clear trace session", "", 0, self.clearTraceSession, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Session's functions List", "", 0, self.showSessionsFunctions, ())
        #idaapi.add_menu_item("Edit/Plugins/", "MyNav: Show session's manager", "", 0, self.showSessionsManager, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Show advanced options", "Alt+F6", 0, self.showAdvanced, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Show trace session", "Ctrl+Alt+F6", 0, self.showTraceSession, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Show session", "Alt+F6", 0, self.showSessionsGraph, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Show browser", "Ctrl+Shift+B", 0, self.showBrowser, ())
        idaapi.add_menu_item("Edit/Plugins/", "-", None, 0, self.doNothing, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Configure CPU Recording", None, 0, self.configureSaveCPU, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Configure timeout", None, 0, self.configureTimeout, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: New advanced session", None, 0, self.newAdvancedSession, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Trace this function", "", 0, self.traceInFunction, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Trace in session", "Ctrl+Alt+F5", 0, self.traceInSession, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: New session", "Alt+F5", 0, self.newSession, ())
        #idaapi.add_menu_item("Edit/Plugins/", "-", None, 0, self.doNothing, ())
        #idaapi.add_menu_item("Edit/Plugins/", "MyNav: Open graph", None, 0, self.openSavedGraph, ())
        idaapi.add_menu_item("Edit/Plugins/", "-", None, 0, self.doNothing, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Run a python script", None, 0, self.runScript, ())
        idaapi.add_menu_item("Edit/Plugins/", "MyNav: Advanced utilities", None, 0, self.searchAdvanced, ())

def main():
    nav = CMyNav()
    """
    if askyn_c(1, "Set breakpoints?") == 1:
        nav.setBreakpoints()

    nav.start()
    nav.showSessions()
    """
    #nav.selectFunctionChilds()
    nav.registerMenus()
    #nav.doDiscoverFunctions()
    #nav.deselectFunctionChilds()
    #nav.showFunctionChilds()

if __name__ == "__main__":
    try:
        main()
    except:
        print "***Error, main", sys.exc_info()[1]


#!/usr/bin/env python

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

# ------------------------------------------------
# Standard imports
import sys
import sqlite3

# ------------------------------------------------
# IDA's imports
import idc
import idaapi
import idautils

# ------------------------------------------------
# Helper
def myexport_print(msg):
    print "[+] %s" % msg

# ------------------------------------------------
# Symbol's exporter class
class CFunctionsMatcher(object):
    def __init__(self):
        self.initialize()

    def __del__(self):
        if self.db:
            self.closeDatabase()

    def initialize(self):
        self.functions = {}
        self.filename = None
        self.db = None
        self.start_ea = None
        self.end_ea = None

    def closeDatabase(self):
        self.db.close()
        self.db = None

    def createSchema(self):
        cur = self.db.cursor()
        sql = """ create table if not exists functions (
                        id integer primary key,
                        name varchar(50),
                        processor varchar(50),
                        nodes integer,
                        edges integer,
                        points integer,
                        size integer,
                        instructions integer,
                        mnemonics text) """
        cur.execute(sql)
        self.db.commit()
        cur.close()
        
        return True

    def openDatabase(self, filename):
        self.db = sqlite3.connect(filename)

    def createDatabase(self, filename):
        self.openDatabase(filename)
        self.createSchema()

    def saveDatabase(self):
        cur = self.db.cursor()
        sql = """insert into functions (name, processor, nodes, edges, points, size, instructions, mnemonics)
                                values (?, ?, ?, ?, ?, ?, ?, ?)"""
        
        for row in self.functions:
            name, nodes, edges, points, size, instructions, mnems = self.functions[row]
            cur.execute(sql, (name, idaapi.get_idp_name(), nodes, edges, points, size, instructions, str(mnems)))
        
        self.db.commit()
        cur.close()
        return True

    def search(self, f):
        name, nodes, edges, points, size, instructions, mnems = f
        
        cur = self.db.cursor()
        sql = """ select name
                    from functions
                   where nodes = ?
                     and edges = ?
                     and points = ?
                     and size = ?
                     and instructions = ? """
        cur.execute(sql, (nodes, edges, points, size, instructions))
        
        res = None
        for row in cur.fetchall():
            res = row[0]
        
        cur.close()
        
        return res

    def searchExact(self, f):
        name, nodes, edges, points, size, instructions, mnems = f
        
        cur = self.db.cursor()
        sql = """ select name
                    from functions
                   where processor = ?
                     and nodes = ?
                     and edges = ?
                     and points = ?
                     and size = ?
                     and instructions = ?
                     and mnemonics = ? """
        cur.execute(sql, (idaapi.get_idp_name(), nodes, edges, points, size, instructions, str(mnems)))
        
        res = None
        for row in cur.fetchall():
            res = row[0]
        
        cur.close()
        
        return res

    def searchAll(self):
        if self.start_ea is not None:
            l = list(idautils.Functions(idc.SegStart(self.start_ea), idc.SegEnd(self.end_ea)))
        else:
            l = list(idautils.Functions())
        
        for f in l:
            name = idc.GetFunctionName(f)
            
            if not name.startswith("sub_"):
                continue
            
            flags = idc.GetFunctionFlags(f)
            if flags & idc.FUNC_LIB or flags == -1:
                continue
            
            x = self.readFunction(f, False)
            
            if x:
                match = self.searchExact(x)
                if match:
                    print "%08x Function %s exact matches with %s" % (f, idc.GetFunctionName(f), match)
                    try:
                        idaapi.set_name(int(f), str(match))
                    except:
                        print "  %08x Cannot rename function" % f
                        print sys.exc_info()[1]
                else:
                    match = self.search(x)
                    if match:
                        print "%08x Function %s partially matches with %s" % (f, idc.GetFunctionName(f), match)
                        try:
                            idc.MakeComm(f, str(match))
                        except:
                            print "  %08x Cannot rename function" % f
                            print sys.exc_info()[1]

    def readFunction(self, f, discard=True):
        name = idc.GetFunctionName(f)
        func = idaapi.get_func(f)
        flow = idaapi.FlowChart(func)
        size = func.endEA - func.startEA
        
        if discard:
            # Unnamed function, ignore it...
            if name.startswith("sub_") or name.startswith("j_") or name.startswith("unknown"):
                return False
            
            # Already recognized runtime's function
            flags = idc.GetFunctionFlags(f)
            if flags & idc.FUNC_LIB or flags == -1:
                return False
        
        nodes = 0
        edges = 0
        points = 0
        instructions = 0
        mnems = []
        dones = {}
        
        for block in flow:
            nodes += 1
            indegree = 0
            outdegree = 0
            for succ_block in block.succs():
                edges += 1
                indegree += 1
                if not dones.has_key(succ_block.id):
                    dones[succ_block] = 1
                    for x in list(idautils.Heads(succ_block.startEA, succ_block.endEA)):
                        instructions += 1
                        mnems.append(idc.GetMnem(x))
            
            for pred_block in block.preds():
                edges += 1
                outdegree += 1
                if not dones.has_key(succ_block.id):
                    dones[succ_block] = 1
                    for x in list(idautils.Heads(succ_block.startEA, succ_block.endEA)):
                        instructions += 1
                        mnems.append(idc.GetMnem(x))
            
            if indegree > 0:
                points += indegree
            if outdegree > 0:
                points += outdegree
        
        if nodes > 1 and instructions > 5 and edges > 1:
            #myexport_print("Exporter: Current function 0x%08x %s" % (f, name))
            return (name, nodes, edges, points, size, instructions, mnems)
        
        return False

    def getFunctions(self):
        for f in idautils.Functions():
            x = self.readFunction(f)
            if x:
                self.functions[f] = x
            
        return self.functions

    def export(self, filename=None):
        self.initialize()
        
        if filename is None:
            f = idc.AskFile(1, "*.sqlite", "Select database to export")
        else:
            f = filename
        
        if f:
            myexport_print("Reading functions...")
            self.getFunctions()
            self.createDatabase(f)
            myexport_print("Exporting functions...")
            self.saveDatabase()
            self.closeDatabase()
            myexport_print("Done")
    
    def doImport(self, filename=None):
        self.initialize()
        
        if filename is None:
            f = idc.AskFile(0, "*.sqlite", "Select database to import")
        else:
            f = filename
        
        if f:
            self.openDatabase(f)
            self.searchAll()

# ------------------------------------------------
# Only called when accesed directly
def main():
    exporter = CFunctionsMatcher()
    #exporter.export()
    exporter.start_ea = idc.SegStart(idc.ScreenEA())
    exporter.end_ea = idc.SegEnd(idc.ScreenEA())
    exporter.openDatabase("c:\\tools\\mynav\\pako.sqlite")
    exporter.searchAll()

if __name__ == "__main__":
    main()

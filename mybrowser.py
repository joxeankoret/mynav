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

import sys

#import idc
#import idautils

import idc
import idaapi
import idautils

from idaapi import GraphViewer, Choose2

def GetCodeRefsFrom(ea):
    name = idc.GetFunctionName(ea)
    ea = idc.LocByName(name)

    f_start = ea
    f_end = idc.GetFunctionAttr(ea, idc.FUNCATTR_END)

    ret = []
    for chunk in idautils.Chunks(ea):
        astart = chunk[0]
        aend = chunk[1]
        for head in idautils.Heads(astart, aend):
            # If the element is an instruction
            if idc.isCode(idc.GetFlags(head)):
                refs = idautils.CodeRefsFrom(head, 0)
                for ref in refs:
                    loc = idc.LocByName(idc.GetFunctionName(ref))
                    if loc not in ret and loc != f_start:
                        ret.append(ref)

    return ret

def GetDataXrefString(ea):
    name = idc.GetFunctionName(ea)
    ea = idc.LocByName(name)

    f_start = ea
    f_end = idc.GetFunctionAttr(ea, idc.FUNCATTR_END)

    ret = []
    for chunk in idautils.Chunks(ea):
        astart = chunk[0]
        aend = chunk[1]
        for head in idautils.Heads(astart, aend):
            # If the element is an instruction
            if idc.isCode(idc.GetFlags(head)):
                refs = list(idautils.DataRefsFrom(head))
                for ref in refs:
                    s = idc.GetString(ref, -1, idc.ASCSTR_C)
                    if not s or len(s) <= 4:
                        s = idc.GetString(ref, -1, idc.ASCSTR_UNICODE)
                    
                    if s:
                        if len(s) > 4:
                            ret.append(repr(s))

    if len(ret) > 0:
        return "\n\n" + "\n".join(ret)
    else:
        return ""

def GetName(ea, resolve_imports=True):
    name = idc.GetFunctionName(ea)
    if not name and resolve_imports:
        name = idc.GetTrueName(ea)
    return name

def GetFunctionStartEA(ea):
    for x in idautils.FuncItems(ea):
        return x
    return ea

##############################################
"""Results List Window Creator with Choose2"""
##############################################
class UnsafeFunctionsChoose2(Choose2):
    class Item:
        def __init__(self, item):
            self.ea        = item['xref']
            self.vfname    = item['func_name']

        def __str__(self):
            return '%08x' % self.ea

    def __init__(self, title, mynav=None):
        Choose2.__init__(self, title, [ ["Line", 8], ["Address", 10], ["Name", 30] ])
        self.n = 0
        self.items = []
        self.item_relations = {}
        self.icon = 41
        self.mynav = mynav
        #print "created", str(self)

    def OnClose(self):
        """space holder"""
        #print "closed", str(self)

    def OnEditLine(self, n):
        """space holder"""
        #print "editing", str(n)

    def OnInsertLine(self):
        """space holder"""
        #print "insert line"

    def OnSelectLine(self, n):
        item = self.items[int(n)]
        idaapi.jumpto(self.item_relations[item[1]])

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnDeleteLine(self, n):
        """space holder"""
        #print "del ",str(n)

    def OnRefresh(self, n):
        return n

    def OnCommand(self, n, cmd_id):
        # Aditional right-click-menu commands handles
        if cmd_id == self.cmd_a:
            """ Browse function """
            item = self.items[int(n)]
            ea = self.item_relations[item[1]]
            ShowFunctionsBrowser(ea)
        elif cmd_id == self.cmd_b:
            """ Browse function showing APIs """
            item = self.items[int(n)]
            ea = self.item_relations[item[1]]
            ShowFunctionsBrowser(ea, True)
        elif cmd_id is not None and cmd_id == self.cmd_d:
            """ Add data entry point """
            item = self.items[int(n)]
            ea = self.item_relations[item[1]]
            mynav.addPoint(ea, "E")
        elif cmd_id is not None and cmd_id == self.cmd_e:
            """ Add target point """
            item = self.items[int(n)]
            ea = self.item_relations[item[1]]
            mynav.addPoint(ea, "T")
        elif cmd_id is not None and cmd_id == self.cmd_f:
            item = self.items[int(n)]
            ea = self.item_relations[item[1]]
            mynav.removePoint(ea, "E")
        elif cmd_id is not None and cmd_id == self.cmd_g:
            item = self.items[int(n)]
            ea = self.item_relations[item[1]]
            mynav.removePoint(ea, "E")
        else:
            print "Unknown command:", cmd_id, "@", n
            
        return 1

    def OnGetIcon(self, n):
        r = self.items[n]
        t = self.icon + r[1].count("*")
        return t

    def show(self):
        t = self.Show()
        if t < 0:
            return False
        
        # create aditional actions handlers
        self.cmd_a = self.AddCommand("Browse function")
        self.cmd_b = self.AddCommand("Browse function (show APIs)")
        
        if self.mynav is not None:
            self.ignore_me = self.AddCommand("-")
            self.cmd_d = self.AddCommand("Add entry point")
            self.cmd_e = self.AddCommand("Add target point")
            self.cmd_f = self.AddCommand("Remove entry point")
            self.cmd_g = self.AddCommand("Remove target point")
        else:
            self.cmd_d = None
            self.cmd_e = None
            self.cmd_f = None
            self.cmd_g = None
        
        return True

    def add_item(self, item):
        if item.__str__() not in self.item_relations:
            self.items.append([ "%08lu" % self.n, item.__str__(), item.vfname ])
            self.item_relations[item.__str__()] = item.ea
            self.n += 1

    def OnGetLineAttr(self, n):
        """space holder"""
        pass

class SessionsManager(Choose2):

    def __init__(self, title, nb = 5, mynav=None):
        Choose2.__init__(self, title, [ ["Session Name", 10] ])
        self.n = 0
        self.items = []
        self.icon = 5
        self.selcount = 0
        self.mynav = mynav
        print "created", str(self)

    def OnClose(self):
        print "closed", str(self)

    def OnEditLine(self, n):
        self.items[n][1] = self.items[n][1] + "*"
        print "editing", str(n)

    def OnInsertLine(self):
        self.items.append(self.make_item())
        print "insert line"

    def OnSelectLine(self, n):
        self.selcount += 1
        Warning("[%02d] selectline '%s'" % (self.selcount, n))

    def OnGetLine(self, n):
        print "getline", str(n)
        return "kk" + str(self.items[n]) + "kk\n\n"

    def OnGetSize(self):
        print "getsize"
        return len(self.items)

    def OnDeleteLine(self, n):
        print "del ",str(n)
        del self.items[n]
        return n

    def OnRefresh(self, n):
        print "refresh", n
        return n

    def OnCommand(self, n, cmd_id):
        if cmd_id == self.cmd_a:
            print "command A selected @", n
        elif cmd_id == self.cmd_b:
            print "command B selected @", n
        else:
            print "Unknown command:", cmd_id, "@", n
        return 1

    def OnGetIcon(self, n):
        r = self.items[n]
        t = self.icon + r[1].count("*")
        print "geticon", n, t
        return t

    def show(self):
        t = self.Show()
        if t < 0:
            return False
        self.cmd_a = self.AddCommand("command A")
        self.cmd_b = self.AddCommand("command B")
        
        return True

    def add_item(self, item):
        self.items.append(item)
        self.n += 1

    def OnGetLineAttr(self, n):
        print "getlineattr", n
        if n == 1:
            return [0xFF0000, 0]

class FunctionsBrowser(GraphViewer):
    def __init__(self, title, father, session):
        GraphViewer.__init__(self, title, False)
        self.father = father
        self.result = session
        self.nodes = {}
        self.totals = {}
        self.last_level = []
        self.max_level = 3
        self.parents = False
        self.is_new_father = False
        self.old_father = False
        self.show_runtime_functions = True
        self.show_string = True
        self.commands = {}
        self.hidden = []
        self.mynav = None

    def addChildNodes(self, father):
        self.addRequiredNodes(father, 0)
        self.addEdges()
        self.addSeeMoreNodes(father)

    def addSeeMoreNodes(self, father):
        for ea in self.last_level:
            total = len(GetCodeRefsFrom(ea))
            if self.totals.has_key(ea):
                total = total - self.totals[ea]
            
            if total > 0:
                self.nodes[str(ea)] = self.AddNode((ea, "(%d more nodes)" % total))
                self.AddEdge(self.nodes[ea], self.nodes[str(ea)])

    def addEdges(self):
        l = self.nodes.keys()
        for ea in l:
            refs = GetCodeRefsFrom(ea)
            for ref in refs:
                if ref in l:
                    self.AddEdge(self.nodes[ea], self.nodes[ref])
                    if self.totals.has_key(ea):
                        self.totals[ea] += 1
                    else:
                        self.totals[ea] = 0
        
        if self.is_new_father:
            self.nodes[self.old_father] = self.AddNode((self.old_father, "Return ..."))
            self.AddEdge(self.nodes[self.old_father], self.nodes[self.father])

    def addRequiredNodes(self, father, level=0):
        for ea in GetCodeRefsFrom(father):
            ea = GetFunctionStartEA(ea)
            if not self.nodes.has_key(ea):
                if idc.GetFunctionFlags(ea) & idc.FUNC_LIB and not self.show_runtime_functions:
                    continue
                
                name = GetName(ea, True)
                if name:
                    if self.show_string:
                        name += GetDataXrefString(ea)
                    
                    if ea not in self.hidden:
                        self.nodes[ea] = self.AddNode((ea, name))
                        
                        if level < self.max_level:
                            self.addRequiredNodes(ea, level+1)
                        elif level == self.max_level:
                            self.last_level.append(ea)

    def OnRefresh(self):
        try:
            self.Clear()
            self.nodes = {}
            self.totals = {}
            self.last_level = []
            self.nodes[self.father] = self.AddNode((self.father, idc.GetFunctionName(self.father)))
            self.addChildNodes(self.father)
            
            return True
        except:
            print "***Error, hamen", sys.exc_info()[1]
            return True

    def OnGetText(self, node_id):
        ea, label = self[node_id]
        flags = idc.GetFunctionFlags(ea)
        
        if label == "Return ...":
            color = 0xfff000
            return (label, color)
        elif node_id == 0:
            color = 0x00f000
            return (label, color)
        elif flags & idc.FUNC_LIB or flags == -1:
            color = 0xf000f0
            return (label, color)
        else:
            return label
    
    def OnHint(self, node_id):
        x = self.OnGetText(node_id)
        if len(x) == 2:
            return x[0]
        else:
            return x

    def OnDblClick(self, node_id):
        ea, label = self[node_id]
        
        if label.startswith("("):
            self.is_new_father = True
            self.old_father = self.father
            self.father = ea
            self.Refresh()
        elif label == "Return ...":
            self.is_new_father = False
            self.father = self.old_father
            self.Refresh()
        else:
            idc.Jump(ea)
        
        return True

    def OnSelect(self, node_id):
        return True

    def Show(self):
        if not GraphViewer.Show(self):
            return False
        """
        if self.mynav is not None and False:
            cmd = self.AddCommand("Open graph", "Ctrl+O")
            self.commands[cmd] = "open"
            cmd = self.AddCommand("Save graph", "Ctrl+O")
            self.commands[cmd] = "save"
            cmd = self.AddCommand("-", "")
            self.commands[cmd] = "-"
        """
        cmd = self.AddCommand("Refresh", "")
        self.commands[cmd] = "refresh"
        cmd = self.AddCommand("Show/hide node", "Ctrl+H")
        self.commands[cmd] = "hide"
        cmd = self.AddCommand("Show/hide strings", "")
        self.commands[cmd] = "strings"
        cmd = self.AddCommand("Show/hide API calls", "")
        self.commands[cmd] = "apis"
        cmd = self.AddCommand("Show all nodes", "Ctrl+A")
        self.commands[cmd] = "unhide"
        cmd = self.AddCommand("Select recursion level", "")
        self.commands[cmd] = "recursion"
        cmd = self.AddCommand("- ", "")
        self.commands[cmd] = "-"
        
        return True

    def OnCommand(self, cmd_id):
        try:
            cmd = self.commands[cmd_id]
            if cmd == "refresh":
                self.Refresh()
            elif cmd == "hide":
                l = {}
                i = 0
                for x in self.nodes:
                    name = idc.GetFunctionName(int(x))
                    if name and name != "":
                        l[i] = name
                        i += 1
                for x in self.hidden:
                    name = idc.GetFunctionName(int(x))
                    if name and name != "":
                        l[i] = name
                        i += 1
                
                chooser = idaapi.Choose([], "Show/Hide functions", 3)
                chooser.width = 50
                chooser.list = l
                c = chooser.choose()
                
                if c:
                    c = c - 1
                    c = idc.LocByName(l[c])
                    
                    if c in self.hidden:
                        self.hidden.remove(c)
                    else:
                        self.hidden.append(c)
                    self.Refresh()
            elif cmd == "unhide":
                self.hidden = []
                self.Refresh()
            elif cmd == "strings":
                self.show_string = not self.show_string
                self.Refresh()
            elif cmd == "apis":
                self.show_runtime_functions = not self.show_runtime_functions
                self.Refresh()
            elif cmd == "recursion":
                num = idc.AskLong(self.max_level, "Maximum recursion level")
                if num:
                    self.max_level = num
                    self.Refresh()
            elif cmd == "open":
                g = self.mynav.showSavedGraphs()
                if g:
                    nodes, hidden = self.mynav.loadSavedGraphNodes(g)
                    name, ea, level, strings, runtime = self.mynav.loadSavedGraphData(g)
                    self.title = name
                    self.father = ea
                    self.max_level = level
                    self.show_runtime_functions = runtime
                    self.show_string = strings
                    self.hidden = hidden
                    self.result = nodes
                    self.Refresh()
            elif cmd == "save":
                self.mynav.saveGraph(self.father, self.max_level, self.show_runtime_functions, \
                                     self.show_string, self.hidden, self.result)
        except:
            print "OnCommand:", sys.exc_info()[1]
        
        return True

class PathsBrowser(GraphViewer):
    def __init__(self, title, nodes, start, target, hits = []):
        GraphViewer.__init__(self, title, False)
        if type(start) is not type([]):
            self.start = [start]
        else:
            self.start = start
        
        if type(target) is not type([]):
            self.target = [target]
        else:
            self.target = target
        
        self.result = nodes
        self.nodes = {}
        self.added = []
        self.hits = []

    def addNodes(self):
        for node in self.result:
            name = idc.GetFunctionName(node)
            if not name:
                continue
            
            if name not in self.added:
                try:
                    self.nodes[idc.LocByName(name)] = self.AddNode((idc.LocByName(name), name))
                    self.added.append(name)
                except:
                    print "Error adding node", sys.exc_info()[1]

    def addEdges(self):
        for ea in self.result:
            refs = GetCodeRefsFrom(ea)
            for ref in refs:
                name = idc.GetFunctionName(ref)
                name2 = idc.GetFunctionName(ea)
                try:
                    if name in self.added:
                        self.AddEdge(self.nodes[idc.LocByName(name2)], self.nodes[idc.LocByName(name)])
                        self.added.append((ea, ref))
                except:
                    print "Error", sys.exc_info()[1]

    def OnRefresh(self):
        self.Clear()
        self.added = []
        self.addNodes()
        self.addEdges()
        
        return True

    def OnGetText(self, node_id):
        try:
            ea, label = self[node_id]
            flags = idc.GetFunctionFlags(ea)
            
            if ea in self.start or ea in self.target or ea in self.hits:
                color = 0x00f000
                return (label, color)
            elif flags & idc.FUNC_LIB or flags == -1:
                color = 0xf000f0
                return (label, color)
            else:
                return label
        except:
            label = str(sys.exc_info()[1])
            #return "Error " + str(label) + " EA 0x%08x" % ea
            return "oxtixe"

    def OnDblClick(self, node_id):
        ea, label = self[node_id]
        idc.Jump(ea)
        
        return True

    def OnCommand(self, cmd_id):
        """
        Triggered when a menu command is selected through the menu or its hotkey
        @return: None
        """
        if self.cmd_close == cmd_id:
            self.Close()
            return
        
        #print "command:", cmd_id

    def Show(self):
        if not GraphViewer.Show(self):
            return False
        
        self.cmd_close = self.AddCommand("Close", "ESC")
        if self.cmd_close == 0:
            print "Failed to add popup menu item!"
        
        return True

class StringsBrowser(GraphViewer):
    def __init__(self, title, elements):
        GraphViewer.__init__(self, title, False)
        self.elements = elements
        self.nodes = {}
        self.added_names = []

    def OnGetText(self, node_id):
        try:
            ea, label, mtype = self[node_id]
            if mtype == -1:
                return str(label)
            elif mtype == 1:
                color = 0x00f000
                return (label, color)
            elif mtype == 0:
                color = 0xf000f0
                return (label, color)
        except:
            return "Error"#: " + str(sys.exc_info()[1])
        
        """print "EA", ea
        print "LABEL", label
        flags = GetFunctionFlags(ea)
        
        if ea in self.start or ea in self.target or ea in self.hits:
            color = 0x00f000
            return (label, color)
        elif flags & FUNC_LIB or flags == -1:
            color = 0xf000f0
            return (label, color)
        else:
            return label"""

    def OnDblClick(self, node_id):
        ea, label, mtype = self[node_id]
        
        if ea != 0:
            idc.Jump(ea)
        return True

    def OnRefresh(self):
        
        try:
            self.Clear()
            self.added_names = []
            self.nodes = {}
            
            sessions = {}
            addresses = []
            strings = []
            
            for x in self.elements:
                if not sessions.has_key(x[0]):
                    sessions[x[0]] = []
                sessions[x[0]].append((x[1], x[2]))
            
            for s in sessions:
                cur_node = self.AddNode((0, "Session " + s, -1))
                
                for addr, string in sessions[s]:
                    addr = int(addr)
                    name = idc.GetFunctionName(addr)
                    if name in self.added_names:
                        continue
                    else:
                        self.added_names.append(name)
                    
                    if not self.nodes.has_key(addr):
                        self.nodes[addr] = self.AddNode((addr, idc.GetFunctionName(addr), 0))
                    self.AddEdge(cur_node, self.nodes[addr])
                    if not self.nodes.has_key(string):
                        self.nodes[string] = self.AddNode((addr, string, 1))
                    self.AddEdge(self.nodes[addr], self.nodes[string])
        except:
            print "Error refresh", sys.exc_info()[1]
        
        return True

def ShowStringsGraph(l):
    g = StringsBrowser("Strings browser", l)
    g.Show()

def ShowFunctionsBrowser(mea=None, show_runtime=False, show_string=True, mynav=None):
    try:
        if mea is None:
            ea = idc.ScreenEA()
        else:
            ea = mea
        
        num = idc.AskLong(3, "Maximum recursion level")
        if not num:
            return
        
        result = list(idautils.CodeRefsFrom(ea, idc.BADADDR))
        g = FunctionsBrowser("Code Refs Browser %s" % idc.GetFunctionName(ea), ea, result)
        g.max_level = num
        g.show_string = True
        g.show_runtime_functions = show_runtime
        g.mynav = mynav
        g.Show()
    except:
        print "Error", sys.exc_info()[1]

def ShowGraph(name, ea, funcs, hidden, level, strings, runtime, mynav):
    g = FunctionsBrowser("Saved graph: %s" % name, ea, funcs)
    g.hidden = hidden
    g.max_level = level
    g.show_string = strings
    g.show_runtime = runtime
    g.mynav = mynav
    g.Show()

def SearchCodePath(start_ea, target_ea, extended = False):
    nodes = []
    sea_nodes = []
    tea_nodes = []
    seas = [start_ea]
    teas = [target_ea]
    i = 0
    if extended:
        max_times = 5
    else:
        max_times = 10

    while True:
        i += 1
        if i > max_times or len(seas) == 0 or len(teas) == 0:
            break
        
        for sea in seas:
            refs = GetCodeRefsFrom(sea)
            for ref in refs:
                if ref in sea_nodes:
                    continue
                #print "START: Function %s" % GetFunctionName(ref)
                sea_nodes.append(ref)
                if ref == target_ea or ref in tea_nodes:
                    nodes.append(target_ea)
                    nodes.extend(sea_nodes)
                    nodes.extend(tea_nodes)
                    nodes.append(start_ea)
                    break
            seas = sea_nodes
        if extended:
            for tea in teas:
                refs = idautils.CodeRefsTo(tea, True)
                for ref in refs:
                    if ref in tea_nodes:
                        continue
                    #print "TARGET: Function %s" % GetFunctionName(ref)
                    tea_nodes.append(ref)
                    if ref == start_ea or ref in sea_nodes:
                        nodes.append(target_ea)
                        nodes.extend(sea_nodes)
                        nodes.extend(tea_nodes)
                        nodes.append(start_ea)
                        break
                teas = tea_nodes

    return nodes

def SearchCodePathDialog(ret_only=False, extended=False):
    f1 = idaapi.choose_func("Select starting function", 0)
    if not f1:
        return
    sea = f1.startEA
    
    f2 = idaapi.choose_func("Select target function", idc.ScreenEA())
    if not f2:
        return
    tea = f2.startEA

    nodes = SearchCodePath(sea, tea, extended)
    if len(nodes) > 0:
        if ret_only:
            return nodes
        else:
            g = PathsBrowser("Code paths from %s to %s" % (idc.GetFunctionName(sea),
                                                           idc.GetFunctionName(tea)),
                                                           nodes, sea, tea)
            g.Show()
    else:
        idaapi.info("No codepath found between %s and %s" % (idc.GetFunctionName(sea), idc.GetFunctionName(tea)))
        return nodes

def main():
    #ShowFunctionsBrowser(show_runtime=True)
    try:
        #SearchCodePathDialog()
        ShowFunctionsBrowser(show_string=True)
    except:
        print "***Error:", sys.exc_info()[1]

if __name__ == "__main__":
    main()

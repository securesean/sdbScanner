# Volatility Shim Database scanner Plugin
# Copyright (C) 2008-2013 Volatility Foundation
# Copyright (C) 2014 Sean Pierce (sdb at securesean com)
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#
"""
@author:       Sean Pierce
@codehelper:   Wyatt Roersma(wyattroersma@gmail.com)
@license:      GNU General Public License 2.0 or later
@contact:      sdb at securesean com   
@organization: iSIGHT Partners
Date		Aug 1 2015
"""

#TODO: copy reder_text to generator, clean up formatting, do profile config
#Future: check registry keys, PEB flags


import os, re
import volatility.debug as debug
import volatility.plugins.common as common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Hex
import volatility.plugins.taskmods as taskmods
from volatility.plugins.malware.malfind import LdrModules
import volatility.win32.rawreg as rawreg
import volatility.plugins.registry.registryapi as registryapi

knownSystemShimmingDlls = ["SCShim.dll", "acadproc.dll", "apphelp.dll", "AcGenral.dll", "AcLayers.dll", "AcRes.dll", "AcSpecfc.dll", "AcWinRT.dll", "acwow64.dll", "AcXtrnal.dll", "acgenral.dll", "aclayers.dll", "aclua.dll", "acspecfc.dll", "acxtrnal.dll", "apihex86.dll",]
knownMaliciousShimmingDlls = ["AcProtect.dll", "vc32loader.dll", "VCLdr64.dll", "SPVCLdr64.dll", "SPVC64Loader.dll", "spvc64loader.dll", ]
# if I wanted to be really efficient I would hard code the lists below
# knownSystemShimmingDlls_lower = []
# knownMaliciousShimmingDlls_lower = []
# shimmingDlls_lower = []

class sdbScanner(taskmods.DllList):
    """Scans for shimmed processes, via linked (and unlinked) dll's in the process"""
    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        self._config.add_option('NAME', short_option = 'n', default = None,
                               help = 'Process name to match',
                               action = 'store', type = 'str')
        
    def unified_output(self, data):
        return TreeGrid([("ImageFileName", str),
                       ("Pid", int),
                       ("Dll Name", str),
                       ("Dll Path", str),
                       ("Note", str)],
                        self.generator(data))

    
    def generator(self,data):
        # this code should all be the same as render_text except for the yield vs table_row return part
        # Process AS must be valid
        # loop through all the task
        for task in data:
            pid = task.UniqueProcessId
            
            if task.Peb:
                for m in task.get_load_modules():
                    yield (0, [str(task.ImageFileName or ''), int(pid), str(m.FullDllName or '')])
            else:
                yield (0, [str(''),
                           int(pid),
                           "Error reading PEB for pid"])

    # the vol platform calls this function.
    # DO NOT believe the old documentation here:  
    def render_text(self, outfd, data):
        # windows is a little weird with case sensitivity (usually windows is case-aware but not case sensitive). 
        # Depending on how the loader is searching for libraries, it might tack on a ".DLL" to the path
        # but the above list is case sensitive file names. So below I'm making multiple lists for efficiency reasons 
        # In testing I found this is the best performance for lists of this size
        knownSystemShimmingDlls_lower = [ dll.lower() for dll in knownSystemShimmingDlls]
        knownMaliciousShimmingDlls_lower = [ dll.lower() for dll in knownMaliciousShimmingDlls]
        shimmingDlls_lower = knownSystemShimmingDlls_lower + knownMaliciousShimmingDlls_lower
        
        
        regapi = registryapi.RegistryApi(self._config)
        #regapi.set_current('system')    # set the services root - I don't know if this matters
                                                                        
        debug.debug("Getting the registry keys")
        # the first option speficies the hive which would be HKLM. But with None it checks all (which doesn't hurt)
        customShims = regapi.reg_get_key(None, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom') 
        customShimsInstallLocation = regapi.reg_get_key(None, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB")
        
        if customShims:
            for s in rawreg.subkeys(customShims):
                outfd.write(s.Name + ": " + str(s))
        else:
            debug.debug("CustomShim Key had nothing (or wasn't there)")
        
        if customShimsInstallLocation:
            for s in rawreg.subkeys(customShimsInstallLocation):
                debug.debug(s.Name + ": " + str(s))
                outfd.write(s.Name + ": " + str(s))
        else:
            debug.debug("Custom Shim Install Location Key had nothing (or wasn't there)")
        
        
        self.table_header(outfd,
                                  [("Process Name", ""),
                                   ("PID", ""),
                                   ("Dll Name", ""),
                                   ("Full Dll Name", ""),
                                   ("Notes", ""),
                                   ])
        
        # loop through all the tasks
        ''' list that I get back: (0, theListBelow)
        [    int(task.UniqueProcessId),
           str(task.ImageFileName),
           Address(base),
           str(load_mod != None),
           str(init_mod != None),
           str(mem_mod != None),
           str(mapped_files[base])]
           
           (0, [4, 'System', 1995243520L, 'False', 'False', 'False', '\\Windows\\System32\\ntdll.dll'])
        '''
        ldrMod = LdrModules(self._config)
        for (zero, [UniqueProcessId, ImageFileName, baseAddress, load_mod, init_mod, mem_mod, mappedDllFullPath] ) in LdrModules.generator(ldrMod, data):
            if mappedDllFullPath is not None and mappedDllFullPath != "":
                FullDllName = mappedDllFullPath
                BaseDllName = mappedDllFullPath.split("\\")[-1].lower()
            else:
                pass
            
            if BaseDllName in shimmingDlls_lower:
                if BaseDllName in knownSystemShimmingDlls_lower and FullDllName.startswith("\\Windows\\"):
                    self.table_row(outfd, ImageFileName, UniqueProcessId, BaseDllName, FullDllName, "Indicates Shimming")
                elif BaseDllName in knownMaliciousShimmingDlls_lower:
                    self.table_row(outfd, ImageFileName, UniqueProcessId, BaseDllName, FullDllName, "Known Malicious Shimming!!!")
                else:
                    self.table_row(outfd, ImageFileName, UniqueProcessId, BaseDllName, FullDllName, "Indicates NOT Normal Shimming")
            
        
        
        # the simple way of doing it - which could result in missed dll's if they are unlinked and/or WOW64   
        '''
        for task in data:
            ImageFileName = str(task.ImageFileName or "")
            debug.debug("Using old method of Searching Modules list of " + ImageFileName)
            
            if task.IsWow64:
                outfd.write("Note: use ldrmodules for listing DLLs in Wow64 processes\n")
                #volatility/plugins/malware/malfind.py:# ldrmodules 
                #volatility/plugins/malware/malfind.py:class LdrModules(taskmods.DllList):

            
            for m in task.get_load_modules():
                FullDllName = str(m.FullDllName or "")
                BaseDllName = str(m.BaseDllName or "").lower()
                if BaseDllName in shimmingDlls_lower:
                    
                    if BaseDllName in knownSystemShimmingDlls_lower and "C:\\Windows\\" in FullDllName:
                        self.table_row(outfd, ImageFileName, task.UniqueProcessId, BaseDllName, FullDllName, "Indicates Normal Shimming")
                    elif BaseDllName in knownMaliciousShimmingDlls_lower:
                        self.table_row(outfd, ImageFileName, task.UniqueProcessId, BaseDllName, FullDllName, "Malicious Shimming!!!")
                    else:
                        self.table_row(outfd, ImageFileName, task.UniqueProcessId, BaseDllName, FullDllName, "Indicates Not Normal Shimming")
        '''
        '''
        for m in task.get_load_modules():
            for dll in knownSystemShimmingDlls:
                if str(m.BaseDllName) is not None and str(m.BaseDllName).lower() == str(dll).lower():
                    #self.table_row(outfd, m.DllBase, m.SizeOfImage, m.LoadCount, str(m.BaseDllName or ''))
                    
                    self.table_row(outfd, str(task.ImageFileName or "") , task.UniqueProcessId, str(m.FullDllName or ""))
        '''
                
        '''
        if task.Peb:
            for m in task.get_load_modules():
                if str(m.BaseDllName) in knownSystemShimmingDlls:
                    self.table_row(outfd, filename, pid, str(m.FullDllName or ''))
                if str(m.BaseDllName) in knownMaliciousShimmingDlls:
                    self.table_row(outfd, filename, pid, str(m.FullDllName or ''))
        else:
            outfd.write("Unable to read PEB for task.\n")
        '''
        
        '''
        outfd.write("*" * 72 + "\n")
        outfd.write("{0} pid: {1:6}\n".format(task.ImageFileName, pid))
        # Do the same loop here checking your dll list def generator
        if task.Peb:
            outfd.write("Command line : {0}\n".format(str(task.Peb.ProcessParameters.CommandLine or '')))
            if task.IsWow64:
                outfd.write("Note: use ldrmodules for listing DLLs in Wow64 processes\n")
            outfd.write("{0}\n".format(str(task.Peb.CSDVersion or '')))
            outfd.write("\n")
            self.table_header(outfd,
                              [("Base", "[addrpad]"),
                               ("Size", "[addr]"),
                               ("LoadCount", "[addr]"),
                               ("Path", ""),
                               ])
            for m in task.get_load_modules():
                self.table_row(outfd, m.DllBase, m.SizeOfImage, m.LoadCount, str(m.FullDllName or ''))
        else:
            outfd.write("Unable to read PEB for task.\n")
        '''

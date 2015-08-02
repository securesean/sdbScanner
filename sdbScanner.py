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
Date		   Aug 1 2015
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
#knownSystemShimmingDlls_lower = []
#knownMaliciousShimmingDlls_lower = []
#shimmingDlls_lower = []

class sdbScanner(taskmods.DllList):
    """Scans for shimmed processes, via linked (and unlinked) dll's in the process"""
        
    def unified_output(self, data):
        return TreeGrid([("ImageFileName", str),
                       ("Pid", int),
                       ("Dll Name", str),
                       ("Dll Path", str),
                       ("Note", str)],
                        self.generator(data))

    
    def generator(self,data):
        ldrMod = LdrModules(self._config)
        for (zero, [UniqueProcessId, ImageFileName, baseAddress, load_mod, init_mod, mem_mod, mappedDllFullPath] ) in LdrModules.generator(ldrMod, data):
            if mappedDllFullPath is not None and mappedDllFullPath != "":
                FullDllName = mappedDllFullPath
                BaseDllName = mappedDllFullPath.split("\\")[-1].lower()
                note = ""
                
                if BaseDllName in self.shimmingDlls_lower:
                    if BaseDllName in self.knownSystemShimmingDlls_lower and FullDllName.startswith("\\Windows\\"):
                        note = "Indicates Shimming"
                    elif BaseDllName in self.knownMaliciousShimmingDlls_lower:
                        note = "Known Malicious Shimming!!!"
                    else:
                        note = "Indicates NOT Normal Shimming"
                    # I don't know what the first number does
                    yield (0, [str(ImageFileName or ''), UniqueProcessId, BaseDllName, FullDllName, note])


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
        
        self.table_header(outfd,
                                  [("Process Name", ""),
                                   ("PID", ""),
                                   ("Dll Name", ""),
                                   ("Full Dll Name", ""),
                                   ("Notes", ""),
                                   ])
        
        ldrMod = LdrModules(self._config)
        for (zero, [UniqueProcessId, ImageFileName, baseAddress, load_mod, init_mod, mem_mod, mappedDllFullPath] ) in LdrModules.generator(ldrMod, data):
            if mappedDllFullPath is not None and mappedDllFullPath != "":
                FullDllName = mappedDllFullPath
                BaseDllName = mappedDllFullPath.split("\\")[-1].lower()
                note = ""
                
                if BaseDllName in shimmingDlls_lower:
                    if BaseDllName in knownSystemShimmingDlls_lower and FullDllName.startswith("\\Windows\\"):
                        note = "Indicates Shimming"
                    elif BaseDllName in self.knownMaliciousShimmingDlls_lower:
                        note = "Known Malicious Shimming!!!"
                    else:
                        note = "Indicates NOT Normal Shimming"
                    # I don't know what the first number does
                    #yield (0, [str(ImageFileName or ''), UniqueProcessId, BaseDllName, FullDllName, note])
                    self.table_row(outfd, ImageFileName, UniqueProcessId, BaseDllName, FullDllName, note)
        

#! /usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import socket
import indigo
import math
import decimal
import datetime
import time
import simplejson as json
import os
from ghpu import GitHubPluginUpdater
import sys
PYTHON_VERSION = sys.version_info[0]
import urllib
    
#from unifi.controller import Controller

class APIError(Exception):
    #self.debugLog("Error Web API: " + str(Exception))
    #plugin.errorLog("Error Web API: " + str(Exception))
    pass
        
class Plugin(indigo.PluginBase):

    def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
        indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)
        self.updater = GitHubPluginUpdater(self)

        self.ControllerIP   = ""
        self.ControllerPort = ""
        self.ControllerRel  = "V4"
        self.ControllerSite = ""
        self.ControllerAuth     = False
        self.ControllerUsername = ""
        self.ControllerPassword = ""
        self.ControllerInterval = 0
        self.ControllerURL      = ""
        self.ControllerURLAPI   = ""
        self.CurlCommand        = ""

        # create empty device list
        self.userDeviceList = {}
        self.wlanDeviceList = {}

        self.sock = None
        self.socketBufferSize = 512
        self.socketStop       = False
        
        self.pushoverPlugin = None
        
    def __del__(self):
        indigo.PluginBase.__del__(self)

    ###################################################################
    # Plugin
    ###################################################################

    def deviceStartComm(self, device):
        self.debugLog(device.name + ": Starting device")
        device.stateListOrDisplayStateIdChanged()
        self.addDeviceToList (device)

    def addDeviceToList(self,device):
        if device:
            if device.deviceTypeId == u"unifiuser":
                self.addDeviceToListUser(device)
            elif device.deviceTypeId == u"unifiwlan":
                self.addDeviceToListWlan(device)
    
    def addDeviceToListUser(self,device):
        propsIPAddress = ''
        propsMACAddress = ''

        if device.id not in self.userDeviceList:
            propsIPAddress  = device.pluginProps["ipaddress"].strip().replace (' ','')           
            propsMACAddress = device.pluginProps["macaddress"].strip().replace (' ','')            
            
            self.userDeviceList[device.id] = {'ref':device, 'ipaddress':propsIPAddress, 'macaddress':propsMACAddress}
            if propsMACAddress > '':
                device.pluginProps["address"] = propsMACAddress
            else:
                device.pluginProps["address"] = propsIPAddress
    
    def addDeviceToListWlan(self,device):
        if device.id not in self.wlanDeviceList:
            ssid = device.pluginProps["ssid"].strip()
            self.wlanDeviceList[device.id] = {'ref':device, 'ssid':ssid}
            
            
    def deleteDeviceFromList(self, device):
        if device:
            if device.deviceTypeId == u"unifiuser":
                if device.id in self.userDeviceList:
                    del self.userDeviceList[device.id]
            elif device.deviceTypeId == u"unifiwlan":
                if device.id in self.wlanDeviceList:
                    del self.wlanDeviceList[device.id]

    def deviceStopComm(self,device):
        if device.id not in self.userDeviceList:
            return
        self.debugLog(device.name + ": Stoping device")
        self.deleteDeviceFromList(device)

    def startup(self):
        self.loadPluginPrefs()
        self.debugLog(u"startup called")
        self.requestID = 0
        self.pushoverPlugin  = indigo.server.getPlugin("io.thechad.indigoplugin.pushover")
        if not self.pushoverPlugin.isEnabled():
            self.debugLog (u"Error: Pushover plugin is not enabled")
        self.updater.checkForUpdate()

    def shutdown(self):
        self.debugLog(u"shutdown called")

    def deviceCreated(self, device):
        self.debugLog(u"Created device of type \"%s\"" % device.deviceTypeId)

    def validateDeviceConfigUi(self, valuesDict, typeId, devId):
        self.debugLog(u"validating device Prefs called")
        if typeId == "unifiuser":
            ipAdr  = valuesDict[u'ipaddress']
            macAdr = valuesDict[u'macaddress']

            if (ipAdr > "") or (macAdr > ""):
                pass
            else:
                errorMsgDict = indigo.Dict()
                errorMsgDict[u'ipaddress'] = u"Mac or IP address needed."
                errorMsgDict[u'macaddress'] = u"Mac or IP address needed."
                return (False, valuesDict, errorMsgDict)
            if (ipAdr > ""):
                if ipAdr.count('.') != 3:
                    errorMsgDict = indigo.Dict()
                    errorMsgDict[u'ipaddress'] = u"This needs to be a valid IP address."
                    return (False, valuesDict, errorMsgDict)
                if self.validateAddress (ipAdr) == False:
                    errorMsgDict = indigo.Dict()
                    errorMsgDict[u'ipaddress'] = u"This needs to be a valid IP address."
                    return (False, valuesDict, errorMsgDict)
            if (macAdr > ""):
                #1c:ab:a7:d8:23:d2
                if macAdr.count(':') != 5:
                    errorMsgDict = indigo.Dict()
                    errorMsgDict[u'macaddress'] = u"This needs to be a valid MAC address."
                    return (False, valuesDict, errorMsgDict)
        if typeId == "unifiwlan":
            ssid = valuesDict[u'ssid'].strip()
            if not ssid:
                errorMsgDict = indigo.Dict()
                errorMsgDict[u'ssid'] = u"SSID needed."
                return (False, valuesDict, errorMsgDict)
        
        return (True, valuesDict)

    def validatePrefsConfigUi(self, valuesDict):
        self.debugLog(u"validating Prefs called")

        ipAdr = valuesDict[u'ipaddress']
        if ipAdr.count('.') != 3:
            errorMsgDict = indigo.Dict()
            errorMsgDict[u'ipaddress'] = u"This needs to be a valid IP address."
            return (False, valuesDict, errorMsgDict)
        if self.validateAddress (ipAdr) == False:
            errorMsgDict = indigo.Dict()
            errorMsgDict[u'ipaddress'] = u"This needs to be a valid IP address."
            return (False, valuesDict, errorMsgDict)

        tcpPort = valuesDict[u'port']
        try:
            iPort = int(tcpPort)
            if iPort <= 0:
                errorMsgDict = indigo.Dict()
                errorMsgDict[u'port'] = u"This needs to be a valid TCP port."
                return (False, valuesDict, errorMsgDict)
        except Exception, e:
            errorMsgDict = indigo.Dict()
            errorMsgDict[u'port'] = u"This needs to be a valid TCP port."
            return (False, valuesDict, errorMsgDict)


        if (valuesDict[u'useAuthentication']):
            if not(valuesDict[u'username']>""):
                errorMsgDict = indigo.Dict()
                errorMsgDict[u'username'] = u"Must be filled."
                return (False, valuesDict, errorMsgDict)
            if not(valuesDict[u'password']>""):
                errorMsgDict = indigo.Dict()
                errorMsgDict[u'password'] = u"Must be filled."
                return (False, valuesDict, errorMsgDict)

        return (True, valuesDict)

    def closedDeviceConfigUi(self, valuesDict, userCancelled, typeId, devId):
        if userCancelled is False:
            indigo.server.log ("Device preferences were updated.")
            device = indigo.devices[devId]
            self.deleteDeviceFromList (device)
            self.addDeviceToList (device)
            
    def closedPrefsConfigUi ( self, valuesDict, UserCancelled):
        #   If the user saves the preferences, reload the preferences
        if UserCancelled is False:
            indigo.server.log ("Preferences were updated, reloading Preferences...")
            self.loadPluginPrefs()

    def loadPluginPrefs(self):
        # set debug option
        if 'debugEnabled' in self.pluginPrefs:
            self.debug = self.pluginPrefs['debugEnabled']
        else:
            self.debug = False

        self.ControllerIP   = self.pluginPrefs["ipaddress"]
        self.ControllerPort = self.pluginPrefs["port"]
        self.ControllerRel  = self.pluginPrefs["release"]
        self.ControllerRel  = self.ControllerRel.strip()
        self.ControllerRel  = self.ControllerRel.upper()
        self.ControllerSite = self.pluginPrefs["siteid"]
        self.ControllerAuth     = self.pluginPrefs["useAuthentication"]
        self.ControllerUsername = self.pluginPrefs["username"]
        self.ControllerPassword = self.pluginPrefs["password"]
        self.ControllerInterval = int(self.pluginPrefs["interval"])
        if (self.ControllerInterval > 0):
            pass
        else:
            self.ControllerInterval = 60

        self.ControllerURL = "https://" + self.ControllerIP.strip() + ":" + self.ControllerPort.strip() + "/"

        if (self.ControllerRel == 'V2'):
            self.ControllerURLAPI = self.ControllerURL + "api/"
        else:
            self.ControllerURLAPI = self.ControllerURL + "api/s/" + self.ControllerSite.strip() + "/"

        indigo.server.log ("Preferences loaded for Unifi controller " + self.ControllerURL + " (Release " + self.ControllerRel +")")

    def menuGetDevWlan(self, filter, valuesDict, typeId, elemId):
        menuList = []
        wLanList = self.unifiGetWlanList()        
        for wlan in wLanList:
            name = wlan['name'].strip()
            menuList.append((name, name))
        return menuList

    ###################################################################
    # Concurrent Thread.
    ###################################################################

    def runConcurrentThread(self):
        try:
            lastTime = datetime.datetime.now()
            nextTime = lastTime
            while not(self.stopThread):
                self.sleep(0.3)
                todayNow = datetime.datetime.now()
                if nextTime <= todayNow:

                    nextTime = todayNow + datetime.timedelta(seconds=self.ControllerInterval)                    
                    self.unifiUserStatusRequest()
                    self.unifiWlanStatusRequest()
        except self.StopThread:
            pass
            self.debugLog(u"Exited loop")

        except Exception, e:
            self.errorLog (u"Error: " + str(e))
            pass


    def stopConcurrentThread(self):
        self.stopThread = True
        self.debugLog(u"stopConcurrentThread called")


    ###################################################################
    # Unifi Web API
    ###################################################################
    
    #curl1 = /usr/bin/curl --tlsv1 --cookie /tmp/unifi_cookie --cookie-jar /tmp/unifi_cookie --insecure --data "login=login" --data "username=canteula" --data "password=tenallero" https://172.30.74.43:8443/login
    #curl2 = /usr/bin/curl --tlsv1 --cookie /tmp/unifi_cookie --cookie-jar /tmp/unifi_cookie --insecure --data "login=login" --data "username=canteula" --data "password=tenallero" https://172.30.74.43:8443/api/s/default/stat/sta
    #curl3 = /usr/bin/curl --tlsv1 --cookie /tmp/unifi_cookie --cookie-jar /tmp/unifi_cookie --insecure --data "login=login" --data "username=canteula" --data "password=tenallero" https://172.30.74.43:8443/api/s/default/list/wlanconf


    #self.CurlCommand = curl1 + "; " + curl2


    def getCurlLoginV2 (self):
        res = ""
        res += '/usr/bin/curl --ss3 --cookie /tmp/unifi_cookie --cookie-jar /tmp/unifi_cookie --insecure --data "login=login" '
        res += ' --data "username=' + self.ControllerUsername + '" '
        res += ' --data "password=' + self.ControllerPassword + '" '
        res += ' ' + self.ControllerURL + 'login'
        return res
        
    def getCurlLoginV3 (self):
        res = ""
        res += '/usr/bin/curl --tlsv1 --cookie /tmp/unifi_cookie --cookie-jar /tmp/unifi_cookie --insecure --data "login=login" '
        res += ' --data "username=' + self.ControllerUsername + '" '
        res += ' --data "password=' + self.ControllerPassword + '" '
        res += ' ' + self.ControllerURL + 'login'
        return res
        
    def getCurlLoginV4 (self):
        res = ""
        res += '/usr/bin/curl -X POST --tlsv1 --insecure '
        res += ' -H "Content-Type: application/json; charset=utf-8"'
        res += ' -H "Referer: ' + self.ControllerURL + 'login?redirect=%2Fmanage" '
        res += ' --cookie /tmp/unifi_cookie --cookie-jar /tmp/unifi_cookie '
        res += " -d '{"
        res += '"username": "' + self.ControllerUsername + '", '
        res += '"password": "' + self.ControllerPassword + '" '
        res += "}'"
        res += ' ' + self.ControllerURL + 'api/login'
        return res
        
    def getCurlLogin (self):
        if (self.ControllerRel == 'V2'):
           return self.getCurlLoginV2()
        if (self.ControllerRel == 'V3'):
           return self.getCurlLoginV3()
        if (self.ControllerRel == 'V4'):
           return self.getCurlLoginV4()   
        return ""
        
    def getCurlCommand (self,url):
        if (self.ControllerRel == 'V2'):
            apiurl = 'api/'
        else:
            apiurl = 'api/s/' + self.ControllerSite.strip() + '/'
        res = ""
        res += '/usr/bin/curl --tlsv1 --cookie /tmp/unifi_cookie --cookie-jar /tmp/unifi_cookie --insecure '
        if (self.ControllerRel == 'V2') or (self.ControllerRel == 'V3'):
            res += ' --data "login=login" '
            res += ' --data "username=' + self.ControllerUsername + '" '
            res += ' --data "password=' + self.ControllerPassword + '" '
        res += ' ' + self.ControllerURL
        res += apiurl
        res += url
        return res

    def getCurlCommand_getClients (self):
        return self.getCurlCommand('stat/sta')

    def getCurlCommand_getUsers (self):
        return self.getCurlCommand('list/user')

    def getCurlCommand_getAps (self):
        return self.getCurlCommand('stat/device')

    def getCurlCommand_getWlans (self):
        return self.getCurlCommand('list/wlanconf')

    def getCurlCommand_getWlanDetail(self,id):
        if id:
            return self.getCurlCommand('upd/wlanconf/' + id.strip())
        else:
            return ''
            
    def validateAddress (self,value):
        try:
            socket.inet_aton(value)
        except socket.error:
            return False
        return True

    def _jsondec(self, data):
        obj = json.loads(data)
        if 'meta' in obj:
            if obj['meta']['rc'] != 'ok':
                raise APIError(obj['meta']['msg'])
        if 'data' in obj:
            return obj['data']
        return obj


    ###################################################################
    # Login
    ###################################################################
    
    def doLogin (self):
        if (self.ControllerRel == 'V2'):
           return self.doLoginV3()
        if (self.ControllerRel == 'V3'):
           return self.doLoginV3()
        if (self.ControllerRel == 'V4'):
           return self.doLoginV4()   
        return False
        
    def doLoginV3 (self):
        theCMD  = ""
        try:
            theCMD = self.getCurlLogin()
            p = os.popen(theCMD,"r")
            
        except Exception, e:
            self.debugLog("Error calling curl")
            self.debugLog(theCMD)
            return False
        return True
        
    def doLoginV4 (self):
        theJSON = ""
        theCMD  = ""
        res     = None
        
        try:
            theCMD = self.getCurlLogin()
            p = os.popen(theCMD,"r")
            while 1:
                line = p.readline()
                if not line: break
                theJSON += line
        except Exception, e:
            self.debugLog("Error calling curl")
            self.debugLog(theCMD)
            return False
        try:
            res = self._jsondec(theJSON)
        except Exception, e:
            self.debugLog("Bad json file")
            self.debugLog(theCMD)
            self.debugLog(theJSON)
            return False
        
        # Buscar "rc":"ok"
        #meta = res["meta"]  
        #rc = meta["rc"]
        #if rc == "ok":
        #    return True
        #else:
        #    self.debugLog("Invalid login")
        #    return False
        return True
        
        
    ###################################################################
    # WLAN device methodes
    ###################################################################

    def unifiGetWlanList(self):
        theJSON = ""
        theCMD  = ""
        res     = None
        
        if not(self.doLogin()):
            return None
            
        try:
            theCMD = self.getCurlCommand_getWlans()
            p = os.popen(theCMD,"r")
            while 1:
                line = p.readline()
                if not line: break
                theJSON += line
        except Exception, e:
            self.debugLog("Error calling curl")
            self.debugLog(theCMD)
            return None

        try:
            res = self._jsondec(theJSON)
        except Exception, e:
            self.debugLog("Bad json file")
            self.debugLog(theCMD)
            self.debugLog(theJSON)
            return None
        return res
    
    def unifiGetWlanDetail(self,id):
        theJSON = ""
        theCMD  = ""
        res     = None
        
        if not(self.doLogin()):
            return None
            
        try:
            theCMD = self.getCurlCommand_getWlanDetail(id)
            p = os.popen(theCMD,"r")
            while 1:
                line = p.readline()
                if not line: break
                theJSON += line
        except Exception, e:
            self.debugLog("Error calling curl")
            self.debugLog(theCMD)
            return None

        try:
            res = self._jsondec(theJSON)
        except Exception, e:
            self.debugLog("Bad json file")
            self.debugLog(theCMD)
            self.debugLog(theJSON)
            return None
        return res
    
    def unifiPostWlanDetail(self,id,changes):
        theCMD  = ''
        theJSON = ''
        id = id.strip()
        if not id or not changes:
            return
        if (self.ControllerRel == 'V2'):
            apiurl = 'api/'
        else:
            apiurl = 'api/s/' + self.ControllerSite.strip() + '/'
            
        
        payload = {
            "name":changes["name"],
            "security":changes["security"],
            "x_passphrase":changes["x_passphrase"],
            "wep_idx":changes["wep_idx"],
            "x_wep":changes["x_wep"],
            "enabled":changes["enabled"],
            "is_guest":changes["is_guest"],
            "vlan_enabled":changes["vlan_enabled"],
            "vlan":changes["vlan"],
            "hide_ssid":changes["hide_ssid"],
            "wpa_mode":changes["wpa_mode"],
            "wpa_enc":changes["wpa_enc"],
            "usergroup_id":changes["usergroup_id"],
            "wlangroup_id":changes["wlangroup_id"],
            "radius_ip_1":changes["radius_ip_1"],
            "radius_port_1":changes["radius_port_1"],
            "x_radius_secret_1":changes["x_radius_secret_1"],
            "radius_ip_2":"",
            "radius_port_2":"",
            "x_radius_secret_2":"",
            "radius_ip_3":"",
            "radius_port_3":"",
            "x_radius_secret_3":"",
            "radius_ip_4":"",
            "radius_port_4":"",
            "x_radius_secret_4":"",
            "radius_acct_ip_1":"",
            "radius_acct_port_1":"",
            "x_radius_acct_secret_1":"",
            "radius_acct_ip_2":"",
            "radius_acct_port_2":"",
            "x_radius_acct_secret_2":"",
            "radius_acct_ip_3":"",
            "radius_acct_port_3":"",
            "x_radius_acct_secret_3":"",
            "radius_acct_ip_4":"",
            "radius_acct_port_4":"",
            "x_radius_acct_secret_4":""
            }
           
        payloadData = json.dumps(payload) 
                        
        theCMD = ""
        theCMD += "/usr/bin/curl "        
        # Añado URL
        #theCMD += " '" + self.ControllerURL + apiurl + 'upd/wlanconf/' + id + "'" 
        if (self.ControllerRel == 'V4'):
            # Añado Content-Type
            theCMD += ' -X POST '
            theCMD += ' --tlsv1 --insecure '
            theCMD += ' --cookie /tmp/unifi_cookie --cookie-jar /tmp/unifi_cookie  ' 
            theCMD += ' -H "Content-Type: application/json; charset=utf-8" '
            theCMD += ' -H "Accept: */*" '     
            # Añado data
            theCMD += " -d '"
            theCMD += payloadData
            theCMD += "' "
            theCMD += self.ControllerURL + apiurl + 'upd/wlanconf/' + id 
        else:
            # Añado Content-Type
            theCMD += " -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' "
            theCMD += " -H 'Accept: */*'"     
            # Añado data
            theCMD += " --data 'json="
            payloadData = urllib.quote_plus(payloadData) 
            theCMD += payloadData
            theCMD += "'"
            #Añado autentificacion 
            theCMD += ' --tlsv1 --cookie /tmp/unifi_cookie --cookie-jar /tmp/unifi_cookie --insecure ' 
            if (self.ControllerRel == 'V2') or (self.ControllerRel == 'V3'):
                theCMD += ' --data "login=login" '
                theCMD += ' --data "username=' + self.ControllerUsername + '" '
                theCMD += ' --data "password=' + self.ControllerPassword + '" '    
            theCMD += self.ControllerURL + apiurl + 'upd/wlanconf/' + id 
            
        if not(self.doLogin()):
            return None
            
        try:
            p = os.popen(theCMD,"r")
            while 1:
                line = p.readline()
                if not line: break
                theJSON += line
        except Exception, e:
            self.debugLog("Error calling curl: " + str(e))
            self.debugLog(theCMD)      
            return None

        try:
            res = self._jsondec(theJSON)
        except Exception, e:
            self.debugLog("Bad json file: " + str(e))
            self.debugLog(theCMD)
            self.debugLog(theJSON)
            return None
        return res
        
    
    def unifiWlanStatusRequest (self):
        unifiWlanList = self.unifiGetWlanList()  
        if unifiWlanList:
            for wlan in self.wlanDeviceList:
                try:
                    ssid = self.wlanDeviceList[wlan]['ssid'].strip().upper()
                    for sta in unifiWlanList:
                        name = ""
                        enabled = False
                        try:
                            try:
                                name = sta['name'].strip().upper()
                            except Exception, e:
                                pass
                            try:
                                enabled = sta['enabled']
                            except Exception, e:
                                pass
                            if name == ssid:
                                device = self.wlanDeviceList[wlan]["ref"]
                                if enabled:
                                    device.updateStateOnServer("onOffState",True) 
                                else:
                                    device.updateStateOnServer("onOffState",False) 
                                break
                        except Exception, e:
                            self.errorLog("Error looping wlans (1): " + str(e))


                except Exception, e:
                    self.errorLog("Error looping wlans (2): " + str(e))

    def unifiWlanRelayOn (self,device):
        indigo.server.log('Enabling WLAN "' + device.name + '"') 
        device.updateStateOnServer("onOffState",True)
        self.unifiWlanSetEnabled (device,True)

    def unifiWlanRelayOff (self,device):
        indigo.server.log('Disabling WLAN "' + device.name + '"') 
        device.updateStateOnServer("onOffState",False)
        self.unifiWlanSetEnabled (device,False)
        
    def unifiWlanRelayToggle (self,device):
        if device.states["onOffState"]:
            self.unifiWlanRelayOff(device)
        else:
            self.unifiWlanRelayOn(device)
   
    # https://teulix:8443/api/s/default/upd/wlanconf/55edded860b26b9aabb6a3c1
    # POST
    # {"name":"Lifx","security":"wpapsk","x_passphrase":"hel@d0depIn@p@r@elnIn0yl@nIn@","wep_idx":"1","x_wep":"","enabled":false,"is_guest":false,"vlan_enabled":false,"vlan":"","hide_ssid":true,"wpa_mode":"wpa2","wpa_enc":"ccmp","usergroup_id":"509039f3f0a9b0e4bd219d88","wlangroup_id":"550da4f160b2c94710a0c927","radius_ip_1":"","radius_port_1":"1812","x_radius_secret_1":"","radius_ip_2":"","radius_port_2":"","x_radius_secret_2":"","radius_ip_3":"","radius_port_3":"","x_radius_secret_3":"","radius_ip_4":"","radius_port_4":"","x_radius_secret_4":"","radius_acct_ip_1":"","radius_acct_port_1":"","x_radius_acct_secret_1":"","radius_acct_ip_2":"","radius_acct_port_2":"","x_radius_acct_secret_2":"","radius_acct_ip_3":"","radius_acct_port_3":"","x_radius_acct_secret_3":"","radius_acct_ip_4":"","radius_acct_port_4":"","x_radius_acct_secret_4":""}
    
    # if PYTHON_VERSION == 2:
    #        return self._read(self.api_url + 'cmd/' + mgr, urllib.urlencode({'json': json.dumps(params)}))
    
    
    def unifiWlanSetEnabled (self,device,enabled):
        unifiWlanList = self.unifiGetWlanList() 
        target        = None
        unifiEnabled  = False
        unifiId       = ""  
        ssid = device.pluginProps['ssid'].strip().upper() 
        for wlan in unifiWlanList:         
            try:
                unifiName = wlan['name'].strip().upper()
                if unifiName == ssid:                    
                    unifiEnabled = wlan['enabled']                    
                    unifiId      = wlan['_id']   
                    wlanmatch    = wlan                       
                    break               
            except Exception, e:
                self.errorLog("unifiWlanSetEnabled Error: " + str(e))
        if unifiId:       
            if unifiEnabled == enabled:
                #self.debugLog("unifiWlanSetEnabled: No hacemos nada." )
                return
            device.updateStateOnServer("onOffState",enabled)  
            if (self.ControllerRel == 'V4'):   
                target = wlanmatch
            else:
                res    = self.unifiGetWlanDetail(unifiId) 
                if res[0]:
                    target = res[0] 
            if (target):
                
                target['enabled'] = enabled
                #self.debugLog(str(target))
                self.unifiPostWlanDetail(unifiId,target)  
            
            
            self.unifiWlanStatusRequest()
             
    
    
    ###################################################################
    # User device methodes
    ###################################################################

    def unifiUserStatusRequest (self):
        theJSON = ""
        theCMD  = ""

        if not(self.doLogin()):
            return

        try:
            theCMD = self.getCurlCommand_getClients()
            p = os.popen(theCMD,"r")
            while 1:
                line = p.readline()
                if not line: break
                theJSON += line
        except Exception, e:
            self.debugLog("Error calling curl")
            self.debugLog(theCMD)
            return

        try:
            res = self._jsondec(theJSON)
        except Exception, e:
            self.debugLog("Bad json file")
            self.debugLog(theCMD)
            self.debugLog(theJSON)
            return

        for client in self.userDeviceList:
            try:
                clientDevice = self.userDeviceList[client]['ref']
                
                connected    = False
                matched      = False
                
                rssi         = 0
                signal       = 0
                lastSeen     = 0
                firstSeen    = 0
                upTime       = 0
                ap_mac       = ''
                
                for sta in res:
                    mac = ""
                    ip  = ""
                    try:
                        try:
                            mac = sta['mac']
                        except Exception, e:
                            pass
                        try:
                            ip  = sta['ip']
                        except Exception, e:
                            pass

                        if mac > "":
                            if self.userDeviceList[client]['macaddress'] == mac:
                                matched = True
                        if ip > "":
                            if self.userDeviceList[client]['ipaddress'] == ip:
                                matched = True
                        if (matched):
                            lastSeen  = int(sta['last_seen'])
                            firstSeen = int(sta['first_seen'])
                            upTime    = int(sta['uptime'])
                            #name = sta['name']
                            #hostname = sta['hostname']
                            rssi   = int(sta['rssi'])
                            signal = int(sta['signal'])
                            ap_mac = sta['ap_mac']
                            break
                            
                    except Exception, e:
                        self.errorLog("Error looping clients (1): " + str(e))

                
                
                connected = matched

                if clientDevice.states["onOffState"] != connected:
                    clientDevice.updateStateOnServer("onOffState",connected)
                    if connected:
                        self.debugLog('device "' + clientDevice.name + '" now is connected.')
                    else:
                        self.debugLog('device "' + clientDevice.name + '" now is absent.')

                if connected:
                    self.updateDeviceState (clientDevice,"lastSeen",  lastSeen) 
                    self.updateDeviceState (clientDevice,"lastAppMac",  ap_mac)
                    
                self.updateDeviceState (clientDevice,"firstSeen", firstSeen)                                  
                self.updateDeviceState (clientDevice,"upTime",    upTime)    
                self.updateDeviceState (clientDevice,"rssi",      rssi)
                self.updateDeviceState (clientDevice,"signal",    signal)

            except Exception, e:
                self.errorLog("Error looping clients (2): " + str(e))

    def updateDeviceState(self,device,state,newValue):
        if (newValue != device.states[state]):
            device.updateStateOnServer(key=state, value=newValue)
            
    def sendRpcRequest(self, device, method, params):
        pass

    ###################################################################
    # Custom Action callbacks
    ###################################################################

    def actionControlDimmerRelay(self, action, dev):
        if action.deviceAction == indigo.kDeviceAction.TurnOn:
            self.unifiWlanRelayOn (dev)
        elif action.deviceAction == indigo.kDeviceAction.TurnOff:
            self.unifiWlanRelayOff (dev)
        elif action.deviceAction == indigo.kDeviceAction.Toggle:
            self.unifiWlanRelayToggle (dev)
        elif action.deviceAction == indigo.kDeviceAction.SetBrightness:
            pass
        elif action.deviceAction == indigo.kDeviceAction.RequestStatus:
            indigo.server.log ('sent "' + dev.name + '" status request')
            self.unifiWlanStatusRequest()
            pass

    def actionControlSensor(self, pluginAction, device):
        if pluginAction.sensorAction == indigo.kDeviceAction.RequestStatus:
            indigo.server.log ('sent "' + device.name + '" status request')
            self.unifiUserStatusRequest()

    ########################################
    # Actions Methods
    ########################################
    
    def silentStatusRequest (self, pluginAction, device):
        self.unifiUserStatusRequest()
        self.unifiWlanStatusRequest()        
        pass

    ########################################
    # Menu Methods
    ########################################
    def toggleDebugging(self):
        if self.debug:
            indigo.server.log("Turning off debug logging")
            self.pluginPrefs["debugEnabled"] = False                
        else:
            indigo.server.log("Turning on debug logging")
            self.pluginPrefs["debugEnabled"] = True
        self.debug = not self.debug
        return
        
    def menuDeviceDiscovery(self):
        if self.discoveryWorking:
            return
        self.deviceDiscover()
        return
        
    def checkForUpdates(self):
        update = self.updater.checkForUpdate() 
        if (update != None):
            pass
        return    

    def updatePlugin(self):
        self.updater.update()
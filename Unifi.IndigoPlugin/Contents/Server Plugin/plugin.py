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
#from unifi.controller import Controller

class Plugin(indigo.PluginBase):

    def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
        indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)


        self.ControllerIP   = ""
        self.ControllerPort = ""
        self.ControllerRel  = "V3"
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

    def __del__(self):
        indigo.PluginBase.__del__(self)

    ###################################################################
    # Plugin
    ###################################################################

    def deviceStartComm(self, device):
        self.debugLog(device.name + ": Starting device")
        device.stateListOrDisplayStateIdChanged()
        propsIPAddress = ''
        propsMACAddress = ''
        propsMinutesOut = 0
        lastseen  = int(time.time()) - 15000
        firstseen = int(time.time()) - 15000
        if device.id not in self.userDeviceList:
            propsIPAddress = device.pluginProps["ipaddress"]
            propsIPAddress = propsIPAddress.strip()
            propsIPAddress = propsIPAddress.replace (' ','')
            propsMACAddress = device.pluginProps["macaddress"]
            propsMACAddress = propsMACAddress.strip()
            propsMACAddress = propsMACAddress.replace (' ','')
            propsMinutesOut = int(device.pluginProps["minutesout"])
            self.userDeviceList[device.id] = {'ref':device, 'ipaddress':propsIPAddress, 'minutesout': propsMinutesOut, 'macaddress':propsMACAddress, 'lastseen':lastseen, 'firstseen':firstseen}
            if propsMACAddress > '':
                device.pluginProps["address"] = propsMACAddress
            else:
                device.pluginProps["address"] = propsIPAddress


    def deviceStopComm(self,device):
        if device.id not in self.userDeviceList:
            return
        self.debugLog(device.name + ": Stoping device")
        del self.userDeviceList[device.id]

    def startup(self):
        self.loadPluginPrefs()
        self.debugLog(u"startup called")
        self.requestID = 0


    def shutdown(self):
        self.debugLog(u"shutdown called")


    def deviceCreated(self, device):
        self.debugLog(u"Created device of type \"%s\"" % device.deviceTypeId)

    def validateDeviceConfigUi(self, valuesDict, typeId, devId):
        self.debugLog(u"validating device Prefs called")
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

        #curl1 = '/usr/bin/curl --tlsv1 --cookie /tmp/unifi_cookie --cookie-jar /tmp/unifi_cookie --insecure --data "login=login" --data "username=canteula" --data "password=tenallero" https://172.30.74.43:8443/login'
        #curl2 = '/usr/bin/curl --tlsv1 --cookie /tmp/unifi_cookie --cookie-jar /tmp/unifi_cookie --insecure --data "login=login" --data "username=canteula" --data "password=tenallero" https://172.30.74.43:8443/api/s/default/stat/sta'

        #self.CurlCommand = curl1 + "; " + curl2

    def getCurlCommand (self,url):

        if url == 'login':
            apiurl = ''
            pass
        else:
            if (self.ControllerRel == 'V2'):
                apiurl = 'api/'
            else:
                apiurl = 'api/s/' + self.ControllerSite.strip() + '/'
        res = ""
        res += '/usr/bin/curl --tlsv1 --cookie /tmp/unifi_cookie --cookie-jar /tmp/unifi_cookie --insecure --data "login=login" '
        res += ' --data "username=' + self.ControllerUsername + '" '
        res += ' --data "password=' + self.ControllerPassword + '" '
        res += ' ' + self.ControllerURL
        res += apiurl
        res += url
        return res

    def getCurlCommand_getClients (self):
        return self.getCurlCommand('login') + ' ; ' + self.getCurlCommand('stat/sta')
        #if  (self.ControllerRel == 'V2'):
        #   return self.getCurlCommand('login') + ' ; ' + self.getCurlCommand('api/stat/sta')
        #else:
        #   return self.getCurlCommand('login') + ' ; ' + self.getCurlCommand('api/s/default/stat/sta')

    def getCurlCommand_getUsers (self):
        return self.getCurlCommand('login') + ' ; ' + self.getCurlCommand('list/user')


    def getCurlCommand_getAps (self):
        return self.getCurlCommand('login') + ' ; ' + self.getCurlCommand('stat/device')

    def getCurlCommand_getWlans (self):
        return self.getCurlCommand('login') + ' ; ' + self.getCurlCommand('list/wlanconf')

    def validateAddress (self,value):
        try:
            socket.inet_aton(value)
        except socket.error:
            return False
        return True

    ###################################################################
    # Concurrent Thread. Socket
    ###################################################################

    def runConcurrentThread(self):

        try:

            lastTime = datetime.datetime.now()
            nextTime = lastTime
            while not(self.stopThread):
                self.sleep(0.5)
                todayNow = datetime.datetime.now()
                if nextTime <= todayNow:

                    nextTime = todayNow + datetime.timedelta(seconds=self.ControllerInterval)
                    self.unifiWlanStatusRequest()
                    self.unifiUserStatusRequest()
        except self.StopThread:
            pass
            self.debugLog(u"Exited loop")

        except Exception, e:
            self.errorLog (u"Error: " + str(e))
            pass


    def stopConcurrentThread(self):

        self.stopThread = True
        self.debugLog(u"stopConcurrentThread called")

    class APIError(Exception):
        pass

    def _jsondec(self, data):
        obj = json.loads(data)
        if 'meta' in obj:
            if obj['meta']['rc'] != 'ok':
                raise APIError(obj['meta']['msg'])
        if 'data' in obj:
            return obj['data']
        return obj

    def unifiWlanStatusRequest (self):

        theJSON = ""
        theCMD  = ""

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
            return

        try:
            res = self._jsondec(theJSON)
        except Exception, e:
            self.debugLog("Bad json file")
            self.debugLog(theCMD)
            self.debugLog(theJSON)
            return




        for wlan in self.wlanDeviceList:
            try:
                ssid = self.userDeviceList[wlan]['ssid']
                for sta in res:
                    name = ""
                    enabled = False
                    try:
                        try:
                            name = sta['name']
                        except Exception, e:
                            pass
                        try:
                            enabled = sta['enabled']
                        except Exception, e:
                            pass

                        if name == ssid:
                            matched = True

                        if (matched):
                            pass

                    except Exception, e:
                        self.debugLog("Error looping devices (2). ")


            except Exception, e:
                self.debugLog("Error looping wlans. ") # + e.strerror)


    def unifiUserStatusRequest (self):

        theJSON = ""
        theCMD  = ""

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


        now = int(time.time())

        for client in self.userDeviceList:
            try:
                clientDevice = self.userDeviceList[client]['ref']
                lastseen     = self.userDeviceList[client]['lastseen']
                firstseen    = self.userDeviceList[client]['firstseen']
                minutesout   = self.userDeviceList[client]['minutesout']
                secondsout   = minutesout * 60
                connected    = False
                matched      = False
                memolast     = lastseen

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
                            lastseen = int(sta['last_seen'])
                            firstseen = int(sta['first_seen'])
                            #name = sta['name']
                            #hostname = sta['hostname']
                            #snr = sta['rssi']
                            #signal = sta['signal']
                    except Exception, e:
                        self.debugLog("Error looping devices (2). ")

                if (now - lastseen) > secondsout:
                    connected = False
                else:
                    connected = True
                if clientDevice.states["onOffState"] != connected:
                    clientDevice.updateStateOnServer("onOffState",connected)
                    if connected:
                        self.debugLog("Unifi Controller: " + clientDevice.name + ' is connected. Has been absent during ' + str((now - memolast)/60) + ' minutes.' )
                        self.userDeviceList[client]['firstseen'] = now
                    else:
                        self.debugLog("Unifi Controller: " + clientDevice.name + ' is disconnected. Has been present during ' + str((now - firstseen)/60) + ' minutes.' )
                self.userDeviceList[client]['firstseen'] = firstseen
                self.userDeviceList[client]['lastseen'] = lastseen



            except Exception, e:
                self.debugLog("Error looping devices. ") # + e.strerror)


    def sendRpcRequest(self, device, method, params):
        pass

    def actionControlSensor(self, pluginAction, device):
        if pluginAction.sensorAction == indigo.kDeviceAction.RequestStatus:
            indigo.server.log ("Unifi controller. Requesting status ... ")
            self.unifiUserStatusRequest()
            self.unifiWlanStatusRequest()

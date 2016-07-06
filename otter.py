from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
    
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Otter")
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
        return
        
    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "Otter"
    
    def getUiComponent(self):
        return self._splitpane
        
    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
   
        # Only process responses that came from the proxy. This will
        # ignore request/responses made by Otter itself.
        # TODO(kkl): Only process in-scope requests.
        if not messageIsRequest and toolFlag == self._callbacks.TOOL_PROXY:
            # create a new log entry with the message details
            row = self._log.size()

            # analyze and store information about the original request/response
            responseBytes = messageInfo.getResponse()
            requestBytes = messageInfo.getRequest()
            request = self._helpers.analyzeRequest(messageInfo)
            response = self._helpers.analyzeResponse(responseBytes)

            # make a modified request to test for authorization issues
            # TODO(kkl): Modify the request bytes.
            modReqResp = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), requestBytes)
            modRequestBytes = modReqResp.getRequest()
            modResponseBytes = modReqResp.getResponse()
            modResponse = self._helpers.analyzeResponse(modResponseBytes)

            entry = LogEntry(self._callbacks.saveBuffersToTempFiles(messageInfo), request.getUrl(), response.getStatusCode(), len(responseBytes), modResponse.getStatusCode(), len(modResponseBytes))

            self._lock.acquire()
            self._log.add(entry)
            self.fireTableRowsInserted(row, row)
            self._lock.release()
        return

    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 5

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "URL"
        if columnIndex == 1:
            return "Orig. Status"
        if columnIndex == 2:
            return "Orig. Length"
        if columnIndex == 3:
            return "Mod. Status"
        if columnIndex == 4:
            return "Mod. Length"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry._url.toString()
        if columnIndex == 1:
            return str(logEntry._origStatus)
        if columnIndex == 2:
            return str(logEntry._origLength)
        if columnIndex == 3:
            return str(logEntry._modStatus)
        if columnIndex == 4:
            return str(logEntry._modLength)
        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

#
# extend JTable to handle cell selection
#
    
class Table(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        return
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
        return
    
#
# class to hold details of each log entry
#

class LogEntry:

    def __init__(self, requestResponse, url, origStatus, origLength, modStatus, modLength):
        self._requestResponse = requestResponse
        self._url = url
        self._origStatus = origStatus
        self._origLength = origLength
        self._modStatus = modStatus
        self._modLength = modLength
        return

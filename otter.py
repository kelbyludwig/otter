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
from javax.swing import JLabel;
from javax.swing import JTextArea;
from javax.swing import JCheckBox;
from javax.swing import JPanel;
from javax.swing import SwingUtilities;
from javax.swing.table import TableRowSorter;
from javax.swing.table import AbstractTableModel;
from org.python.core.util.StringUtil import fromBytes, toBytes;
from threading import Lock
from re import search, sub
from string import replace, find

#TODO(kkl): Make the table UI sortable.
#TODO(kkl): A setting for hiding unmodified requests/responses.
#TODO(kkl): Allow for a configurable amount of request modifications.
#TODO(kkl): Ignore typically static file extensions by default (e.g. js, css). Allow for opt-out..
#TODO(kkl): Another useful response difference metric could be difflib's
#           `ratio` method. This would likely require hideable columns in the log-entry as
#           I don't think this would be useful by default to most.

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
       
        # main split pane for log entries and request/response viewing
        self._settingPanel = JPanel()
        self._logPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        # setup settings pane ui
        self._settingPanel.setBounds(0,0,1000,1000)
        self._settingPanel.setLayout(None)

        self._isRegexp = JCheckBox("Use regexp for matching.")
        self._isRegexp.setBounds(10, 10, 220, 20)

        matchLabel = JLabel("String to Match:")
        matchLabel.setBounds(10, 40, 200, 20)
        self._matchString = JTextArea("User 1 Session Information")
        self._matchString.setWrapStyleWord(True)
        self._matchString.setLineWrap(True)
        matchString = JScrollPane(self._matchString)
        matchString.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        matchString.setBounds(10, 60, 400, 200)

        replaceLabel = JLabel("String to Replace:")
        replaceLabel.setBounds(10, 270, 200, 20)
        self._replaceString = JTextArea("User 2 Session Information")
        self._replaceString.setWrapStyleWord(True)
        self._replaceString.setLineWrap(True)
        replaceString = JScrollPane(self._replaceString)
        replaceString.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        replaceString.setBounds(10, 290, 400, 200)

        self._settingPanel.add(self._isRegexp)
        self._settingPanel.add(matchLabel)
        self._settingPanel.add(matchString)
        self._settingPanel.add(replaceLabel)
        self._settingPanel.add(replaceString)
        
        # table of log entries
        self.logTable = Table(self)
        self.logTable.getColumnModel().getColumn(0).setPreferredWidth(700)
        self.logTable.getColumnModel().getColumn(1).setPreferredWidth(150)
        self.logTable.getColumnModel().getColumn(2).setPreferredWidth(100)
        self.logTable.getColumnModel().getColumn(3).setPreferredWidth(130)
        self.logTable.getColumnModel().getColumn(4).setPreferredWidth(100)
        self.logTable.getColumnModel().getColumn(5).setPreferredWidth(130)

        # rudimentary row sorting, use .setRowFilter for filters
        self.tableSorter = TableRowSorter(self)
        self.logTable.setRowSorter(self.tableSorter)

        scrollPane = JScrollPane(self.logTable)
        self._logPane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        logTabs = JTabbedPane()
        self._origRequestViewer = callbacks.createMessageEditor(self, False)
        self._origResponseViewer = callbacks.createMessageEditor(self, False)
        self._modRequestViewer = callbacks.createMessageEditor(self, False)
        self._modResponseViewer = callbacks.createMessageEditor(self, False)
        logTabs.addTab("Original Request", self._origRequestViewer.getComponent())
        logTabs.addTab("Original Response", self._origResponseViewer.getComponent())
        logTabs.addTab("Modified Request", self._modRequestViewer.getComponent())
        logTabs.addTab("Modified Response", self._modResponseViewer.getComponent())
        self._logPane.setRightComponent(logTabs)
        
        # top most tab interface that seperates log entries from settings
        maintabs = JTabbedPane()
        maintabs.addTab("Log Entries", self._logPane)
        maintabs.addTab("Settings", self._settingPanel)
        self._maintabs = maintabs
       
        # customize the UI components
        callbacks.customizeUiComponent(maintabs)
        
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
        return self._maintabs
        
    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
   
        # Only process responses that came from the proxy. This will
        # ignore request/responses made by Otter itself.
        if not messageIsRequest and toolFlag == self._callbacks.TOOL_PROXY:
            # create a new log entry with the message details
            row = self._log.size()

            # analyze and store information about the original request/response
            responseBytes = messageInfo.getResponse()
            requestBytes = messageInfo.getRequest()
            request = self._helpers.analyzeRequest(messageInfo)
            response = self._helpers.analyzeResponse(responseBytes)
            
            # ignore out-of-scope requests.
            if not self._callbacks.isInScope(request.getUrl()):
                return

            wasModified = False
            ms = self._matchString.getText()
            rs = self._replaceString.getText()
            mss = ms.split(",")
            rss = rs.split(",")
            if len(rss) != len(mss):
                mss = [""]
                
            for i,x in enumerate(mss):
                if x == "":
                    continue
                if self._isRegexp.isSelected():
                    if search(x, requestBytes):
                        requestBytes = sub(x, rss[i], requestBytes)
                        wasModified = True
                else:
                    if fromBytes(requestBytes).find(x) >= 0:
                        requestBytes = toBytes(replace(fromBytes(requestBytes), x, rss[i]))
                        wasModified = True

            # make a modified request to test for authorization issues
            entry = None
            if wasModified:
                modReqResp = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), requestBytes)
                modRequestBytes = modReqResp.getRequest()
                modResponseBytes = modReqResp.getResponse()
                modResponse = self._helpers.analyzeResponse(modResponseBytes)
                orig = self._callbacks.saveBuffersToTempFiles(messageInfo)
                mod = self._callbacks.saveBuffersToTempFiles(modReqResp)
                entry = LogEntry(orig, mod, request.getUrl(), response.getStatusCode(), len(responseBytes), modResponse.getStatusCode(), len(modResponseBytes), wasModified)
            else:
                orig = self._callbacks.saveBuffersToTempFiles(messageInfo)
                entry = LogEntry(orig, None, request.getUrl(), response.getStatusCode(), len(responseBytes), "None", 0, wasModified)

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
        return 6

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "URL"
        if columnIndex == 1:
            return "Request Modified?"
        if columnIndex == 2:
            return "Orig. Status"
        if columnIndex == 3:
            return "Orig. Length"
        if columnIndex == 4:
            return "Mod. Status"
        if columnIndex == 5:
            return "Mod. Length"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry._url.toString()
        if columnIndex == 1:
            return str(logEntry._wasModified)
        if columnIndex == 2:
            return str(logEntry._origStatus)
        if columnIndex == 3:
            return str(logEntry._origLength)
        if columnIndex == 4:
            return str(logEntry._modStatus)
        if columnIndex == 5:
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
        logEntry = self._extender._log.get(self._extender.logTable.convertRowIndexToModel(row))
        self._extender._origRequestViewer.setMessage(logEntry._origRequestResponse.getRequest(), True)
        self._extender._origResponseViewer.setMessage(logEntry._origRequestResponse.getResponse(), False)
        if not logEntry._modRequestResponse is None:
            self._extender._modRequestViewer.setMessage(logEntry._modRequestResponse.getRequest(), True)
            self._extender._modResponseViewer.setMessage(logEntry._modRequestResponse.getResponse(), False)
        else:
            self._extender._modRequestViewer.setMessage(toBytes(""), True)
            self._extender._modResponseViewer.setMessage(toBytes(""), False)
        self._extender._currentlyDisplayedItem = logEntry._origRequestResponse
        JTable.changeSelection(self, row, col, toggle, extend)
        return
    
#
# class to hold details of each log entry
#

class LogEntry:

    def __init__(self, origRequestResponse, modRequestResponse, url, origStatus, origLength, modStatus, modLength, wasModified):
        self._origRequestResponse = origRequestResponse
        self._modRequestResponse = modRequestResponse
        self._url = url
        self._origStatus = origStatus
        self._origLength = origLength
        self._modStatus = modStatus
        self._modLength = modLength
        self._wasModified = wasModified
        return

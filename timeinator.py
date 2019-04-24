from re import sub
from socket import gethostbyname
from threading import Thread
from time import time

from javax.swing import (JTabbedPane, JPanel, JLabel, JTextField,
                         JTextArea, JCheckBox, JMenuItem, JButton, JTable,
                         JScrollPane, JProgressBar)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import Color, GridBagLayout, GridBagConstraints, Insets
import java.lang

from burp import (
    IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController)

EXTENSION_NAME = "Timeinator"
COLUMNS = [
    "Payload", "Number of Requests", "Status Code", "Length (B)", "Body (B)",
    "Minimum (ms)", "Maximum (ms)", "Mean (ms)", "Median (ms)"]


def mean(values):
    return sum(values) / len(values)


def median(values):
    length = len(values)
    values.sort()
    if length % 2 != 0:
        # Odd number of values, so chose middle one
        return values[length//2]
    else:
        # Even number of values, so mean of middle two
        return mean([values[length//2], values[(length//2)-1]])


class BurpExtender(
          IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController):

    # Implement IBurpExtender
    def registerExtenderCallbacks(self, callbacks):

        callbacks.registerContextMenuFactory(self)

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName(EXTENSION_NAME)

        # Construct UI

        self._tabbedPane = JTabbedPane()

        insets = Insets(3, 3, 3, 3)

        # Target Panel
        attackPanel = JPanel(GridBagLayout())

        targetHeadingLabel = JLabel("<html><b>Target</b></html>")
        targetHeadingLabelConstraints = GridBagConstraints()
        targetHeadingLabelConstraints.gridx = 0
        targetHeadingLabelConstraints.gridy = 0
        targetHeadingLabelConstraints.gridwidth = 4
        targetHeadingLabelConstraints.anchor = GridBagConstraints.LINE_START
        targetHeadingLabelConstraints.insets = insets
        attackPanel.add(targetHeadingLabel, targetHeadingLabelConstraints)

        startAttackButton = JButton("<html><b>Start Attack</b></html>",
                                    actionPerformed=self._startAttack)
        startAttackButtonConstraints = GridBagConstraints()
        startAttackButtonConstraints.gridx = 4
        startAttackButtonConstraints.gridy = 0
        startAttackButtonConstraints.insets = insets
        attackPanel.add(startAttackButton, startAttackButtonConstraints)

        hostLabel = JLabel("Host:")
        hostLabelConstraints = GridBagConstraints()
        hostLabelConstraints.gridx = 0
        hostLabelConstraints.gridy = 1
        hostLabelConstraints.anchor = GridBagConstraints.LINE_START
        hostLabelConstraints.insets = insets
        attackPanel.add(hostLabel, hostLabelConstraints)

        self._hostTextField = JTextField(25)
        self._hostTextField.setMinimumSize(
            self._hostTextField.getPreferredSize())
        hostTextFieldConstraints = GridBagConstraints()
        hostTextFieldConstraints.gridx = 1
        hostTextFieldConstraints.gridy = 1
        hostTextFieldConstraints.weightx = 1
        hostTextFieldConstraints.gridwidth = 2
        hostTextFieldConstraints.anchor = GridBagConstraints.LINE_START
        hostTextFieldConstraints.insets = insets
        attackPanel.add(self._hostTextField, hostTextFieldConstraints)

        portLabel = JLabel("Port:")
        portLabelConstraints = GridBagConstraints()
        portLabelConstraints.gridx = 0
        portLabelConstraints.gridy = 2
        portLabelConstraints.anchor = GridBagConstraints.LINE_START
        portLabelConstraints.insets = insets
        attackPanel.add(portLabel, portLabelConstraints)

        self._portTextField = JTextField(5)
        self._portTextField.setMinimumSize(
            self._portTextField.getPreferredSize())
        portTextFieldConstraints = GridBagConstraints()
        portTextFieldConstraints.gridx = 1
        portTextFieldConstraints.gridy = 2
        portTextFieldConstraints.gridwidth = 2
        portTextFieldConstraints.anchor = GridBagConstraints.LINE_START
        portTextFieldConstraints.insets = insets
        attackPanel.add(self._portTextField, portTextFieldConstraints)

        self._protocolCheckBox = JCheckBox("Use HTTPS")
        protocolCheckBoxConstraints = GridBagConstraints()
        protocolCheckBoxConstraints.gridx = 0
        protocolCheckBoxConstraints.gridy = 3
        protocolCheckBoxConstraints.gridwidth = 3
        protocolCheckBoxConstraints.anchor = GridBagConstraints.LINE_START
        protocolCheckBoxConstraints.insets = insets
        attackPanel.add(self._protocolCheckBox, protocolCheckBoxConstraints)

        requestHeadingLabel = JLabel("<html><b>Request</b></html>")
        requestHeadingLabelConstraints = GridBagConstraints()
        requestHeadingLabelConstraints.gridx = 0
        requestHeadingLabelConstraints.gridy = 4
        requestHeadingLabelConstraints.gridwidth = 4
        requestHeadingLabelConstraints.anchor = GridBagConstraints.LINE_START
        requestHeadingLabelConstraints.insets = insets
        attackPanel.add(requestHeadingLabel, requestHeadingLabelConstraints)

        self._messageEditor = callbacks.createMessageEditor(self, True)
        messageEditorComponent = self._messageEditor.getComponent()
        messageEditorComponentConstraints = GridBagConstraints()
        messageEditorComponentConstraints.gridx = 0
        messageEditorComponentConstraints.gridy = 5
        messageEditorComponentConstraints.weightx = 1
        messageEditorComponentConstraints.weighty = .75
        messageEditorComponentConstraints.gridwidth = 4
        messageEditorComponentConstraints.gridheight = 2
        messageEditorComponentConstraints.fill = GridBagConstraints.BOTH
        messageEditorComponentConstraints.insets = insets
        attackPanel.add(
            messageEditorComponent, messageEditorComponentConstraints)

        addPayloadButton = JButton(
            "Add \xa7", actionPerformed=self._addPayload)
        addPayloadButtonConstraints = GridBagConstraints()
        addPayloadButtonConstraints.gridx = 4
        addPayloadButtonConstraints.gridy = 5
        addPayloadButtonConstraints.fill = GridBagConstraints.HORIZONTAL
        addPayloadButtonConstraints.insets = insets
        attackPanel.add(addPayloadButton, addPayloadButtonConstraints)

        clearPayloadButton = JButton(
            "Clear \xa7", actionPerformed=self._clearPayloads)
        clearPayloadButtonConstraints = GridBagConstraints()
        clearPayloadButtonConstraints.gridx = 4
        clearPayloadButtonConstraints.gridy = 6
        clearPayloadButtonConstraints.anchor = GridBagConstraints.PAGE_START
        clearPayloadButtonConstraints.fill = GridBagConstraints.HORIZONTAL
        clearPayloadButtonConstraints.insets = insets
        attackPanel.add(clearPayloadButton, clearPayloadButtonConstraints)

        payloadHeadingLabel = JLabel("<html><b>Payloads<b></html>")
        payloadHeadingLabelConstraints = GridBagConstraints()
        payloadHeadingLabelConstraints.gridx = 0
        payloadHeadingLabelConstraints.gridy = 7
        payloadHeadingLabelConstraints.gridwidth = 4
        payloadHeadingLabelConstraints.anchor = GridBagConstraints.LINE_START
        payloadHeadingLabelConstraints.insets = insets
        attackPanel.add(payloadHeadingLabel, payloadHeadingLabelConstraints)

        self._payloadTextArea = JTextArea()
        payloadScrollPane = JScrollPane(self._payloadTextArea)
        payloadScrollPaneConstraints = GridBagConstraints()
        payloadScrollPaneConstraints.gridx = 0
        payloadScrollPaneConstraints.gridy = 8
        payloadScrollPaneConstraints.weighty = .25
        payloadScrollPaneConstraints.gridwidth = 3
        payloadScrollPaneConstraints.fill = GridBagConstraints.BOTH
        payloadScrollPaneConstraints.insets = insets
        attackPanel.add(payloadScrollPane, payloadScrollPaneConstraints)

        requestsNumLabel = JLabel("Number of requests for each payload:")
        requestsNumLabelConstraints = GridBagConstraints()
        requestsNumLabelConstraints.gridx = 0
        requestsNumLabelConstraints.gridy = 9
        requestsNumLabelConstraints.gridwidth = 2
        requestsNumLabelConstraints.anchor = GridBagConstraints.LINE_START
        requestsNumLabelConstraints.insets = insets
        attackPanel.add(requestsNumLabel, requestsNumLabelConstraints)

        self._requestsNumTextField = JTextField("10", 4)
        self._requestsNumTextField.setMinimumSize(
            self._requestsNumTextField.getPreferredSize())
        requestsNumTextFieldConstraints = GridBagConstraints()
        requestsNumTextFieldConstraints.gridx = 2
        requestsNumTextFieldConstraints.gridy = 9
        requestsNumTextFieldConstraints.anchor = GridBagConstraints.LINE_START
        requestsNumTextFieldConstraints.insets = insets
        attackPanel.add(
            self._requestsNumTextField, requestsNumTextFieldConstraints)

        # Results Panel
        resultsPanel = JPanel(GridBagLayout())

        self._progressBar = JProgressBar()
        self._progressBar.setStringPainted(True)
        self._progressBar.setMinimum(0)
        progressBarContraints = GridBagConstraints()
        progressBarContraints.gridx = 0
        progressBarContraints.gridy = 0
        progressBarContraints.fill = GridBagConstraints.HORIZONTAL

        resultsPanel.add(self._progressBar, progressBarContraints)

        self._resultsTableModel = ResultsTableModel(COLUMNS, 0)
        resultsTable = JTable(self._resultsTableModel)
        resultsTable.setAutoCreateRowSorter(True)
        cellRenderer = ColoredTableCellRenderer()
        for index in [5, 6, 7, 8]:
            column = resultsTable.columnModel.getColumn(index)
            column.cellRenderer = cellRenderer
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(99999999)
        resultsTable.getColumnModel().getColumn(1).setMinWidth(160)
        resultsTable.getColumnModel().getColumn(2).setMinWidth(100)
        resultsTable.getColumnModel().getColumn(3).setMinWidth(80)
        resultsTable.getColumnModel().getColumn(4).setMinWidth(80)
        resultsTable.getColumnModel().getColumn(5).setMinWidth(110)
        resultsTable.getColumnModel().getColumn(6).setMinWidth(110)
        resultsTable.getColumnModel().getColumn(7).setMinWidth(110)
        resultsTable.getColumnModel().getColumn(8).setMinWidth(110)
        resultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        resultsScrollPane = JScrollPane(resultsTable)
        resultsScrollPaneConstraints = GridBagConstraints()
        resultsScrollPaneConstraints.gridx = 0
        resultsScrollPaneConstraints.gridy = 1
        resultsScrollPaneConstraints.weightx = 1
        resultsScrollPaneConstraints.weighty = 1
        resultsScrollPaneConstraints.fill = GridBagConstraints.BOTH
        resultsPanel.add(resultsScrollPane, resultsScrollPaneConstraints)

        # About Panel
        aboutPanel = JPanel(GridBagLayout())
        with open("about.html") as file:
            aboutBody = file.read()
        aboutLabel = JLabel(
                aboutBody.format(extension_name=EXTENSION_NAME))
        aboutLabelConstraints = GridBagConstraints()
        aboutLabelConstraints.weightx = 1
        aboutLabelConstraints.weighty = 1
        aboutLabelConstraints.insets = insets
        aboutLabelConstraints.fill = GridBagConstraints.HORIZONTAL
        aboutLabelConstraints.anchor = GridBagConstraints.PAGE_START

        aboutPanel.add(aboutLabel, aboutLabelConstraints)

        self._tabbedPane.addTab("Attack", attackPanel)
        self._tabbedPane.addTab("Results", resultsPanel)
        self._tabbedPane.addTab("About", aboutPanel)

        callbacks.addSuiteTab(self)

    # Implement ITab
    def getTabCaption(self):
        return EXTENSION_NAME

    def getUiComponent(self):
        return self._tabbedPane

    # Implement IMessageEditorController
    def getHttpService(self):
        self._updateClassFromUI()
        return self._httpService

    def getRequest(self):
        # Strangely this doesn't seem necessary; returning None also works.
        self._updateClassFromUI()
        return self._request

    def getResponse(self):
        return None

    # Implement IContextMenuFactory
    def createMenuItems(self, contextMenuInvocation):
        messages = contextMenuInvocation.getSelectedMessages()

        # Only add menu item if a single request is selected
        if len(messages) == 1:
            self._contextMenuData = messages
            menu_item = JMenuItem(
                "Send to {}".format(EXTENSION_NAME),
                actionPerformed=self._contextMenuItemClicked
            )
            return [menu_item]

    def _contextMenuItemClicked(self, _):
        httpRequestResponse = self._contextMenuData[0]

        # Update class variables with request data
        self._httpService = httpRequestResponse.getHttpService()
        self._request = httpRequestResponse.getRequest()

        # Update fields in tab
        self._hostTextField.setText(self._httpService.getHost())
        self._portTextField.setText(str(self._httpService.getPort()))
        self._protocolCheckBox.setSelected(
            True if self._httpService.getProtocol() == "https" else False)
        self._messageEditor.setMessage(self._request, True)

    def _startAttack(self, _):

        # Switch to results tab
        self._tabbedPane.setSelectedIndex(1)

        # Clear results table
        self._resultsTableModel.setRowCount(0)

        # Set progress bar to 0%
        self._progressBar.setValue(0)

        Thread(target=self._makeHttpRequests).start()

    def _makeHttpRequests(self):

        # Set class variables from values in UI
        self._updateClassFromUI()

        self._responses = {}

        # Set progress bar max to number of requests
        self._progressBar.setMaximum(len(self._payloads) * self._numReq)

        for payload in self._payloads:
            self._responses[payload] = []
            # Stick payload into request at specified position
            # Use lambda function for replacement string to stop slashes being
            # escaped
            request = sub("\xa7[^\xa7]*\xa7", lambda x: payload, self._request)
            request = self._updateContentLength(request)
            for _ in xrange(self._numReq):
                # Make request and work out how long it took in ms. This method
                # is crude, but it's as good as we can get with current Burp
                # APIs. See https://bit.ly/2JX29Nf
                startTime = time()
                response = self._callbacks.makeHttpRequest(
                    self._httpService, request)
                endTime = time()
                duration = (endTime - startTime) * 1000

                self._progressBar.setValue(self._progressBar.getValue() + 1)

                self._responses[payload].append(duration)

                # If all responses for this payload have
                #  been added to array, add to results table.
                if len(self._responses[payload]) == self._numReq:
                    # Add results to results tab
                    results = self._responses[payload]
                    numReqs = self._numReq
                    statusCode = response.getStatusCode()
                    analysis = self._helpers.analyzeResponse(
                        response.getResponse())
                    for header in analysis.getHeaders():
                        if header.startswith("Content-Length"):
                            content_length = int(header.split(": ")[1])
                    meanTime = round(mean(results), 3)
                    medianTime = round(median(results), 3)
                    minTime = int(min(results))
                    maxTime = int(max(results))
                    rowData = [
                        payload, numReqs, statusCode,
                        len(response.getResponse()), content_length, minTime,
                        maxTime, meanTime, medianTime]
                    self._resultsTableModel.addRow(rowData)

    def _updateClassFromUI(self):
        host = self._hostTextField.text
        port = int(self._portTextField.text)
        protocol = "https" if self._protocolCheckBox.isSelected() else "http"

        # I previously tried using the IP address of the destination web server
        # instead of the hostname when building the HttpService. This was in an
        # attempt to prevent DNS queries introducing a delay. Unfortunately it
        # caused issues with HTTPS requests, probably because of SNIs. As an
        # alternative, the hostname is resolved in the next line and hopefully
        # it will be cached at that point.
        gethostbyname(host)

        self._httpService = self._helpers.buildHttpService(
            host, port, protocol)
        self._request = self._updateContentLength(
            self._messageEditor.getMessage())
        self._numReq = int(self._requestsNumTextField.text)
        self._payloads = set(self._payloadTextArea.text.split("\n"))

    def _addPayload(self, _):
        request = self._messageEditor.getMessage()
        selection = self._messageEditor.getSelectionBounds()
        if selection[0] == selection[1]:
            # No text selected so in/out points are same
            request.insert(selection[0], 0xa7)
            request.insert(selection[1], 0xa7)
        else:
            request.insert(selection[0], 0xa7)
            request.insert(selection[1]+1, 0xa7)
        self._messageEditor.setMessage(request, True)

    def _clearPayloads(self, _):
        request = self._messageEditor.getMessage()
        request = self._helpers.bytesToString(request).replace("\xa7", "")
        self._messageEditor.setMessage(request, True)

    def _updateContentLength(self, request):
        # Dirty trick (toggle type twice) to make burp fix the
        # Content-Length header
        request = self._helpers.toggleRequestMethod(request)
        request = self._helpers.toggleRequestMethod(request)
        return request


# Required for coloured cells
class ColoredTableCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column):

        renderer = DefaultTableCellRenderer.getTableCellRendererComponent(
                self, table, value, isSelected, hasFocus, row, column)

        value = table.getValueAt(row, column)
        model = table.getModel()
        rowsCount = model.getRowCount()
        if rowsCount == 1:
            renderer.setBackground(table.getBackground())
            renderer.setForeground(table.getForeground())
        else:
            colValues = []
            for index in xrange(rowsCount):
                valueAtIndex = model.getValueAt(index, column)
                colValues.append(valueAtIndex)
            minBound = min(colValues)
            maxBound = max(colValues)
            if minBound != maxBound:
                valueAsFraction = (
                    float(value - minBound) / (maxBound - minBound))
                if valueAsFraction > 0.75:
                    renderer.setForeground(Color.WHITE)
                else:
                    renderer.setForeground(Color.BLACK)
                if valueAsFraction > 0.5:
                    red = 1.0
                else:
                    red = (valueAsFraction * 2.0)
                if valueAsFraction < 0.5:
                    green = 1.0
                else:
                    green = 2 - (valueAsFraction * 2.0)
                blue = 111/256.0

                if isSelected:
                    red -= 0.25
                    if red < 0:
                        red = 0.0

                    green -= 0.25
                    if green < 0:
                        green = 0.0

                    blue -= 0.25
                    if blue < 0:
                        blue = 0.0

                renderer.setBackground(Color(red, green, blue))
        return renderer


# Required for proper sorting
class ResultsTableModel(DefaultTableModel):
    def getColumnClass(self, column):
        # Native java types are required here for proper sortings
        types = [
            java.lang.String,
            java.lang.Integer,
            java.lang.Integer,
            java.lang.Integer,
            java.lang.Integer,
            java.lang.Integer,
            java.lang.Integer,
            java.lang.Float,
            java.lang.Float]
        return types[column]

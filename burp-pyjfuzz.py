"""
Burp-PyJFuzz trivial python fuzzer based on radamsa.

MIT License

Copyright (c) 2016 Daniele Linguaglossa <d.linguaglossa@mseclab.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import subprocess
import urllib
from burp import ITab
from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from javax.swing import JLabel, JTextField, JOptionPane, JTabbedPane, JPanel, JButton
from java.awt import GridBagLayout, GridBagConstraints

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, ITab):
    name = "Burp PyJFuzz"
    args = ""
    _jTabbedPane = JTabbedPane()
    _jPanel = JPanel()
    _jAboutPanel = JPanel()
    _jPanelConstraints = GridBagConstraints()
    _jLabelParameters = None
    _jTextFieldParameters = None
    _jLabelTechniques = None
    _jTextFieldTechniques = None
    _jLabelFuzzFactor = None
    _jTextFieldFuzzFactor = None
    _jLabelAdditionalCmdLine = None
    _jTextFieldAdditionalCmdLine = None
    _jButtonSetCommandLine = None
    _jLabelAbout = None
    aboutText = """
<center><h2><b>PyJFuzz</b> - <i>Trivial JSON Fuzzer</i></h2><br>
Created by Daniele 'dzonerzy' Linguaglossa, security consultant @ Consulthink S.p.A.<br>
PyJFuzz is a JSON fuzzer written in pure python, it allows to generate and fuzz JSON object while maintaining<br>
the structure of original one. This project is still in <b>beta</b> so expect some errors, anyway it should do its work!<br>
PyJFuzz is released under <b><a href= "https://opensource.org/licenses/MIT">MIT</a></b> license, the author does
not take any legal responsibility for the program usage.<br>

Happy fuzzing<br><br>
<img src="https://pbs.twimg.com/profile_images/1072826149/mobile_security_lab_logo_medium.png" width="50" height="50">
<img src="https://i.vimeocdn.com/portrait/7297389_300x300" width="50" height="50">
<img src="http://2sxc.org/Portals/0/adam/Content/b0u5ab1H1E6dfLHhr4JLog/Image/500px-License_icon-mit.svg.png" width="50" height="50">


                """

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.name)
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        callbacks.addSuiteTab(self)
        self.initPanelConfig()
        self._jTabbedPane.addTab("Configuration", self._jPanel)
        self._jTabbedPane.addTab("About", self._jAboutPanel)
        return

    def getUiComponent(self):
        return self._jTabbedPane

    def getTabCaption(self):
        return "PyJFuzz"

    def initPanelConfig(self):
        self._jPanel.setBounds(0, 0, 1000, 1000)
        self._jPanel.setLayout(GridBagLayout())

        self._jAboutPanel.setBounds(0, 0, 1000, 1000)
        self._jAboutPanel.setLayout(GridBagLayout())

        self._jLabelParameters = JLabel("Parameters to Fuzz (comma separated): ")
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 0
        self._jPanel.add(self._jLabelParameters, self._jPanelConstraints)

        self._jTextFieldParameters = JTextField("", 15)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 1
        self._jPanelConstraints.gridy = 0
        self._jPanel.add(self._jTextFieldParameters, self._jPanelConstraints)

        self._jLabelTechniques = JLabel("Techniques (\"CHPTRSX\"):")
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 1
        self._jPanel.add(self._jLabelTechniques, self._jPanelConstraints)

        self._jTextFieldTechniques = JTextField("CHPTRSX", 3)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 1
        self._jPanelConstraints.gridy = 1
        self._jPanel.add(self._jTextFieldTechniques, self._jPanelConstraints)

        self._jLabelFuzzFactor = JLabel("Fuzz Factor (0-6):")
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 2
        self._jPanel.add(self._jLabelFuzzFactor, self._jPanelConstraints)

        self._jTextFieldFuzzFactor = JTextField("6", 3)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 1
        self._jPanelConstraints.gridy = 2
        self._jPanel.add(self._jTextFieldFuzzFactor, self._jPanelConstraints)

        self._jLabelAdditionalCmdLine = JLabel("Additional command line switch:")
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 3
        self._jPanel.add(self._jLabelAdditionalCmdLine, self._jPanelConstraints)

        self._jTextFieldAdditionalCmdLine = JTextField("", 3)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 1
        self._jPanelConstraints.gridy = 3
        self._jPanel.add(self._jTextFieldAdditionalCmdLine, self._jPanelConstraints)

        self._jButtonSetCommandLine = JButton('Set Configuration', actionPerformed=self.setCommandLine)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 5
        self._jPanelConstraints.gridwidth = 2
        self._jPanel.add(self._jButtonSetCommandLine, self._jPanelConstraints)

        self._jLabelAbout = JLabel("<html><body>%s</body></html>" % self.aboutText)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 0
        self._jAboutPanel.add(self._jLabelAbout, self._jPanelConstraints)

    def setCommandLine(self, event=None):
        params = self._jTextFieldParameters.getText()
        techniques = self._jTextFieldTechniques.getText()
        fuzz_factor = self._jTextFieldFuzzFactor.getText()
        additional = self._jTextFieldAdditionalCmdLine.getText()
        cmdline = "-p %s " % params if params != "" else ""
        cmdline += "-f %s " % fuzz_factor if fuzz_factor != "" else ""
        cmdline += "-t %s " % techniques if techniques != "" else ""
        cmdline += "%s" % additional if additional != "" else ""
        self.args = cmdline
        JOptionPane.showMessageDialog(None, "Command line configured!")

    def getGeneratorName(self):
        return "PyJFuzz JSON Fuzzer"

    def createNewInstance(self, attack):
        return JSONFuzzer(self, attack, self.args)


class JSONFuzzer(IIntruderPayloadGenerator):
    def __init__(self, extender, attack, args):
        self._args = args.split()
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self.pyjfuzz = "pyjfuzz.py"
        return

    def hasMorePayloads(self):
        return True

    def getNextPayload(self, current_payload):
        payload = "".join(chr(x) for x in current_payload)
        payload = self.fuzz(payload)
        return payload

    def reset(self):
        return

    def fuzz(self, original_payload):
        # Call PyJFuzz
        original_payload = urllib.unquote(original_payload)
        p1 = subprocess.Popen([self.pyjfuzz, '-j', original_payload] + self._args, stdout=subprocess.PIPE)
        output = p1.communicate()
        p1.stdout.close()
        del p1
        return output[0]

import subprocess
import urllib
from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from javax.swing import JOptionPane

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    args = ""

    def registerExtenderCallbacks(self, callbacks):
        self.args = JOptionPane.showInputDialog(None, "Insert PyJFuzz command line", "PyJFuzz", 1)
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        return

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
        output = p1.communicate()[0]
        p1.stdout.close()
        del p1
        return output

# Attempts to detect and blacklist devices that are sending honeypot signals

class AntiPoisonObject():
    def __init__(self, threshold, resourceName, wordlist, client, confidence):
        self.confidenceScore = confidence
        self.confidenceThreshold = threshold
        self.resouce = resourceName
        self.wordlist = wordlist
        self.client = client

    def CheckRandomness(self):
        with open(self.wordlist, 'r') as wordlist:
            inWordlist = False
            for line in wordlist:
                if line in self.resouce:
                    self.confidenceScore += 1
                    inWordlist = True
            
        wordlist.close()

        if(not inWordlist):
            self.confidenceScore = self.confidenceScore - 2
    
    def CheckConfidence(self):
        if(self.confidenceScore >= self.confidenceThreshold):
            return True
        else:
            return False
            
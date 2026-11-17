# Test-only FTPS server: user deploy/deploypass, TLS required on control and data.
import logging
from importlib.metadata import version

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import TLS_FTPHandler
from pyftpdlib.servers import FTPServer

# every command, reply and dropped connection goes to the container's log,
# which run.sh prints in full when an area fails (C88). pyftpdlib's own
# "[debug] call: ..." lines (each TLS handshake step) are left out: they
# buried the failing session.
class NoCallTrace(logging.Filter):
    def filter(self, record):
        return not record.getMessage().startswith("[debug]")


logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")
for h in logging.getLogger().handlers:
    h.addFilter(NoCallTrace())
try:
    logging.info("pyftpdlib %s, pyopenssl %s", version("pyftpdlib"), version("pyopenssl"))
except Exception as e:  # a version that cannot be read must not stop the server
    logging.info("versions unknown: %s", e)

auth = DummyAuthorizer()
auth.add_user("deploy", "deploypass", "/data", perm="elradfmwMT")
TLS_FTPHandler.certfile, TLS_FTPHandler.keyfile = "/cert.pem", "/key.pem"
TLS_FTPHandler.tls_control_required = TLS_FTPHandler.tls_data_required = True
TLS_FTPHandler.authorizer = auth
TLS_FTPHandler.passive_ports = range(30000, 30010)
FTPServer(("0.0.0.0", 21), TLS_FTPHandler).serve_forever()

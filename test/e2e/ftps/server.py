# Test-only FTPS server: user deploy/deploypass, TLS required on control and data.
import logging
from importlib.metadata import version

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import TLS_FTPHandler
from pyftpdlib.servers import FTPServer

# every command and every dropped connection goes to the container's log,
# which run.sh prints when an area fails
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")
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

# komando's OpenVPN container: OpenVPN runs here, inside its own network
# namespace, and dante offers a SOCKS5 port into the tunnel. The computer
# running komando never gets a tunnel device, route or DNS change.
FROM alpine:3.22
RUN apk add --no-cache openvpn dante-server
COPY entrypoint.sh up.sh sockd.conf /etc/komando/
RUN chmod 755 /etc/komando/entrypoint.sh /etc/komando/up.sh
EXPOSE 1080
ENTRYPOINT ["/etc/komando/entrypoint.sh"]

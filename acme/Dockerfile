# acme.sh with the gateway's start script and PAN-OS hook: gets and renews one Let's Encrypt wildcard
# certificate for the stack, and (DMZ) puts it on the firewall for inbound decryption. See docs/guide.md.
FROM neilpang/acme.sh:3.1.7

# The base image upgrades acme.sh from GitHub on every run unless told not to. Upgrades come with
# this image instead, so the version is the one tested.
ENV AUTO_UPGRADE=0

COPY run.sh /usr/local/bin/gateway-acme
COPY tm_panos.sh /acmebin/deploy/tm_panos.sh
RUN chmod 0755 /usr/local/bin/gateway-acme && chmod 0644 /acmebin/deploy/tm_panos.sh

ENTRYPOINT ["/usr/local/bin/gateway-acme"]

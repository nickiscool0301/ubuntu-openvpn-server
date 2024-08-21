#!/bin/bash

# Install necessary dependencies
install_dependencies() {
    apt-get update
    apt-get install -y openvpn openssl ca-certificates easy-rsa
}

# Detect the private IP
get_private_ip() {
    local private_ips
    private_ips=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')

    if [[ $(echo "$private_ips" | wc -l) -eq 1 ]]; then
        private_ip=$private_ips
    else
        select_private_ip "$private_ips"
    fi
}

# Select the private IPs
select_private_ip() {
    local private_ips="$1"
    local ip_count=$(echo "$private_ips" | wc -l)

    echo "Multiple private IP addresses detected:"
    echo "$private_ips" | nl -s ') '
    read -p "Select the IP address [1]: " ip_number
    until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$ip_count" ]]; do
        echo "$ip_number: invalid selection."
        read -p "Select the IP address [1]: " ip_number
    done
    [[ -z "$ip_number" ]] && ip_number=1
    private_ip=$(echo "$private_ips" | sed -n "${ip_number}p")
}

# Get public IP if the server is behind NAT
get_public_ip() {
    if echo "$private_ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
        echo "This server is behind NAT. Retrieving the public IPv4 address..."
        local public_ip_guess
        public_ip_guess=$(curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")
        read -p "Public IPv4 address / hostname [$public_ip_guess]: " public_ip
        [[ -z "$public_ip" ]] && public_ip="$public_ip_guess"
    else
        public_ip=$private_ip
    fi
}

# Main function to select the IP addresses
select_ip() {
    get_private_ip
    get_public_ip
}

# Set up easy-rsa and generate server keys
setup_easy_rsa() {
    local client=$1

    # Create the working directory for easy-rsa
    mkdir -p /etc/openvpn/server/easy-rsa/
    cd /etc/openvpn/server/easy-rsa/ || exit

    # Initialize PKI (Public Key Infrastructure)
    /usr/share/easy-rsa/easyrsa init-pki

    # Generate CA
    /usr/share/easy-rsa/easyrsa --batch build-ca nopass

    # Generate server cert
    /usr/share/easy-rsa/easyrsa --batch build-server-full server nopass

    /usr/share/easy-rsa/easyrsa --batch gen-crl

    # Generate client certificates for the passed client name
    /usr/share/easy-rsa/easyrsa --batch build-client-full "$client" nopass

    cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server/
    chown nobody:nogroup /etc/openvpn/server/crl.pem
    chmod o+x /etc/openvpn/server/

    # Generate tls-crypt
    openvpn --genkey secret /etc/openvpn/server/tc.key

    # Create dh pem
    echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' >/etc/openvpn/server/dh.pem
}

# Generate client configuration
generate_client_config() {
    local client=$1
    local public_ip=$2
    local port=$3
    local protocol=$4
    {
        cat /etc/openvpn/server/client-common.txt
        echo "<ca>"
        cat /etc/openvpn/server/easy-rsa/pki/ca.crt
        echo "</ca>"
        echo "<cert>"
        sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
        echo "</cert>"
        echo "<key>"
        cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
        echo "</key>"
        echo "<tls-crypt>"
        sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
        echo "</tls-crypt>"
    } >~/"$client".ovpn
}

# Generate server.conf
create_server_config() {
    local private_ip=$1
    local port=$2
    local protocol=$3

    echo "local $private_ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0
push \"redirect-gateway def1 bypass-dhcp\"
push \"dhcp-option DNS 8.8.8.8\"
push \"dhcp-option DNS 8.8.4.4\"
keepalive 10 120
user nobody
group nogroup
persist-key
persist-tun
crl-verify crl.pem
verb 3" >/etc/openvpn/server/server.conf
}

# Configure firewall
configure_firewall() {
    local private_ip=$1
    local port=$2
    local protocol=$3

    # Enable net.ipv4.ip_forward for the system
    echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn-forward.conf
    # Enable without reboot
    echo 1 >/proc/sys/net/ipv4/ip_forward

    iptables_path=$(command -v iptables)
    echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $private_ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $private_ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >/etc/systemd/system/openvpn-iptables.service
    echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >>/etc/systemd/system/openvpn-iptables.service
    systemctl enable --now openvpn-iptables.service
}

# Create template for client configuration file
create_client_template() {
    local public_ip=$1
    local port=$2
    local protocol=$3

    echo "client
dev tun
proto $protocol
remote $public_ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
ignore-unknown-option block-outside-dns
verb 3" >/etc/openvpn/server/client-common.txt
    if [[ "$protocol" = "udp" ]]; then
        echo "explicit-exit-notify" >>/etc/openvpn/server/server.conf
    fi
}

# Stop OpenVPN server
stop_server() {
    echo "Stopping OpenVPN service..."
    systemctl stop openvpn-server@server.service
    systemctl stop openvpn-iptables.service
}

# Start OpenVPN server
start_server() {
    echo "Starting OpenVPN service..."
    systemctl start openvpn-server@server.service
    systemctl start openvpn-iptables.service
}

# Delete OpenVPN server
delete_server() {
    echo "Deleting OpenVPN server configuration and associated files..."
    systemctl disable openvpn-server@server.service
    systemctl disable openvpn-iptables.service
    rm -f /etc/systemd/system/openvpn-iptables.service
    rm -rf /etc/openvpn/server
    echo "Done!"
}

# Add new client
add_new_client() {
    echo "Enter a name for new client:"
    read -p "Name: " input_client_name
    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<<"$input_client_name")
    cd /etc/openvpn/server/easy-rsa/ || exit
    /usr/share/easy-rsa/easyrsa --batch build-client-full "$client" nopass
    generate_client_config "$client" "$public_ip" "$port" "$protocol"
    echo "Client added. Configuration available at ~/$client.ovpn"
}

# Revoke client
revoke_client() {
    echo "Select the client to revoke:"
    tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
    read -p "Client: " client_number
    client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
    cd /etc/openvpn/server/easy-rsa/ || exit
    /usr/share/easy-rsa/easyrsa --batch revoke "$client"
    /usr/share/easy-rsa/easyrsa gen-crl
    cp pki/crl.pem /etc/openvpn/server/crl.pem
    chown nobody:nogroup /etc/openvpn/server/crl.pem
    echo "Client revoked!"
}

# Install OPENVPN
install_openvpn() {
    clear
    echo 'Ubuntu OpenVPN server'

    select_ip

    echo
    echo "Choose the protocol for OpenVPN?"
    echo "   1) UDP"
    echo "   2) TCP"
    read -p "Protocol [1]: " protocol
    [[ -z "$protocol" || "$protocol" == "1" ]] && protocol=udp || protocol=tcp

    echo
    echo "Choose the port for OpenVPN"
    read -p "Port [1194]: " port
    [[ -z "$port" ]] && port="1194"

    echo
    echo "Choose the name for default client:"
    read -p "Name [client]: " input_client_name
    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<<"$input_client_name")
    [[ -z "$client" ]] && client="client"

    install_dependencies
    setup_easy_rsa "$client"
    create_server_config "$private_ip" "$port" "$protocol"
    configure_firewall "$private_ip" "$port" "$protocol"
    create_client_template "$public_ip" "$port" "$protocol"

    # Start server
    systemctl enable --now openvpn-server@server.service

    # Generate client configuration
    generate_client_config "$client" "$public_ip" "$port" "$protocol"
    echo "Finished! The client configuration is available at ~/$client.ovpn"
}

# Main menu
main_menu() {
    clear
    echo "OpenVPN server is already installed."
    echo "  1) Add a new client"
    echo "  2) Revoke a client"
    echo "  3) Stop OpenVPN server"
    echo "  4) Start VPN server"
    echo "  5) Delete the OpenVPN server"
    echo "  6) Exit"
    read -p "Option: " option

    case "$option" in
    1) add_new_client ;;
    2) revoke_client ;;
    3) stop_server ;;
    4) start_server ;;
    5) delete_server ;;
    6) exit ;;
    *)
        echo "Invalid option"
        main_menu
        ;;
    esac
}

# Check if OpenVPN is installed and run the appropriate function
if [[ ! -e /etc/openvpn/server/server.conf ]]; then
    install_openvpn
else
    main_menu
fi

# Useful commands
# Check serverlog:
# sudo journalctl -u openvpn-server@server.service -f

# Start/stop/restart server:
# sudo systemctl status openvpn-server@server.service
# sudo systemctl start openvpn-server@server.service
# sudo systemctl stop openvpn-server@server.service
# sudo systemctl restart openvpn-server@server.service

#!/usr/bin/env bash

INTERFACE=Wi-Fi

sudo -v

while true; do sudo -n true; sleep 60; kill -0 "$$" || exit; done 2>/dev/null &

function disable_proxy() {
    sudo networksetup -setsocksfirewallproxystate $INTERFACE off
    echo "$(tput setaf 64)" 
    echo "SOCKS proxy disabled."
    echo "$(tput sgr0)" 
}
trap disable_proxy INT

sudo networksetup -setsocksfirewallproxy $INTERFACE 127.0.0.1 9050 off
sudo networksetup -setsocksfirewallproxystate $INTERFACE on

echo "$(tput setaf 64)" 
echo "SOCKS proxy 127.0.0.1:9050 enabled."
echo "$(tput setaf 136)" 
echo "Starting Tor..."
echo "$(tput sgr0)" 

tor

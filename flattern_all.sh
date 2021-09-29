#!/bin/bash

truffle-flattener contracts/0x_v3/asset-proxy/ERC20Proxy.sol > deployables/ERC20Proxy.sol
truffle-flattener contracts/0x_v3/exchange/Exchange.sol > deployables/Exchange.sol

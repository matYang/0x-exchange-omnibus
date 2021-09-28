## 0x-exchange-omnibus

This repo contains forked and reorganized contracts found in [0x-monorepo](https://github.com/0xProject/0x-monorepo) of 0x Project. The goal is to achieve a single and maintainable [Truffle](https://github.com/trufflesuite/truffle) project, that can be used for debugging existing 0x applications, such as a custom Coordinator contract, or deploy a completely new 0x Exchange infrastructure to an EVM-compatible sidechain.

### Getting started

```bash
$ git clone git@github.com:InjectiveLabs/0x-exchange-omnibus.git
$ cd 0x-exchange-omnibus
$ yarn
```

### Building contracts

```bash
$ yarn truffle build
```

### Starting a debugger

```bash
$ yarn truffle debug
```

### Initial migration

First, you'll need to get a 0x ganache snapshot. It already has 0x deployed, but useful part is that there are pre-allocated balances with ether.

```bash
$ yarn get-snapshot # downloads and unzips 0x v3 snapshot
$ yarn ganache # starts ganache-cli
```

Finally, run the initial migration for the entire codebase:

```bash
$ yarn truffle migrate --reset
```

Expect this log:

```
Addresses: {
    "erc20Proxy": "0x2eBb94Cc79D7D0F1195300aAf191d118F53292a8",
    "erc721Proxy": "0x5315e44798395d4a952530d131249fE00f554565",
    "erc1155Proxy": "0xC6B0D3C45A6b5092808196cB00dF5C357d55E1d5",
    "etherToken": "0xDFF540fE764855D3175DcfAe9d91AE8aEE5C6D6F",
    "exchange": "0x99356167eDba8FBdC36959E3F5D0C43d1BA9c6DB",
    "erc20BridgeProxy": "0xc7124963Ab16C33E5bF421D4c0090116622B3074",
    "forwarder": "0x0000000000000000000000000000000000000000",
    "multiAssetProxy": "0x3f16cA81691dAB9184cb4606C361D73c4FD2510a",
    "staticCallProxy": "0x7209185959D7227FB77274e1e88151D7C4c368D3"
}

   > Saving migration to chain.
   > Saving artifacts
   -------------------------------------
   > Total cost:           0.5240408 ETH


Summary
=======
> Total deployments:   19
> Final cost:          0.5274106 ETH
```

### Cleanup

Removes ganache state and information about deployed contracts.

```
$ rm -rf 0x_ganache_snapshot build
```

### License

Apache License 2.0

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
    "exchange": "0x99356167eDba8FBdC36959E3F5D0C43d1BA9c6DB"
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

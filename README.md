[![license](https://img.shields.io/github/license/mashape/apistatus.svg)]()

### Features

- Supports clusters of pools each running individual currencies
- Supports TPM signature in submit work
- Supports gas deposit query in other chain
- Supports Pay per Block scheme
- Ultra-low-latency, multi-threaded Stratum implementation using asynchronous I/O
- Adaptive share difficulty ("vardiff")
- PoW validation (hashing) using native code for maximum performance
- Session management for purging DDoS/flood initiated zombie workers
- Payment processing
- Banning System
- Detailed per-pool logging to console & filesystem
- Runs on Linux and Windows


#### Enhanced Ethereum Stratum Protocol

Implements the [Ethereum stratum mining protocol](https://github.com/nicehash/Specifications/blob/master/EthereumStratum_NiceHash_v1.0.0.txt) authored by NiceHash. This protocol is implemented by all major Ethereum miners.

- Claymore Miner must be configured to communicate using this protocol by supplying the <code>-esm 3</code> command line option
- Genoil's ethminer must be configured to communicate using this protocol by supplying the <code>-SP 2</code> command line option


### Runtime Requirements on Windows

- [.Net Core 2.2 Runtime](https://www.microsoft.com/net/download/core)
- [PostgreSQL Database](https://www.postgresql.org/)
- Coin Daemon (per pool)

### Runtime Requirements on Linux

- [.Net Core 2.2 SDK](https://www.microsoft.com/net/download/core)
- [PostgreSQL Database](https://www.postgresql.org/)
- Coin Daemon (per pool)
- Miningcore needs to be built from source on Linux. Refer to the section further down below for instructions.

### Running pre-built Release Binaries on Windows

- Download latest code
- Extract the Archive
- Setup the database as outlined below
- Create a configuration file <code>config.json</code> as described [here](https://github.com/coinfoundry/miningcore/wiki/Configuration)
- Run <code>dotnet poolcore.dll -c config.json</code>

### Basic PostgreSQL Database setup

Create the database:

```console
$ createuser miningcore
$ createdb miningcore
$ psql (enter the password for postgres)
```

Inside psql execute:

```sql
alter user miningcore with encrypted password 'some-secure-password';
grant all privileges on database miningcore to miningcore;
```

Import the database schema:

```console
$ psql -d miningcore -U miningcore -f createdb.sql
```


### Building from Source

#### Building on Ubuntu 16.04

```console
$ wget -q https://packages.microsoft.com/config/ubuntu/16.04/packages-microsoft-prod.deb
$ sudo dpkg -i packages-microsoft-prod.deb
$ sudo apt-get update -y
$ sudo apt-get install apt-transport-https -y
$ sudo apt-get update -y
$ sudo apt-get -y install dotnet-sdk-2.2 git cmake build-essential libssl-dev pkg-config libboost-all-dev libsodium-dev libzmq5
$ cd miningcore/src/Miningcore
$ dotnet publish -c Release --framework netcoreapp2.2  -o ../../build
```

#### Building on Windows

Download and install the [.Net Core 2.2 SDK](https://www.microsoft.com/net/download/core)

```dosbatch
> cd miningcore/src/Miningcore
> dotnet publish -c Release --framework netcoreapp2.2  -o ..\..\build
```

#### Building on Windows - Visual Studio

- Download and install the [.Net Core 2.2 SDK](https://www.microsoft.com/net/download/core)
- Install [Visual Studio 2017](https://www.visualstudio.com/vs/). Visual Studio Community Edition is fine.
- Open `Miningcore.sln` in VS 2017


#### After successful build

Create a configuration file <code>config.json</code> as described [here](https://github.com/coinfoundry/miningcore/wiki/Configuration)

```
cd ../../build
dotnet poolcore.dll -c config.json
```

## Running a production pool

A public production pool requires a web-frontend for your users to check their hashrate, earnings etc. Miningcore does not include such frontend but there are several community projects that can be used as starting point.

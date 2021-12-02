# Bitcoin Cigs - Smokin' Hot Bitcoin Signatures
Now with added shitcoin message verification!! (have not put any work into ensuring signing works, just verify_message. )
```
Dogecoin, Digibyte, Litecoin, Namecoin, Unobtanium

WIP: groestlcoin, zcash, syscoin
```
## Installation

```sh
~$ gem install bitcoin-cigs
```

## Command Line

Usage:
```sh
~$ bitcoin-cigs 
Usage: bitcoin-cigs command [arguments ...] [options ...]

Commands
     verify bitcoin-address signature [message-file]
     sign private-key [message-file]

Options
    -m, --message MESSAGE            Message can also be read from STDIN
    -S, --no-strip                   Do not strip leading and trailing whitespace from message (stripped by default)
```

Examples:
```sh
~$ # Sign with -m message parameter
~$ bitcoin-cigs sign 5JFZuDkLgbEXK4CUEiXyyz4fUqzAsQ5QUqufdJy8MoLA9S1RdNX -m 'this is a message'
HIBYi2g3yFimzD/YSD9j+PYwtsdCuHR2xwIQ6n0AN6RPUVDGttgOmlnsiwx90ZSjmaWrH1/HwrINJbaP7eMA6V4=
~$ 
~$ # Verify with message from STDIN
~$ echo 'this is a message' | bitcoin-cigs verify 11o51X3ciSjoLWFN3sbg3yzCM8RSuD2q9 HIBYi2g3yFimzD/YSD9j+PYwtsdCuHR2xwIQ6n0AN6RPUVDGttgOmlnsiwx90ZSjmaWrH1/HwrINJbaP7eMA6V4=
~$ 
~$ # Verify with message from file
~$ echo 'this is a message' > message.txt
~$ bitcoin-cigs verify 11o51X3ciSjoLWFN3sbg3yzCM8RSuD2q9 HIBYi2g3yFimzD/YSD9j+PYwtsdCuHR2xwIQ6n0AN6RPUVDGttgOmlnsiwx90ZSjmaWrH1/HwrINJbaP7eMA6V4= message.txt
~$ 
```

## Ruby API

Sign a message:
```ruby
require 'rubygems'
require 'bitcoin-cigs'

# Support for Wallet Import Format, Compressed WIF, Mini Format, Hex and Base64 wallets
wallet_key = "5JFZuDkLgbEXK4CUEiXyyz4fUqzAsQ5QUqufdJy8MoLA9S1RdNX"
message = "this is a message"

puts "The signature is: #{BitcoinCigs.sign_message!(wallet_key, message)}"
```

Verify a message signature:
```ruby
require 'rubygems'
require 'bitcoin-cigs'

address = "11o51X3ciSjoLWFN3sbg3yzCM8RSuD2q9"
signature = "HIBYi2g3yFimzD/YSD9j+PYwtsdCuHR2xwIQ6n0AN6RPUVDGttgOmlnsiwx90ZSjmaWrH1/HwrINJbaP7eMA6V4="
message = "this is a message"

if BitcoinCigs.verify_message(address, signature, message)
  puts "It looks like you own address #{address}!"
end
```

Verify a dogecoin signature:
```ruby
require 'rubygems'
require 'bitcoin-cigs'

address = "DMZyFd2BN5aUh1raM9neXPiBYqzSMLEtcr"
signature = "IDKhqgCatjxqO2jrfXvWZkb/MoRSguwX64lyVooqtZ6iIep1wD3S4S/+I5ROvI/xZtfRwz5T2+IqW9zGGXOXT70="
message = "this is a message"

if BitcoinCigs.verify_message(address, signature, message, :network=>:dogecoin)
  puts "It looks like you own address #{address}!"
end
```
# Adding more coins!?

### Want to add your own coin?

The code has been edited to make this pretty simple for any bitcoin clones, For other coins some tweaks maybe needed.

We also want any coins that have a solid user base added to this repo, so if you add coins to this codebase please don't hesitate to start a pull request.

What you need to add a bitcoin clone? PRIVATE_KEY_PREFIX, PUBLIC_KEY_PREFIX, STRMESSAGEMAGIC.

All you need to do is edit the lib\bitcoin_cigs.rb

Step 1. Private_key_prefix:
```

  PRIVATE_KEY_PREFIX = {
    :addyourcoinhere => 0x??,
    :unobtanium => 0xE0,
    :litecoin => 0xB0,
    :dogecoin => 0x9E,
    :mainnet => 0x80,
    :testnet => 0xEF
  }
```
Step 2. Public_Key_prefix:
``` 

  NETWORK_VERSION = {
    :addyourcoinhere => 0x??,
    :unobtanium => 0x82,
    :litecoin => 0x30,
    :dogecoin => 0x1e,
    :mainnet => 0x00,
    :testnet => 0x6F
  }
```
Step 3. StrMessageMagic:
```  
  PREFIX_MESSAGE_MAGIC = {
    :addyourcoinhere => "\x18YourCoin Signed Message:\n",
    :unobtanium => "\x1bUnobtanium Signed Message:\n",
    :litecoin => "\x19Litecoin Signed Message:\n",
    :dogecoin => "\x19Dogecoin Signed Message:\n",
    :mainnet => "\x18Bitcoin Signed Message:\n",
    :testnet => "\x18Bitcoin Signed Message:\n"
  }
  
```


# Credits

Thanks to jackjack for pointing me to Armory's implementation of message signatures:
https://github.com/jackjack-jj/jasvet

[Bitcoin Cigs](https://github.com/michaelgpearce/bitcoin-cigs) is maintained by [Michael Pearce](https://github.com/michaelgpearce).

# Donation

If you find this software useful and wish to donate, you can do so here:
```
1Cyd1wG4hCXK5aRCJQu3KnnhSrrfgs7NeM
```
If you find the edits to this software useful and wish to donate, you can do so here:
```
188gkL7ZYcsoGShuv7VTFtZaG5RUcxcwhQ
```

# Copyright

Copyright (c) 2013 Michael Pearce. See LICENSE.txt for further details.


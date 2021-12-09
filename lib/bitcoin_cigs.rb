%w(error crypto_helper compact_int base_58 curve_fp point public_key private_key signature ec_key keccak256 bech32 segwit_addr).each do |f|
  require File.join(File.dirname(__FILE__), 'bitcoin_cigs', f)
end

module BitcoinCigs
  PRIVATE_KEY_PREFIX = {
    #:zcash => 0x80,
    :qtum => 0x80,
    :pivx => 0x3F,
    :komodo => 0xBC,
    :viacoin => 0xC7,
    :vertcoin => 0x80,
    :monacoin => 0xAC,
    :syscoin => 0x80,
    :groestlcoin => 0x80,
    :namecoin => 0xB4,
    :digibyte => 0x80,
    :dash => 0xCC,
    :unobtanium => 0xE0,
    :litecoin => 0xB0,
    :dogecoin => 0x9E,
    :mainnet => 0x80,
    :testnet => 0xEF
  }
  NETWORK_VERSION = {
    #:zcash => 0x1cb8,
    :qtum => 0x58,
    :pivx => 0x1E,
    :komodo => 0x3C,
    :viacoin => 0x47,
    :vertcoin => 0x47,
    :monacoin => 0x32,
    :syscoin => 0x3F,
    :groestlcoin => 0x24,
    :namecoin => 0x34,
    :digibyte => 0x1E,
    :dash => 0x4C,
    :unobtanium => 0x82,
    :litecoin => 0x30,
    :dogecoin => 0x1e,
    :mainnet => 0x00,
    :testnet => 0x6F
  }
	
  PREFIX_HRP = {
    :viacoin => "via",
    :vertcoin => "vtc",
    :monacoin => "mona",
    :syscoin => "sys",
    :digibyte => "dgb",
    :litecoin => "ltc",
    :groestlcoin => "grs",
    :mainnet => "bc"
  }
  
  PREFIX_MESSAGE_MAGIC = {
    #:zcash => "\x19Zcash Signed Message:\n",
    :qtum => "x15Qtum Signed Message:\n",
    :pivx => "\x18DarkNet Signed Message:\n",
    :komodo => "\x17Komodo Signed Message:\n",
    :viacoin => "\x18Viacoin Signed Message:\n",
    :vertcoin => "\x19Vertcoin Signed Message:\n",
    :monacoin => "\x19Monacoin Signed Message:\n",
    :syscoin => "\x18Syscoin Signed Message:\n",
    :groestlcoin => "\x1cGroestlCoin Signed Message:\n",
    :namecoin => "\x19Namecoin Signed Message:\n",
    :digibyte => "\x19DigiByte Signed Message:\n",
    :dash => "\x19DarkCoin Signed Message:\n",
    :unobtanium => "\x1bUnobtanium Signed Message:\n",
    :litecoin => "\x19Litecoin Signed Message:\n",
    :dogecoin => "\x19Dogecoin Signed Message:\n",
    :mainnet => "\x18Bitcoin Signed Message:\n",
    :testnet => "\x18Bitcoin Signed Message:\n"
  }
  
  P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  R = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  B = 0x0000000000000000000000000000000000000000000000000000000000000007
  A = 0x0000000000000000000000000000000000000000000000000000000000000000
  Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

  CURVE_SECP256K1 = ::BitcoinCigs::CurveFp.new(P, A, B)
  GENERATOR_SECP256K1 = ::BitcoinCigs::Point.new(CURVE_SECP256K1, Gx, Gy, R)
  
  class << self
    include ::BitcoinCigs::CryptoHelper
    require 'eth'
	  
    def verify_address(address, options = {:network => :mainnet})
      #more checks probably needed, but is some basic validating
      if ['ethereum', 'qtum', 'solana', 'neo', 'avalanche', 'tron'].include? options[:network].to_s.downcase
        return isChecksumAddress(toChecksumAddress(address))
      else 
        #trial code - for segwit check
        address.length > 34 && address.length < 45 ? addresstype = 1 : addresstype = 0
        if addresstype == 0
          decoded_address = decode58(address)
          return (str_to_num(decoded_address) >> (8 * 24) == NETWORK_VERSION[options[:network]]) && address.length < 35 && validateInputAddresses(address)
        else
          hrp, data, spec = Bech32.decode(address)
          hrpmatches = PREFIX_HRP[options[:network]] == hrp
          return hrpmatches && validateInputAddresses(address) && address.length < 45
        end
      end
    end
	
     def isAddress(address) #might be obsolete now.
       if (!/^(0x)?[0-9a-f]{40}$/i.match(address))
         return false
       elsif (/^(0x)?[0-9a-f]{40}$/.match(address) || /^(0x)?[0-9A-F]{40}$/.match(address))
         return true
       end
    end
 
    def isChecksumAddress (address, chainId = nil)
      stripAddress = stripHexPrefix(address)
      prefix = chainId != nil ? chainId.to_s + '0x' : ''
      keccakHash = Digest::Keccak256.new.hexdigest(prefix + stripAddress)

      for i in 0..stripAddress.length-1
        output = keccakHash[i].to_i >= 8 ? stripAddress[i].upcase : stripAddress[i]
        if (stripHexPrefix(address)[i].to_s != output.to_s)
          return false
        end
      end
        return true
      end
	
    def toChecksumAddress (address, chainId = nil)
      if(!/^(0x)?[0-9a-f]{40}$/i.match(address))
        raise ::BitcoinCigs::Error.new("not a valid Ethereum address")
    end

      stripAddress = stripHexPrefix(address).downcase
      prefix = chainId != nil ? chainId.to_s + '0x' : ''
      keccakHash = Digest::Keccak256.new.hexdigest(prefix + stripAddress)
      checksumAddress = '0x'
      
      for i in 0..stripAddress.length-1
        checksumAddress += keccakHash[i].to_i(16) >= 8 ? stripAddress[i].upcase : stripAddress[i]
      end
	  return checksumAddress
    end
	
    def stripHexPrefix (address)
      return address[0..1] == '0x' ? address[2..41] : address
    end

    def verify_message(address, signature, message, options = {:network => :mainnet})
      begin
        verify_message!(address, signature, message, options)
        true
      rescue ::BitcoinCigs::Error
        false
      end
    end

    def validateInputAddresses(address)
      return address.match?(/[0-9a-zA-Z]{34}/i)
    end
	   
    def verify_message!(address, signature, message, options = {:network => :mainnet})
      
      #verify Ethereum?
      if options[:network].downcase.to_s == "ethereum"
        address = Eth::Utils.public_key_to_hex(Eth::Key.personal_recover(message, signature))
      else
	#All other coins
        #Segwit implementation (dodgy) - Part 1
        #check if address length is greater than 30
        address.length > 34 && address.length < 45 ? addresstype = 1 : addresstype = 0
      
        if addresstype == 0
          decoded_address = decode58(address)
          raise ::BitcoinCigs::Error.new("Incorrect address or message for signature.") if decoded_address.nil?
        end

        # network_version = str_to_num(decoded_address) >> (8 * 24)

        addr = get_signature_address!(signature, message, options, addresstype)
       
        #Segwit Implemntation - End of Part 1
      end
        raise ::BitcoinCigs::Error.new("Incorrect address or message for signature.") if address != addr
        nil
    end

    def get_signature_address(signature, message, options = {:network => :mainnet})
      begin
        get_signature_address!(signature, message, options)
      rescue ::BitcoinCigs::Error
        false
      end 
    end

    # Segwit Implementation (dodgy) - Part 2
    def get_signature_address!(signature, message, options = {:network => :mainnet}, addresstype = 0)

      message = calculate_hash(format_message_to_sign(message, options), options)

      curve = CURVE_SECP256K1
      g = GENERATOR_SECP256K1
      a, b, p = curve.a, curve.b, curve.p
      
      order = g.order
      
      sig = decode64(signature)
      raise ::BitcoinCigs::Error.new("Bad signature length") if sig.size != 65
      raise ::BitcoinCigs::Error.new("Bad characters in signature") if signature != encode64(sig)
      
      hb = sig[0].ord
      r, s = [sig[1...33], sig[33...65]].collect { |s| str_to_num(s) }
      
      
      raise ::BitcoinCigs::Error.new("Bad signature first byte") if hb < 27 || hb >= 35
      
      compressed = false
      if hb >= 31
        compressed = true
        hb -= 4
      end
      
      recid = hb - 27
      x = (r + (recid / 2) * order) % p
      y2 = ((x ** 3 % p) + a * x + b) % p
      yomy = sqrt_mod(y2, p)
      if (yomy - recid) % 2 == 0
        y = yomy
      else
        y = p - yomy
      end
      
      r_point = ::BitcoinCigs::Point.new(curve, x, y, order)
      e = str_to_num(message)
      minus_e = -e % order
      
      inv_r = inverse_mod(r, order)
      q = (r_point * s + g * minus_e) * inv_r
      
    
      public_key = ::BitcoinCigs::PublicKey.new(g, q, compressed)
      # Segwit Implementation (dodgy) - Part 3
      addresstype == 0 ? public_key_to_bc_address(public_key.ser(), options) : public_key_to_segwit_address(public_key.ser(), options)
    end
    
    def sign_message(wallet_key, message, options = {:network => :mainnet})
      begin
        sign_message!(wallet_key, message, options)
      rescue ::BitcoinCigs::Error
        nil
      end
    end
    
    def sign_message!(wallet_key, message, options = {:network => :mainnet})
      private_key = convert_wallet_format_to_bytes!(wallet_key, options[:network].to_s)
      
      options[:network].to_s == "groestlcoin" ? msg_hash = sha256(format_message_to_sign(message, options)) : msg_hash = sha256(sha256(format_message_to_sign(message, options)))
      ec_key = ::BitcoinCigs::EcKey.new(str_to_num(private_key))
      private_key = ec_key.private_key
      public_key = ec_key.public_key
      addr = public_key_to_bc_address(get_pub_key(ec_key, ec_key.public_key.compressed), options)
      
      sig = private_key.sign(msg_hash, random_k)
      raise ::BitcoinCigs::Error.new("Unable to sign message") unless public_key.verify(msg_hash, sig)
      
      4.times do |i|
        hb = 27 + i
        
        sign = "#{hb.chr}#{sig.ser}"
        sign_64 = encode64(sign)
        
        begin
          verify_message!(addr, sign_64, message, options)
          return sign_64
        rescue ::BitcoinCigs::Error
          next
        end
      end
      
      raise ::BitcoinCigs::Error, "Unable to construct recoverable key"
    end
    
    def convert_wallet_format_to_bytes!(input, network)
      bytes = if is_wallet_import_format?(input, network)
        decode_wallet_import_format(input, network)
      elsif is_compressed_wallet_import_format?(input, network)
        decode_compressed_wallet_import_format(input, network)
      elsif is_mini_format?(input)
        sha256(input)
      elsif is_hex_format?(input)
        decode_hex(input)
      elsif is_base_64_format?(input)
        decode64(input)
      else
        raise ::BitcoinCigs::Error.new("Unknown Wallet Format")
      end
      
      bytes
    end
    
    private
    
    def format_message_to_sign(message, options = {:network=>:mainnet})
	"#{PREFIX_MESSAGE_MAGIC[options[:network]]}#{::BitcoinCigs::CompactInt.new(message.size).encode}#{message}"
    end
    
    def random_k
      k = 0
      8.times do |i|
        k |= (rand * 0xffffffff).to_i << (32 * i)
      end
      
      k
    end
        
    def get_pub_key(public_key, compressed)
      i2o_ec_public_key(public_key, compressed)
    end
    
    def i2o_ec_public_key(public_key, compressed)
      key = if compressed
        "#{public_key.public_key.point.y & 1 > 0 ? '03' : '02'}%064x" % public_key.public_key.point.x
      else
        "04%064x%064x" % [public_key.public_key.point.x, public_key.public_key.point.y]
      end

      decode_hex(key)
    end

    def decode_wallet_import_format(input, network)
      bytes = decode58(input)#[1..-1]
      hash = bytes[0..32]
      
      network == "groestlcoin" ? checksum = sha256(hash) : checksum = sha256(sha256(hash))
      raise ::BitcoinCigs::Error.new("Wallet checksum invalid") if bytes[33..37] != checksum[0..3]

      version, hash = hash[0], hash[1..-1]
      raise ::BitcoinCigs::Error.new("Wallet Version #{version} not supported") if version.ord != PRIVATE_KEY_PREFIX[network]
      
      hash
    end
    
    def decode_compressed_wallet_import_format(input, network)
      bytes = decode58(input)
      hash = bytes[0...34]
      
      network == "groestlcoin" ? checksum = sha256(hash) : checksum = sha256(sha256(hash))
      raise ::BitcoinCigs::Error.new("Wallet checksum invalid") if bytes[34..37] != checksum[0..3]

      version, hash = hash[0], hash[1..32]
      raise ::BitcoinCigs::Error.new("Wallet Version #{version} not supported") if version.ord != PRIVATE_KEY_PREFIX[network]
      
      hash
    end
    
    # 64 characters [0-9A-F]
    def is_hex_format?(key)
      /^[A-Fa-f0-9]{64}$/ =~ key
    end
    
    # 51 characters base58 starting with 5
    def is_wallet_import_format?(key, network)
      /^#{network == :mainnet ? '5' : '9'}[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{50}$/ =~ key
    end
    
    # 52 characters base58 starting with L or K
    def is_compressed_wallet_import_format?(key, network)
      /^[network == :mainnet ? 'LK' : 'c'][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{51}$/ =~ key
    end
    
    # 44 characters
    def is_base_64_format?(key)
      /^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=+\/]{44}$/ =~ key
    end
    
    # 22, 26 or 30 characters, always starts with an 'S'
    def is_mini_format?(key)
      validChars22 = /^S[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{21}$/ =~ key
      validChars26 = /^S[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{25}$/ =~ key
      validChars30 = /^S[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{29}$/ =~ key
      
      bytes = sha256("#{key}?")
    
      (bytes[0].ord === 0x00 || bytes[0].ord === 0x01) && (validChars22 || validChars26 || validChars30)
    end
    
    def debug_bytes(s)
      s.chars.collect(&:ord).join(', ')
    end
    
    def calculate_hash(d, options = {:network=>:mainnet})
      options[:network].to_s == "groestlcoin" ? sha256(d) : sha256(sha256(d)) #replace sha256(d) with: groestl512(groestl512(d))[0..33]
    end

    # Segwit Implementation (dodgy) - Part 4
    def public_key_to_segwit_address(public_key, options = {:network => :mainnet})
      h160 = hash_160(public_key)
      segwit_addr = SegwitAddr.new
      segwit_addr.hrp = PREFIX_HRP[options[:network]].to_s
      vh160 = NETWORK_VERSION[options[:network]].chr + h160
      segwit_addr.scriptpubkey = "0014" + vh160.unpack("H*").to_s[4..43]
      segwit_addr.addr
    end

    def public_key_to_bc_address(public_key, options = {:network=>:mainnet})
      h160 = hash_160(public_key)
      hash_160_to_bc_address(h160, options)
    end
    
    def hash_160_to_bc_address(h160, options = {:network=>:mainnet})
      vh160 = NETWORK_VERSION[options[:network]].chr + h160
      h = calculate_hash(vh160, options)
      addr = vh160 + h[0...4]
	    
      encode58(addr)
    end
    
    def hash_160(public_key)
      ripemd160(sha256(public_key))
    end
    
  end
end

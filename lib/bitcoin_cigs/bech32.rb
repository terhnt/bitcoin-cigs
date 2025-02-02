# Copyright (c) 2017 Shigeyuki Azuchi
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

module Bech32

  module Encoding
    BECH32 = 1
    BECH32M = 2
  end

  SEPARATOR = '1'

  CHARSET = %w(q p z r y 9 x 8 g f 2 t v d w 0 s 3 j n 5 4 k h c e 6 m u a 7 l)

  BECH32M_CONST = 0x2bc830a3

  module_function

  # Encode Bech32 string
  def encode(hrp, data, spec)
    checksummed = data + create_checksum(hrp, data, spec)
    hrp + SEPARATOR + checksummed.map{|i|CHARSET[i]}.join
  end

  # Decode a Bech32 string and determine hrp and data
  def decode(bech)
    # check uppercase/lowercase
    return nil if bech.bytes.index{|x| x < 33 || x > 126}
    return nil if (bech.downcase != bech && bech.upcase != bech)
    bech = bech.downcase
    # check data length
    pos = bech.rindex(SEPARATOR)
    return nil if pos.nil? || pos < 1 || pos + 7 > bech.length || bech.length > 90
    # check valid charset
    bech[pos+1..-1].each_char{|c|return nil unless CHARSET.include?(c)}
    # split hrp and data
    hrp = bech[0..pos-1]
    data = bech[pos+1..-1].each_char.map{|c|CHARSET.index(c)}
    # check checksum
    spec = verify_checksum(hrp, data)
    spec ? [hrp, data[0..-7], spec] : nil
  end

  # Compute the checksum values given hrp and data.
  def create_checksum(hrp, data, spec)
    values = expand_hrp(hrp) + data
    const = (spec == Bech32::Encoding::BECH32M ? Bech32::BECH32M_CONST : 1)
    polymod = polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    (0..5).map{|i|(polymod >> 5 * (5 - i)) & 31}
  end

  # Verify a checksum given Bech32 string
  def verify_checksum(hrp, data)
    const = polymod(expand_hrp(hrp) + data)
    case const
    when 1
      Encoding::BECH32
    when BECH32M_CONST
      Encoding::BECH32M
    end
  end

  # Expand the hrp into values for checksum computation.
  def expand_hrp(hrp)
    hrp.each_char.map{|c|c.ord >> 5} + [0] + hrp.each_char.map{|c|c.ord & 31}
  end

  # Compute Bech32 checksum
  def polymod(values)
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    values.each do |v|
      top = chk >> 25
      chk = (chk & 0x1ffffff) << 5 ^ v
      (0..4).each{|i|chk ^= ((top >> i) & 1) == 0 ? 0 : generator[i]}
    end
    chk
  end

  private_class_method :polymod, :expand_hrp

end
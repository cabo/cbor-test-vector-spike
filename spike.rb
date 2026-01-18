require 'pp'
require 'cbor-pure'
require 'cbor-deterministic'
require 'cbor-canonical'
require 'cbor-packed'           # for cbor_visit

## -- manipulating hex strings

class String
  def hexi
    bytes.map{|x| "%02x" % x}.join
  end
  def hexs
    bytes.map{|x| "%02x" % x}.join(" ")
  end
  def xeh
    gsub(/\s/, "").chars.each_slice(2).map{ |x| Integer(x.join, 16).chr("BINARY") }.join
  end
  def vlb
    n = 0
    each_byte { |b| n <<= 8; n += b}
    n
  end
end
class Integer
  def to_bytes
    digits(256).reverse!.pack("C*")
  end
  def to_bytes0
    digits(256).reverse!.drop_while{|dig| dig == 0}.pack("C*")
  end
end

## -- DLO check

def dlo?(o)
  o.cbor_visit do |item|
    case item
    when String, Array, Hash
      return false if item.cbor_stream?
    end
    true # continue visiting
  end
  true # didn't find any streaming items
end

fail unless dlo?([1, 2, 3, {a: 1, b: 2}])
fail unless dlo?(CBOR.decode("80".xeh))
fail if dlo?(CBOR.decode("9F80FF".xeh))
fail unless dlo?(CBOR.decode("A18001".xeh))
fail if dlo?(CBOR.decode("A1BF8001FF60".xeh))
fail unless dlo?(CBOR.decode("60".xeh))
fail if dlo?(CBOR.decode("817F6130623232FF".xeh))

=begin

## -- random arguments

def nrand(n, max, mixin = [])
  ((0...n).map {
     (2 ** Random.rand(Float(max))).floor - 1
   } + mixin).sort.uniq
end

# pp nrand(20, 64)
# pp nrand(10, 5, [0, 1, 23, 24, 25])

def boundary(first, *more)
  [0, 1, first - 1, first, first + 1] + more.flat_map {
    v = 256 ** _1
    [v-1, v, v+1]
  }
end

## -- Integers

arguments = nrand(20, 64, boundary(24, 1, 2, 4, 8))

unsigned = Hash[arguments.map {|a|
                  [a.to_cbor.hexs, {value: a, ic: Set[]}]
                }]

negative = Hash[arguments.map {|a|
                  val = ~a
                  [val.to_cbor.hexs, {value: val, ic: Set[]}]
                }]

def check_int(hexenc, attr)
  cb = hexenc.xeh
  cd = CBOR.decode(cb)
  val = attr[:value]
  fail [hexenc, attr].inspect if cd != attr[:value]
  attr[:ic] << :DLO if dlo?(val)
  attr[:ic] << :PS if val.to_cbor == cb
  attr[:ic] << :CDE if val.to_deterministic_cbor == cb
  attr[:ic] << :LDE if val.to_canonical_cbor == cb
end

def widen_int(hexenc, attr)
#pp [hexenc, attr]
  cb = hexenc.xeh
  ib = cb.getbyte(0)
  arg = "%02x" % (ib & 0x1f) if (arg = hexenc[2..]) == "" # immediate value XXX negative
  attr_out = attr.merge({ic: Set[]})
  mt = ib >> 5
  if mt < 2
    initial_nibble = "13"[mt]
    case ib & 0x1f
    in 0..0x17
      [initial_nibble + "8" + arg, attr_out]
    in 0x18
      [initial_nibble + "900" + arg, attr_out]
    in 0x19
      [initial_nibble + "a0000" + arg, attr_out]
    in 0x1a
      [initial_nibble + "b00000000" + arg, attr_out]
    in 0x1b
      val = attr[:value]
      if mt == 1
        val = ~val
      end
      [(0xc2+mt).to_s(16) + (val.to_bytes0).to_cbor.hexi, attr_out]
    end
  elsif mt == 6
    content = CBOR.decode(arg.xeh)
    if content[0..3] != "\x00\x00\x00\x00".b
      content = "\x00".b + content
      [hexenc[0..1] + content.to_cbor.hexi, attr_out]
    end
  else fail [:WI, hexenc, attr].inspect
  end
end

[unsigned, negative].each do |cases|
#  pp [:CASES, cases]
  loop do
    add = Hash[
    cases.map do |c|
      check_int(*c)
      # add.concat
      w = widen_int(*c)
      if w != nil
        check_int(*w)
        w
      end
    end.compact].reject {|k, _| cases.key?(k)}
#    pp [:ADD, add]
    break if add == {}
    cases.merge! add
  end
end

pp unsigned

pp negative

=end

## -- Floats


def check_int(hexenc, attr)
  cb = hexenc.xeh
  cd = CBOR.decode(cb)
  val = attr[:value]
  fail [hexenc, attr].inspect if cd != attr[:value] && cd == cd # not a NaN...
  if attr[:ic] != Set[]
    fail [hexenc, attr].inspect
  end
  attr[:ic] << :DLO if dlo?(val)
  attr[:ic] << :PS if val.to_cbor == cb # XXX
  attr[:ic] << :CDE if val.to_deterministic_cbor == cb
  attr[:ic] << :LDE if val.to_canonical_cbor == cb
end

def analyze_f64(f64)
  [f64 >> 63, (f64 >> 52) & ((1<<11)-1), f64 & ((1<<52)-1) ]
end
def construct_f64(sign, exp, mant)
  sign << 63 | exp << 52 | mant
end

binary64 = Hash[(0...100).map {
                  ran1 = Random.rand(2**64)
                  sign, exp, mant = analyze_f64(ran1)
                  ran0 = ((exp & 1) * 2) - 1 # exponent sign
                  ran1 = (exp & 0xF0) != 0       # 6 % non-finites
                  exp = ran1 ? Integer(2**Random.rand(0.0...10.0)*ran0 + 1023) : 2047
                  ran2 = construct_f64(sign, exp, mant)
                  ["fb" + (bin = [ran2].pack("Q>")).hexi,
                   {value: bin.unpack("G").first, ic: Set[]}] 
                  }]

[0.0, -0.0, Float::INFINITY, -Float::INFINITY, Float::NAN].each do |val|
  binary64[val.to_cbor.hexi] = {value: val, ic: Set[]} # needed?
  # Add non-PS 64-bit forms
  bits64 = [val].pack("G")
  binary64["fb" + bits64.hexi] = {value: val, ic: Set[]}
  bits64.setbyte(2, 1)            # poison for f16; does not work for 0.0
  mybits = bits64.unpack("G").first.to_cbor
  mybits.setbyte(3, 0)
  case mybits.getbyte(0)
  in 0xfa
    binary64[mybits.hexi] = {value: val, ic: Set[]}
  in 0xfb                       # 0.0/-0.0
    binary64["fa%02x000000" % mybits.getbyte(1)] = {value: val, ic: Set[]}
  end
end

floats = Hash[[23, 10].flat_map do |expobits|
  binary64.flat_map {|hexenc, attr|
         enc = [CBOR.decode(hexenc.xeh)].pack("G").unpack("Q>").first
         enc &= -(2**(52-expobits))
         enc = "\xFB".b + [enc].pack("Q>")
         val = CBOR.decode(enc)
         enc_short = val.to_cbor
         [[enc_short.hexi, {value: val, ic: Set[]}], [enc.hexi, {value: val, ic: Set[]}]]
       }
end]

floats.merge!(binary64)
floats.each { |k, v| check_int(k, v)}

pp floats.sort

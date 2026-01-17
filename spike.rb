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

unsigned = arguments.map {|a|
  {cbor_hex: a.to_cbor.hexs, value: a, ic: Set[]}
}

negative = arguments.map {|a|
  val = ~a
  {cbor_hex: val.to_cbor.hexs, value: val, ic: []}
}

def check_int(c)
  cb = c[:cbor_hex].xeh
  cd = CBOR.decode(cb)
  fail c.inspect if cd != c[:value]
  c[:ic] << :DLO if c[:value].to_cbor == cb # default is definite length
  c[:ic] << :PS if c[:value].to_cbor == cb
  c[:ic] << :CDE if c[:value].to_deterministic_cbor == cb
  c[:ic] << :LDE if c[:value].to_canonical_cbor == cb
end

def widen_int(c)
pp c
  cb = c[:cbor_hex].xeh
  ib = cb.getbyte(0)
  arg = c[:cbor_hex][2..]
  mt = ib >> 5
  if mt < 2
    case ib & 0x1f
    in 0..0x17
      [{cbor_hex: "18" + arg, value: c[:value], ic: []}]
    in 0x18
      [{cbor_hex: "1900" + arg, value: c[:value], ic: []}]
    in 0x19
      [{cbor_hex: "1a000000" + arg, value: c[:value], ic: []}]
    in 0x1a
      [{cbor_hex: "1b0000000000000000000000" + arg, value: c[:value], ic: []}]
    in 0x1b
      []                        # do the C2/C3
    end
  else
    []
  end
end

loop do
  add = []
  unsigned.each do |c|
    check_int(c)
    add.concat widen_int(c)
  end
  break if add == []
end

    negative.each do |c|
      check_int(c)
    end


    pp unsigned

    pp negative

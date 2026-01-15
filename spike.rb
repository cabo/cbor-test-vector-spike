require 'pp'
require 'cbor-pure'
require 'cbor-deterministic'
require 'cbor-canonical'

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

arguments = nrand(20, 64, boundary(24, 1, 2, 4, 8))

unsigned = arguments.map {|a|
  {cbor_hex: a.to_cbor.hexs, value: a, ic: []}
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

unsigned.each do |c|
  check_int(c)
end

negative.each do |c|
  check_int(c)
end


pp unsigned

pp negative

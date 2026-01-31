require 'pp'
require 'cbor-pretty' # includes require 'cbor-pure'
require 'cbor-deterministic'
require 'cbor-canonical'
require 'cbor-packed'           # for cbor_visit
require 'csv'
require 'edn-abnf'
require 'iana-registry'

## -- manipulating hex strings

class String
  def hexi
    bytes.map{|x| "%02x" % x}.join
  end
  def xeh
    gsub(/\s/, "").chars.each_slice(2).map{ |x| Integer(x.join, 16).chr("BINARY") }.join
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

def minimizebytes(s)            # XXX needs TLC
  sz = 1
  s.each_line.map {|ln| ln.sub(/\s*#.*/, '')}.join.scan(/([0-9a-fA-F][0-9a-fA-F])|(\s+)/).map {|b, c|
    b or if c[0] == "\n"
           osz = sz
           sz = c.size
           ")-("[(sz <=> osz) + 1] * ((osz-sz)/3).abs +
             ((sz > 1 && osz >= sz) ? "-" : "")
         else
           "."
         end
         }.join
end

def prettier(s)
  minimizebytes(CBOR::pretty(s.xeh))
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


module CBOR
  module DLO

    module Object_DLO_CBOR
      def cbor_prepare_dlo
        self
      end
      def to_dlo_cbor
        cbor_prepare_dlo.to_cbor
      end
    end
    Object.send(:include, Object_DLO_CBOR)

    module Array_DLO_CBOR
      def cbor_prepare_dlo
        map(&:cbor_prepare_dlo)
      end
    end
    Array.send(:include, Array_DLO_CBOR)

    module Hash_DLO_CBOR
      def cbor_prepare_dlo
        Hash[map {|k, v|
               [k.cbor_prepare_dlo, v.cbor_prepare_dlo]}]
      end
    end
    Hash.send(:include, Hash_DLO_CBOR)

    module String_DLO_CBOR
      def cbor_prepare_dlo
        dup.cbor_stream!(nil)
      end
    end
    String.send(:include, String_DLO_CBOR)

    module Tagged_DLO_CBOR
      def cbor_prepare_dlo
        CBOR::Tagged.new(tag, value.cbor_prepare_dlo)
      end
    end
    CBOR::Tagged.send(:include, Tagged_DLO_CBOR)
  end
end

[1, 2, 3, {a: 1, b: 2},
 CBOR.decode("80".xeh),
 CBOR.decode("9F80FF".xeh),
 CBOR.decode("A18001".xeh),
 CBOR.decode("A1BF8001FF60".xeh),
 CBOR.decode("60".xeh),
 CBOR.decode("817F6130623232FF".xeh),
].each do |item|
  pd = item.cbor_prepare_dlo
  fail unless item == pd
  fail unless dlo?(pd)
end


def set_flags(hexenc, attr, description = false)
  cb = hexenc.xeh
  cd = CBOR.decode(cb)
  cdd = cd.to_deterministic_cbor
  val = attr[:value]
  vald = val.to_deterministic_cbor
  if cdd != vald
    fail [hexenc, cd, attr, cdd.hexi, vald.hexi].inspect
  end
  attr[:ic] = Set[]
  attr[:ic] << :DLO if dlo?(cd)
  attr[:ic] << :PS if cd.to_cbor == cb
  attr[:ic] << :CDE if vald == cb
  attr[:ic] << :LDE if val.to_canonical_cbor == cb
  attr[:description] = description if description
end

# indexed by initial byte
ARG_LENGTH = ([0]*24 + [1, 2, 4, 8] + [false]*3 + [true]) * 8

## -- CLI arg processing


Encoding.default_external = Encoding::UTF_8
require 'optparse'
require 'ostruct'

$error = 0

output_formats = [:csv, :"test-vector"]

$options = OpenStruct.new
# $options.seed = 4711 # could set a default seed this way
$options.target = output_formats[0]

begin
  op = OptionParser.new do |opts|
    opts.banner = "Usage: $0 [options]"

    opts.on("-v", "--[no-]verbose", "Run verbosely") do |v|
      $options.verbose = v
    end
    opts.on("-d", "--[no-]more-diagnostic", "Use more detailed EDN") do |v|
      $options.more_diag = v
    end
    opts.on("-p", "--[no-]more-pretty", "Use more detailed hex format") do |v|
      $options.more_pretty = v
    end
    opts.on("-sSEED", "--seed=SEED", Integer,
            "Random number generator seed") do |v|
      $options.seed = v
    end
    opts.on("-tFMT", "--to=FMT", output_formats,
            "Target format (#{output_formats.join("/")}, default: csv)") do |v|
      $options.target = v.to_sym
    end
  end
  op.parse!
rescue Exception => e
  warn e
  warn op
  exit 1
end

if $options.seed
  Random.srand($options.seed)
end
seed = Random.seed

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
                  [a.to_cbor.hexi, {value: a, ic: Set[]}]
                }]

negative = Hash[arguments.map {|a|
                  val = ~a
                  [val.to_cbor.hexi, {value: val, ic: Set[]}]
                }]

def widen_arg(hexenc, pos = 0)
  h = hexenc.dup
  hpos = 2*pos
  cb = h.xeh
  ib = cb.getbyte(pos)
  arg_length = ARG_LENGTH[ib]
  return nil if arg_length == true # XXX should widen inside
  arg = if arg_length == 0
          "%02x" % (ib & 0x1f)
        else
          hexenc[hpos + 2, arg_length * 2]
        end
  mt = ib >> 5
  initial_nibble = "%x" % (2*mt+1)
  case arg_length
  in 0
    h[hpos, 2] = initial_nibble + "8" + arg
  in 1
    h[hpos, 4] = initial_nibble + "900" + arg
  in 2
    h[hpos, 6] = initial_nibble + "a0000" + arg
  in 4
    h[hpos, 10] = initial_nibble + "b00000000" + arg
  in 8
    rep = yield cb, pos, ib, mt, h
    return nil unless rep
    h[hpos, 18] = rep
  end
  h
end

def widen_int(hexenc, attr)
  cb = hexenc.xeh
  ib = cb.getbyte(0)
  arg = "%02x" % (ib & 0x1f) if (arg = hexenc[2..]) == "" # immediate value XXX negative
  attr_out = attr.merge({ic: Set[]})
  mt = ib >> 5
  if mt < 2
    w = widen_arg(hexenc) do
      val = attr[:value] ^ -mt
      (0xc2+mt).to_s(16) + (val.to_bytes0).to_cbor.hexi
    end
    [w, attr_out]
  elsif mt == 6
    content = CBOR.decode(arg.xeh)
    if content[0..3] != "\x00\x00\x00\x00".b
      content = "\x00".b + content
      [hexenc[0..1] + content.to_cbor.hexi, attr_out]
    end
  else fail [:WI, hexenc, attr].inspect
  end
end

[[unsigned, "unsigned integer"], [negative, "negative integer"]].each do |cases, desc|
  loop do
    add = Hash[
    cases.map do |c|
      set_flags(*c, c[1][:description] || desc)
      # add.concat
      w = widen_int(*c)
      if w != nil
        set_flags(*w, "widened #{desc}")
        w
      end
    end.compact].reject {|k, _| cases.key?(k)}
    break if add == {}
    cases.merge! add
  end
end

# pp unsigned

# pp negative

## -- Simples

arguments = nrand(10, 8, [20, 21, 22, 23, 32, 33, 255]).select {(0..23) === _1 || (32..255) === _1}

simple_lit = {20 => false, 21 => true, 22 => nil}

simples = Hash[arguments.map {|arg|
                 val = if simple_lit.key? arg
                         simple_lit[arg]
                       else
                         CBOR::Simple.new(arg)
                       end
                 [val.to_cbor.hexi, {value: val, ic: Set[]}]
              }]

simples.each { |k, v| set_flags(k, v, "simple")}

# pp simples

## -- Floats

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

[0.0, -0.0, Float::INFINITY, -Float::INFINITY, Float::NAN, -Float::NAN].each do |val|
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
floats.each { |k, v|
  CBOR.decode(k.xeh).to_cbor.hexi
  desc = "#{CBOR.decode(k.xeh).to_cbor.hexi != k ? "widened " : ""}float"
  set_flags(k, v, desc)
}

primitive = unsigned.merge(negative, simples, floats) # .sort

# pp primitive

## -- Strings

def gen_word
  @words ||= (File.readlines("/usr/share/dict/words", chomp: true).shuffle rescue %w{tic tac toe})
  @wordptr ||= 0
  @wordptr = 0 if @wordptr == @words.size
  w = @words[@wordptr]
  @wordptr += 1
  w
end

bytes_lengths = nrand(15, 5, nrand(10, 9, [0, 1, 2, 23, 24, 255, 256, 257]))

def gen_bytes(bl)
  l = bl.sample
  (0...l/8+1).map { [Random.rand(2**64)].pack("Q>") }.join[0...l]
end

def gen_words(bl)
  l = bl.sample
  w = gen_word
  while w.length < l
    w << "-" << gen_word
  end
  w[0...l]
end

# 5.times do
#   pp gen_bytes(bytes_lengths)
#   pp gen_word
# end

strings = Hash[[2, 3].flat_map do |mt|
                 (0...100).flat_map {
                   val = if mt == 2
                           desc = "byte string"
                           gen_bytes(bytes_lengths)
                         else
                           desc = "text string"
                           gen_words(bytes_lengths)
                         end
                   enc_short = val.to_cbor
                   [[enc_short.hexi, {value: val, ic: Set[], description: desc}]]
       }
end]

#warn [:strings, strings.size].inspect
indef_stringvals = Set[]        # only do one indef per val

loop do
  add = Hash[
    strings.map do |hexenc, attr|
      val = attr[:value]
      desc = attr[:description].split[-2..-1].join(" ") # just byte/text string
      set_flags(hexenc, attr)
      # add.concat
      w = widen_arg(hexenc) do |cb, pos, ib, mt, h|
        val = CBOR.decode(hexenc.xeh)
        unless indef_stringvals === val
          indef_stringvals << val
          s = val.bytesize
          r = Random.rand(s+1) # "Zero-length chunks, while not particularly useful, are permitted."
          val.cbor_stream!([r, s - r])
          h.clear               # wholesale replacement
          val.to_cbor.hexi
        end
      end
      if w != nil
        new_c = [w, {value: val}]
        set_flags(*new_c, val.cbor_stream? ? "streaming #{desc}" : "widened #{desc}")
        new_c
      end
    end.compact].reject {|k, _| strings.key?(k)}
#  warn [:add, add.size].inspect
  break if add == {}
  strings.merge! add
end

to_out = primitive.merge(strings).sort

# Arrays

samples = nrand(25, 5, [0, 1, 23, 24, 25])

arrays = {}
samples.each do |n|
  totalsize = 0
  descriptions = Set[]
  a = (0...n).map do |i|
    el = if Random.rand(2) == 0 && arrays != {} && totalsize < 1000
           k = arrays.keys.sample
           descriptions << arrays[k][:description]
           k
         else
           k, v = to_out.sample
           descriptions << v[:description]
           k
         end
    totalsize += el.size
    val = CBOR.decode(el.xeh)
    val
  end
  k = a.to_cbor.hexi
  v = {value: a}
  unless arrays.key?(k)
    set_flags(k, v, "array (#{descriptions.join("/")})")
    arrays[k] = v
  end
end

loop do
  add = Hash[
    arrays.map do |hexenc, attr|
      desc = "widened array"
      val = attr[:value]
      w = widen_arg(hexenc) do |cb, pos, ib, mt, h|
        desc = "streaming array"
        val = CBOR.decode(hexenc.xeh)
        val.cbor_stream!
        h.clear               # wholesale replacement
        val.to_cbor.hexi
      end
      if w != nil
        new_c = [w, {value: val}]
        set_flags(*new_c, desc)
        new_c
      end
    end.compact].reject {|k, _| arrays.key?(k)}
  break if add == {}
  arrays.merge! add
end


to_out.concat arrays.to_a

# Build examples, widen them, add to to_out

# --- Maps

samples = nrand(10, 5, [0, 1, 23, 24, 25])


maps = {}
samples.each do |n|
  totalsize = 0
  descs = [Set[], Set[]]        # k, v
  a = Hash[(0...n).map do |i|
             r = Random.rand(5)
             el = [0, 1].map { |n|
               if r < 3 && maps != {} && totalsize < 1000
                 ret = maps.keys.sample
                 ret = maps.keys.sample if ret.size > 1000
                 descs[n] << maps[ret][:description]
                 ret
               elsif r == 3 && totalsize < 1000
                 k = arrays.keys.sample
                 descs[n] << arrays[k][:description]
                 k
               else
                 k, v = to_out.sample
                 descs[n] << v[:description]
                 k
               end
             }
             totalsize += el.map {|x| x.bytesize}.sum
             val = el.map {|e| CBOR.decode(e.xeh)}
             val
           end]
  descadd = ""
  case Random.rand(4)
  in 0
    descadd = "CDE "
    a = a.cbor_prepare_deterministic # fix descs
  in 1
    descadd = "LDE "
    a = a.cbor_pre_canonicalize # fix descs
  else
  end
  k = a.to_cbor.hexi
  v = {value: a}
  unless maps.key?(k)
    set_flags(k, v, "#{descadd}map (#{descs[0].join("/")}) -> (#{descs[1].join("/")}))")
    maps[k] = v
  end
end

loop do
  add = Hash[
    maps.map do |hexenc, attr|
      desc = "widened map"
      w = widen_arg(hexenc) do |cb, pos, ib, mt, h|
        desc = "streaming map"
        val = CBOR.decode(hexenc.xeh)
        val.cbor_stream!
        h.clear               # wholesale replacement
        val.to_cbor.hexi
      end
      if w != nil
        new_c = [w, {value: attr[:value]}]
        set_flags(*new_c, desc)
        new_c
      end
    end.compact].reject {|k, _| maps.key?(k)}
  break if add == {}
  maps.merge! add
end

to_out.concat maps.to_a


## -- Tags


reg = IANA::Registry::CBOR_TAGS.new

arguments = (nrand(10, 1) + nrand(20, 64, boundary(24, 1, 2, 4))).reject { reg.find(_1)} # Don't use registered tags

tags = {}
arguments.each do |arg|
  content = to_out.sample
  desc = "tag with #{content[1][:description]}"
  cb = arg.to_cbor.hexi
  cb[0] = "cd"[cb[0].to_i]
  cb << content[0]
  attr = {value: CBOR::Tagged.new(arg, content[1][:value])}
  set_flags(cb, attr, desc)
  tags[cb] = attr
end


loop do
  add = Hash[
    tags.map do |hexenc, attr|
      desc = "widened #{attr[:description].sub(/widened tag/, "tag")}"
      val = attr[:value]
      w = widen_arg(hexenc) do
        # No streaming for tags
      end
      if w != nil
        new_c = [w, {value: val}]
        set_flags(*new_c, desc)
        new_c
      end
    end.compact].reject {|k, _| tags.key?(k)}
  break if add == {}
  tags.merge! add
end

to_out.concat tags.to_a

# --- put everything together

to_out.sort!
case $options.target
in :csv

  MY_CSV_OPTIONS = {
    col_sep:            ";",
    quote_char:         '|',
    quote_empty:        false,
  }

  headers = ["CBOR", "value", "attributes", "description"]
  output = CSV.generate('', headers: headers, write_headers: true, **MY_CSV_OPTIONS) do |csv|
    to_out.each do |k, v|
      val = v[:value]
      val = val.cbor_prepare_dlo unless $options.more_diag
      k = prettier(k) if $options.more_pretty
      csv << [k, val.cbor_diagnostic, v[:ic].join("/"), v[:description]]
    end
  end

  puts output

in :"test-vector"
  fail "Not yet implemented"
end

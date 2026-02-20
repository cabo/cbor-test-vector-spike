#!/usr/bin/env ruby -Ku
require 'csv'
require 'cbor-diagnostic'

TEST_VECTOR_CSV_OPTIONS = {
  col_sep:            ';',
  quote_char:         '|',
  quote_empty:        false,
  headers:            ["CBOR", "value", "attributes", "description"],
  write_headers:      true,
  header_converters:  :symbol_raw
}

if __FILE__ == $PROGRAM_NAME

  require_relative './test-vector-cbor-dlo'

  class String
    def hexi
      bytes.map{|x| "%02x" % x}.join
    end
    def xeh
      gsub(/\s/, "").chars.each_slice(2).map{ |x| Integer(x.join, 16).chr("BINARY") }.join
    end
  end

  require 'optparse'

  Encoding.default_external = Encoding::UTF_8
  require 'optparse'
  require 'ostruct'

  $error = 0

  output_formats = [:edn, :json]

  $options = OpenStruct.new
  $options.target = output_formats[0]

  begin
    op = OptionParser.new do |opts|
      opts.banner = "Usage: #{$PROGRAM_NAME} [options]"

      opts.on("-v", "--[no-]verbose", "Run verbosely") do |v|
        $options.verbose = v
      end
      opts.on("-tFMT", "--to=FMT", output_formats,
              "Target format (#{output_formats.join("|")}, default: #{$options.target})") do |v|
        $options.target = v.to_sym
      end
    end
    op.parse!
  rescue Exception => e
    warn op unless e.to_s == 'exit'
    exit 1
  end

  require 'json'

  data = CSV.parse(ARGF.read, **TEST_VECTOR_CSV_OPTIONS)

  tests = data.map do |row|
    flags = row[:attributes]&.split("/") || []
    r = if $options.target == :json
          {
            "encoded_hex" => row[:CBOR],      # .xeh
            "decoded_edn" => row[:value],     # needs to be EDN-parsed
          }
        else
          bin = row[:CBOR].xeh
          {
            "encoded" => bin,
            "decoded" => CBOR.decode(bin).cbor_prepare_dlo
          }
        end
    r.merge!({
      "description" => row[:description],
      "flags" => flags,
    })
    unless flags&.include?("PS") && flags&.include?("DLO")
      r["roundtrip"] = false
    end
    r
  end

  out = {"title" => "good fuzz",
         "description" => "Good tests from fuzzing RFC 8949",
         "tests" => tests}

  out_text = if $options.target == :json
               JSON.pretty_generate(out)
             else # :edn
               out.cbor_diagnostic
             end
  puts out_text
end

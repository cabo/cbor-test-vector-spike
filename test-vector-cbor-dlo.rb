require 'cbor-packed'           # for cbor_visit

class String
  def hexi
    bytes.map{|x| "%02x" % x}.join
  end
  def xeh
    gsub(/\s/, "").chars.each_slice(2).map{ |x| Integer(x.join, 16).chr("BINARY") }.join
  end
end

module CBOR
  module DLO

    def self.dlo?(o)
      o.cbor_visit do |item|
        case item
        when String, Array, Hash
          return false if item.cbor_stream?
        end
        true # continue visiting
      end
      true # didn't find any streaming items
    end


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

if __FILE__ == $PROGRAM_NAME

  def dlo?(...) = CBOR::DLO::dlo?(...)

  fail unless dlo?([1, 2, 3, {a: 1, b: 2}])
  fail unless dlo?(CBOR.decode("80".xeh))
  fail if dlo?(CBOR.decode("9F80FF".xeh))
  fail unless dlo?(CBOR.decode("A18001".xeh))
  fail if dlo?(CBOR.decode("A1BF8001FF60".xeh))
  fail unless dlo?(CBOR.decode("60".xeh))
  fail if dlo?(CBOR.decode("817F6130623232FF".xeh))

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
    fail unless CBOR::DLO::dlo?(pd)
  end

end

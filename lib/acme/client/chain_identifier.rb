class Acme::Client
  class ChainIdentifier
    def initialize(pem_certificate_chain)
      @pem_certificate_chain = pem_certificate_chain
    end

    def match?(name: nil, fingerprint: nil)
      if fingerprint
        match_fingerprint?(fingerprint.downcase)
      elsif name
        match_name?(name)
      end
    end

    def match_name?(name)
      issuers.any? do |issuer|
        issuers.last.include?(name)
      end
    end

    def match_fingerprint?(fingerprint)
      sha256_fingerprints.include?(fingerprint)
    end

    private

    def issuers
      x509_certificates.map(&:issuer).map(&:to_s)
    end

    def sha256_fingerprints
      x509_certificates.map(&:to_der).map { |der| OpenSSL::Digest::SHA256.new(der).to_s }
    end

    def x509_certificates
      @x509_certificates ||= splitted_pem_certificates.map { |pem| OpenSSL::X509::Certificate.new(pem) }
    end

    def splitted_pem_certificates
      @pem_certificate_chain.each_line.slice_after(/END CERTIFICATE/).map(&:join)
    end
  end
end

require 'spec_helper'

describe Acme::Client::Resources::Order do
  let(:private_key) { generate_private_key }
  let(:unregistered_client) do
    client = Acme::Client.new(private_key: private_key, directory: DIRECTORY_URL)
    client.new_account(contact: 'mailto:info@example.com', terms_of_service_agreed: true)
    client
  end

  let(:client) do
    client = Acme::Client.new(private_key: private_key, directory: DIRECTORY_URL)
    client.new_account(contact: 'mailto:info@example.com', terms_of_service_agreed: true)
    client
  end

  let(:order) do
    client.new_order(identifiers: [{ type: 'dns', value: 'example.com' }])
  end

  context 'status' do
    it 'send the agreement for the terms', vcr: { cassette_name: 'order_status' } do
      expect(order.status).to eq('pending')
    end
  end

  context 'finalize' do
    let(:authorization) { order.authorizations.first }
    let(:challenge) { authorization.http01 }

    it 'call client finalize failure', vcr: { cassette_name: 'order_finalize_fail' } do
      csr = Acme::Client::CertificateRequest.new(names: %w[example.com])
      expect { order.finalize(csr: csr) }.to raise_error(Acme::Client::Error::Unauthorized)
    end

    it 'call client finalize sucess', vcr: { cassette_name: 'order_finalize_sucess' } do
      serve_once(challenge.file_content) do
        challenge.request_validation
      end

      csr = Acme::Client::CertificateRequest.new(names: %w[example.com])
      expect { order.finalize(csr: csr) }.not_to raise_error
    end
  end

  context 'certificate' do
    let(:authorization) { order.authorizations.first }
    let(:challenge) { authorization.http01 }
    let(:finalized_order) do
      serve_once(challenge.file_content) do
        challenge.request_validation
      end

      csr = Acme::Client::CertificateRequest.new(names: %w[example.com])
      order.finalize(csr: csr)
      order.reload
      order
    end

    it 'call client certificate sucess', vcr: { cassette_name: 'order_certificate_download_sucess' } do
      certificate = finalized_order.certificate

      expect { OpenSSL::X509::Certificate.new(certificate) }.not_to raise_error
    end

    it 'call client certificate fail', vcr: { cassette_name: 'order_certificate_download_fail' } do
      expect { order.certificate }.to raise_error(Acme::Client::Error::CertificateNotReady)
    end

    it 'call client certificate with a force_chain', vcr: { cassette_name: 'order_certificate_download_preferred_chain' } do
      force_chain_name = 'Pebble Root CA 769220'

      expect { finalized_order.certificate(force_chain: force_chain_name) }.not_to raise_error
    end

    it 'call client certificate with an unmatched force_chain', vcr: { cassette_name: 'order_certificate_download_preferred_chain' } do
      force_chain_name = 'Fail Test CA'

      expect {
        finalized_order.certificate(force_chain: force_chain_name)
      }.to raise_error(Acme::Client::Error::ForcedChainNotFound)
    end

    it 'call client certificate with a force_chain_fingerprint', vcr: { cassette_name: 'order_certificate_download_preferred_chain' } do
      force_chain_fingerprint = 'a6721e5342b38e14d2f163a0658cd9dc8ec72e7c6e070c2895217d9b48e0d7da'

      expect { finalized_order.certificate(force_chain_fingerprint: force_chain_fingerprint) }.not_to raise_error
    end

    it 'call client certificate with an unmatched fingerprint', vcr: { cassette_name: 'order_certificate_download_preferred_chain' } do
      force_chain_fingerprint = 'someRanD0MSha'

      expect {
        finalized_order.certificate(force_chain: force_chain_fingerprint)
      }.to raise_error(Acme::Client::Error::ForcedChainNotFound)
    end
  end

  context 'reload' do
    it 'reload a update attributes', vcr: { cassette_name: 'order_reload' } do
      expect { order.reload }.not_to raise_error
      expect(order.url).not_to be_nil
    end
  end

  context 'authorizations' do
    it 'load authorizations', vcr: { cassette_name: 'order_authorizations' } do
      authorizations = order.authorizations
      expect(authorizations).to all(be_a(Acme::Client::Resources::Authorization))
    end
  end
end

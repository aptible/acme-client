require 'spec_helper'

describe Acme::Client::ChainIdentifier do
  let(:pem) { open('./spec/fixtures/certificate_chain.pem').read }
  let(:issuer_name) { 'Pebble Root CA' }
  let(:issuer_fingerprint) { '508494af86890199b188befb827c75ae97538272e8dba4c27852b4ce8b96b248' }

  subject { Acme::Client::ChainIdentifier.new(pem) }
  it 'matches certificate by name' do
    expect(subject).to be_a_match_name(issuer_name)
  end

  it 'fail non matching certificate name' do
    expect(subject).not_to be_a_match_name('foo')
  end

  it 'matches certificate by fingerprint' do
    expect(subject).to be_a_match_fingerprint(issuer_fingerprint)
  end

  it 'fail non matching certificate fingerprint' do
    expect(subject).not_to be_a_match_fingerprint('foo')
  end

  describe '#match?' do
    it 'routes to correct method by argument' do
      expect(subject).to be_a_match(name: issuer_name)
      expect(subject).to be_a_match(fingerprint: issuer_fingerprint)
    end

    it 'gives fingerprint precedence' do
      expect(subject).to be_a_match(name: 'foo', fingerprint: issuer_fingerprint)
    end
  end
end

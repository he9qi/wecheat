require 'spec_helper'

describe Wecheat::MsgCrypt do

  let(:timestamp) { "1415979516" }
  let(:nonce)     { "1320562132" }
  let(:signature) { "8dc95bd84e3a9d58b3cffd08e922a215fc07d7f1" }
  let(:message)   { "<xml><ToUserName><![CDATA[oia2TjjewbmiOUlr6X-1crbLOvLw]]></ToUserName><FromUserName><![CDATA[gh_7f083739789a]]></FromUserName><CreateTime>1407743423</CreateTime><MsgType>  <![CDATA[video]]></MsgType><Video><MediaId><![CDATA[eYJ1MbwPRJtOvIEabaxHs7TX2D-HV71s79GUxqdUkjm6Gs2Ed1KF3ulAOA9H1xG0]]></MediaId><Title><![CDATA[testCallBackReplyVideo]]></Title><Descript  ion><![CDATA[testCallBackReplyVideo]]></Description></Video></xml>" }
  let(:msg_crypt) { Wecheat::MsgCrypt.new "wx2c2769f8efd9abc2", "spamtest", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG" }
  let(:encrypted_message) {
    """<xml>
      <Encrypt><![CDATA[3kKZ++U5ocvIF8dAHPct71x8uU00NF2unLwn6szkBOHqvn9ZZgpyNCFCOePMhK64EuaOTcKtje/BFGmmDNFHg5EpNoZAXj3s7A2YopQCIwDAEb0Eer5Agl3g6jOskVgs3Youycx9ijoP83HUYiMf7/z/xuTUY2oKcMLT5qTVFiXoGDKcEqGcRRkx0W59g4vTbmg6unyOOC31p8C4GYZRRzswd5HCaQSmIJsWuSsxJusdqyDURhXAATTcvm2uYwDxmN11SIiyoT25oIiRd5i6Us6Q86+nB2nZciOR5RX2yFa4diFpzg6fsiK9h8lWvnsj/loZyul/r/x3dYB6h9lAPYg0NVMCZBjOBRhW/UJXK0ep07VMtF16qsoq4eVa36PQc774WqTbOsKTf6Vd1w4VCS+BVwMRF9XbH5W5RT5fQUDVflwZHFBS5vCPd37l0QFSo/p9+5TzYRfFN8/GLSz9m6a2qmNAIwqsy0UdZL+PB8KqQGaHt4a2czt70nATcFA0Vxposa2hA1DCFN47VkAPNn613Y5tsX2CEj38XPVJKDBqmu2Urk89XFRvR1clOeZ+RFW8Gt1I2aahqhea1LkEHIyblsp2QiOjicCYFOOC5CpRE4I4k2qJ/z8TP3Wiq8Yh]]></Encrypt>
      <MsgSignature><![CDATA[8dc95bd84e3a9d58b3cffd08e922a215fc07d7f1]]></MsgSignature>
      <TimeStamp>1415979516</TimeStamp>
      <Nonce><![CDATA[1320562132]]></Nonce>
      </xml>"""
  }

  describe "#encrypt" do
    it "generate xml with encrypt" do
      expect(SecureRandom).to receive(:hex).with(8).and_return("HLFOQjbkfgUh46s8")
      expect(msg_crypt.encrypt message, nonce, timestamp).to eq(encrypted_message)
    end
  end

  describe "#decrypt" do
    it "raises invalid signature" do
      expect { msg_crypt.decrypt(encrypted_message, "invalid_signature", nonce, timestamp) }.to \
        raise_error(Wecheat::InvalidSignature)
    end

    it "get decrypted xml" do
      expect(msg_crypt.decrypt(encrypted_message, signature, nonce, timestamp)).to \
        eq(message)
    end
  end

end

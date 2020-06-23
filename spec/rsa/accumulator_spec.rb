require 'spec_helper'

RSpec.describe RSA::Accumulator do

  include RSA::ACC::Functions

  it "has a version number" do
    expect(RSA::ACC::VERSION).not_to be nil
  end

  describe '#initialize' do
    it 'should generate n and acc' do
      acc = RSA::Accumulator.generate_random
      expect(acc.n).is_a?(Integer)
      expect(acc.value).is_a?(Integer)
      expect(acc.value < acc.n).to be true
      expect(acc.n.bit_length).to eq(3072)
    end
  end

  describe '#add' do
    context 'with a single element' do
      it 'should generate updated acc' do
        acc = RSA::Accumulator.generate_rsa2048
        initial = acc.value
        acc.add('a')
        acc.add('b')
        acc.add('c')
        acc.add('d')
        p = hash_to_prime('a') * hash_to_prime('b') * hash_to_prime('c') * hash_to_prime('d')
        expect(acc.value).to eq(initial.pow(p, acc.n))
      end
    end

    context 'with multiple elements' do
      it 'should generate product of all elements.' do
        acc = RSA::Accumulator.generate_rsa2048
        acc.add('a')
        acc.add('b')
        acc.add('c')
        acc2 = RSA::Accumulator.generate_rsa2048
        acc2.add('a', 'b', 'c')
        expect(acc).to eq(acc2)
        # TODO include? supports multiple elements
      end
    end
  end

  describe '#member' do
    it 'checks whether element exist in the accumulator' do
      acc = RSA::Accumulator.generate_random
      acc.add('a')
      acc.add('b')
      proof = acc.add('c')
      dummy = RSA::ACC::MembershipProof.new('d', proof.witness, proof.acc_value, proof.proof)
      expect(acc.member?(proof)).to be true
      expect(acc.member?(dummy)).to be false
    end
  end

  describe '#delete' do
    context 'with correct witness' do
      it 'should delete correctly.' do
        acc = RSA::Accumulator.generate_random
        acc.add('a', 'b')
        acc0 = acc.value
        proof = acc.add('c')
        expect(acc.member?(proof)).to be true
        deleted_proof = acc.delete(proof)
        expect(acc.value).to eq(acc0)
        expect(acc.member?(proof)).to be false
        deleted_prime = deleted_proof.element_prime
        expect(RSA::ACC::PoE.verify(deleted_proof.witness, deleted_prime, proof.acc_value, deleted_proof.proof, acc.n)).to be true

        # empty delete
        acc1 = acc.value
        expect(acc.delete)
        expect(acc.value).to eq(acc1)
      end
    end

    context 'with bad witness' do
      it 'should raise error.' do
        acc = RSA::Accumulator.generate_random
        acc.add('a', 'b')
        proof = acc.add('c')
        dummy = RSA::ACC::MembershipProof.new('b', proof.witness, proof.acc_value, proof.proof)
        expect{acc.delete(dummy)}.to raise_error(RSA::ACC::Error, 'Bad witness.')
      end
    end
  end

  describe '#root_factor' do
    it 'should return xi-th root.' do
      acc = RSA::Accumulator.generate_rsa2048
      factorization = [78251750415843988103204227422250607655859466573259045592767128771607933292993, 53365470345028571844922079485887563611724522797603647213730384716486205720189, 29758383065206600500317794970535330816860581595412318673289399442125438230171]
      result = acc.root_factor(*factorization)
      expect(result.size).to eq(3)
      expect(result[0]).to eq(20027256449746146237830855196327826249859654163676527913155169580109722268868760521559935523934068986918663124476614910465057134916966257351497776471413327974241945407754369007728815060012918059049263724622070582170275766983793147855878978977599713714856176082559132225427914386933523168150259145985244612824910150097366292640996966776621612825405458995676868473306225904599616290735216521665389425856282512290197041082348663848323749672236961858285228390017628096448233713658528822110890009835631209125357706177617439223525156753149346490059174714810212269629801431074048923669540012624603530569458827024367189743709)
      expect(result[1]).to eq(22513970264734384835067213737669313066419526250656136849450247512917707737778474152375976163153798267331348036087019466235427614155757198399503034541199298320462662748494889164078629394628406146708400920173468176418092557727143966667096271034862667624075852017444107998637858581587505276094362595667101058658223405298607801813915332869863572627129240473397500821440830489657937176667507196521101236006667028246733860974638732785896064976166586067381183282199786769541410503092635186588600862285332309114550652837371755312525212151881516416256789882758678545621446750782031234869880947742099969758474275102572845344518)
      expect(result[2]).to eq(11858623177220340855687523193148265672331599173264549688990615530787447917321063076941306600115366659266195606794134662137325112542914421474040169964123714953006056004616441314984958458794130659176293625379691155924770032315055172613906091315904912245731703599757345888668354324776897406679357021767243594069038999498154769539549470936306461899360334826566572872343464230932352470290792817176257367602693270148860070893505495081415804030083619841004823608704851785007831531882724875992454567109478153485046065529355439433716854469176577773770246520398951544490693991254791532787948273590910789526518017086634468259280)
    end
  end

  describe "#prove_non_member" do
    it 'should generate non membership proof.' do
      members = %w(a b)
      non_members = %w(c, d)
      acc = RSA::Accumulator.generate_rsa2048
      acc.add(*members)
      proof = acc.prove_non_membership(members, non_members)
      expect(acc.non_member?(non_members, proof)).to be true
    end
  end

end

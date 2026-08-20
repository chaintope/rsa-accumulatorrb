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
        expect(acc.value).to eq(normalize(initial.pow(p, acc.n), acc.n))
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
      x = factorization.inject(:*)
      result.each_with_index do |root, i|
        expect(normalize(root.pow(factorization[i], acc.n), acc.n))
            .to eq(normalize(acc.value.pow(x, acc.n), acc.n))
      end
      expect(result[0]).to eq(5168652025911747256196328043720572321569627962527504114621968255933939751838835034704083001946715419999627516772900171724241424232209927151310712648659517018445447399533407728242603287257343837325751247202620582907337612875302552241451480771208714686941253018083326466389280731812598347022395486296972257162639032325067344618088175088840430751392964391507905974614514029636968533089064676498425584818527939370180264973852955827932384171906641975619186562616804093666423830795649601910034606680092141653350043639508333244437769633207026799852980116627955630255239014289974603712411366011960860642551570098454930976648)
      expect(result[1]).to eq(2681938210923508658959969502379085505009755875547895178326890323125954282929121403888042362726986139586942605162495615953870944993418986103305454578873546672224730058792887571892788952641855749666614051651222988659520822131951733430234188713945760777721577083198350693179336537158616239078292036615115811329325777123825835445169808995598470949669182913787273626479909444578647647156774001642713774668143423413643445081562886890360068867977017766523231670434645420573247041361543237432323754230391041664157096979754017155437714234474856873655364948679489354263593694581992292512070430894464421453536122020249275375839)
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

  describe '.generate_with_modulus' do
    it 'should build an accumulator on the given modulus.' do
      n = RSA::Accumulator::RSA2048_MODULUS
      acc = RSA::Accumulator.generate_with_modulus(n)
      expect(acc.n).to eq(n)
      expect(acc).to eq(RSA::Accumulator.generate_rsa2048)
      proof = acc.add('a')
      expect(acc.member?(proof)).to be true
    end

    it 'should reject a modulus that is not an odd integer greater than 4.' do
      [nil, 'abc', 4, 9.0, 15 * 2].each do |bad|
        expect { RSA::Accumulator.generate_with_modulus(bad) }.to raise_error(ArgumentError)
      end
    end
  end

  describe '.generate_random' do
    it 'should not use a degenerate initial value.' do
      acc = RSA::Accumulator.generate_random(1024)
      expect(acc.g).to be > 1
      expect(acc.g).to be < acc.n - 1
      expect(acc.g.gcd(acc.n)).to eq(1)
    end
  end

  describe 'quotient group Z_n^* / {+-1}' do
    it 'should keep every published group element normalized.' do
      acc = RSA::Accumulator.generate_rsa2048
      acc.add('a', 'b')
      proof = acc.add('c')
      expect(acc.value).to eq(normalize(acc.value, acc.n))
      expect(acc.g).to eq(normalize(acc.g, acc.n))
      expect(proof.witness).to eq(normalize(proof.witness, acc.n))
      expect(proof.proof).to eq(normalize(proof.proof, acc.n))
    end

    it 'should accept a negated witness as the same group element.' do
      acc = RSA::Accumulator.generate_rsa2048
      acc.add('a', 'b')
      proof = acc.add('c')
      negated = RSA::ACC::MembershipProof.new(
          proof.element, acc.n - proof.witness, proof.acc_value, acc.n - proof.proof)
      expect(acc.member?(negated)).to be true
      expect { acc.delete(negated) }.not_to raise_error
    end
  end

  describe '#non_member?' do
    let(:acc) do
      a = RSA::Accumulator.generate_rsa2048
      a.add('a', 'b')
      a
    end

    context 'with a forged proof' do
      it 'should not accept a gv_inv chosen by the prover.' do
        # A prover picks an arbitrary d and claims gv_inv = d^x, so that NI-PoE passes
        # for any x. v = acc.value(a = 1) makes NI-PoKE2 pass as well.
        x = elements_to_prime(['a'])
        v = acc.value
        d = 3
        gv_inv = d.pow(x, acc.n)
        forged = RSA::ACC::NonMembershipProof.new(
            d, v, gv_inv,
            RSA::ACC::PoKE2.prove(acc.value, 1, v, acc.n),
            RSA::ACC::PoE.prove(d, x, gv_inv, acc.n))
        expect(acc.non_member?(['a'], forged)).to be false
      end

      it 'should ignore gv_inv in the proof.' do
        non_members = %w(c d)
        proof = acc.prove_non_membership(%w(a b), non_members)
        tampered = RSA::ACC::NonMembershipProof.new(
            proof.d, proof.v, 12345, proof.poke2_proof, proof.poe_proof)
        expect(acc.non_member?(non_members, tampered)).to be true
      end
    end

    context 'with a degenerate group element' do
      it 'should return false without raising.' do
        non_members = %w(c d)
        proof = acc.prove_non_membership(%w(a b), non_members)
        [0, 1, acc.n - 1, acc.n].each do |bad|
          bad_proof = RSA::ACC::NonMembershipProof.new(
              proof.d, bad, proof.gv_inv, proof.poke2_proof, proof.poe_proof)
          expect(acc.non_member?(non_members, bad_proof)).to be false
        end
      end
    end
  end

  describe '#prove_membership' do
    context 'holding elements' do
      it 'should generate inclusion proof from holding products.' do
        acc = RSA::Accumulator.generate_random(hold_elements: true)
        acc.add(*%w(a b c d e f))
        proof = acc.prove_membership('c')
        expect(acc.member?(proof)).to be true
        proof = acc.prove_membership(*%w(b e))
        expect(acc.member?(proof)).to be true
        proof_be = acc.prove_membership(*%w(b e))
        acc.delete(acc.prove_membership('b'))
        expect(acc.prove_membership('b')).to be nil
        expect(acc.member?(proof_be)).to be false
        expect(acc.prove_membership('g')).to be nil
        expect(acc.prove_membership(*%w(b g))).to be nil
      end
    end

    context 'not holding elements' do
      it 'should raise error.' do
        acc = RSA::Accumulator.generate_random
        acc.add(*%w(a b c d e f))
        expect{acc.prove_membership('c')}.to raise_error(RSA::ACC::Error, 'This accumulator does not hold the product of the elements.')
      end
    end
  end

end

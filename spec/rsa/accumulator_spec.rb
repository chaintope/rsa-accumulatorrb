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
        acc = RSA::Accumulator.generate_rsa3072
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
        acc = RSA::Accumulator.generate_rsa3072
        acc.add('a')
        acc.add('b')
        acc.add('c')
        acc2 = RSA::Accumulator.generate_rsa3072
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
      acc = RSA::Accumulator.generate_rsa3072
      factorization = [78251750415843988103204227422250607655859466573259045592767128771607933292993, 53365470345028571844922079485887563611724522797603647213730384716486205720189, 29758383065206600500317794970535330816860581595412318673289399442125438230171]
      result = acc.root_factor(*factorization)
      expect(result.size).to eq(3)
      expect(result[0]).to eq(2144158068164689130805861545198726572551140119287477464767287974585708056931469075834012558463896342615295318664525794995016573037902223739918792285258786115414256034094577399040116495869969054357539836666736075461077775522600740078108952285824245283551455179138945846356955843598072710271192531900741801176034593571069199739978216006331012638643770110240853041124977303816941191051713839077796962325507435445173255969213495191883830124694168720659744742352947206604555658426370827212425715481966936388527420252721379427474109123898939877671559413084658278308665715532713292185986984036209914006264385414867998295172119856522284808022221304308390463474562100749688043219962349381833574470071152366738600149855270374448797484770791355050263379578727434936726546873129104143951380896624251994181549879811465905384545458027311186618836339581349869463373887694606203927939092619292986327144946563695620229086188099032281254011005)
      expect(result[1]).to eq(563963234311229334173179864456599927870074314216390251250245254883820419113244974403901864376797490895660127169699196327296249493325628440350635270078125074863219706419001176829984251898026164804005637609697567256117070461946747189477636965035278918763428506888019914202905649123214841487506937806097236593677421207223304216665012255022301437166184645529678260798512416122879662724668285372196915635069279673466805977785064538661847837429634769807131463757222058317318862061347255902310437767541922747617215184912828451123927233410252849691152035236428331599419747434546661364901532286868480053471210989384381691294882022132858943426164879880928830375624794952163847344327987526449627909965433525022079123040840048416367975991686646809925886845048507018703639466470414850540791709113017970614613877836182703294810182906448702113072099213947908400286662755222365069017484801962812188302540115522514992294151551319334609723427)
      expect(result[2]).to eq(162917132896824457843442194035552177291611502528434875659105736394667096112252319096461708201543846428475793542153807499718536277841448117877721037606202658426404755344900007014091331695381382565906352820334269117427330320349593355116159183730903971112297650131610139251791235442233020714251845688511987874404562362391633573366620396604704210242119349925776437397917961176678804258027468242034600991299034021029814814536112784798483634989387255133182422014065166202587270000444359195492188045223992208536240907377322455614341669190246618456173976072551294150954166885187240016392702589907583233005799405110511463530389502599762299994971417434214466084514496411263776603197582712681686798155614965882160148013171623609554221630369968723184710947707400016682713918071216639254091255167615398200686534446843515668825065965088415055393469749541023533317348380657628800312442801995362365913260864576298230072647294869148812044349)
    end
  end

  describe "#prove_non_member" do
    it 'should generate non membership proof.' do
      members = %w(a b)
      non_members = %w(c, d)
      acc = RSA::Accumulator.generate_rsa3072
      acc.add(*members)
      proof = acc.prove_non_membership(members, non_members)
      expect(acc.non_member?(non_members, proof)).to be true
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

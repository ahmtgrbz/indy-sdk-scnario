import asyncio
import json
import time
from os.path import dirname
from indy import pool, did, wallet, ledger, anoncreds, blob_storage
from indy.error import ErrorCode, IndyError
from utils import ensure_previous_request_applied
from definations import transcript_cred_def, network, steward, goverment, company, university, transcript, person

async def create_wallet(steward):
    try:
        await wallet.create_wallet(steward['wallet_config'],
                                    steward['wallet_credentials'])
    except IndyError as e:
        if e.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass

    steward['wallet'] = await wallet.open_wallet(steward['wallet_config'],
                                                   steward['wallet_credentials'])
    print("{} cüzdanı oluşturuldu".format(steward["name"]))

async def getting_verinym(from_, to):
    await create_wallet(to)

    (to['did'], to['key']) = await did.create_and_store_my_did(to['wallet'], "{}")

    from_['info'] = {
        'did': to['did'],
        'verkey': to['key'],
        'role': to['role'] or None
    }

    await send_nym(from_['pool'], from_['wallet'], from_['did'], from_['info']['did'],
                   from_['info']['verkey'], from_['info']['role'])

async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)

async def connect_network():
    print("{}'e bağlanılıyor".format(network["name"]))
    network["config"] = json.dumps({"genesis_txn": str(network["genesis_txn_path"])})
    await pool.set_protocol_version(2)
    try:
        await pool.create_pool_ledger_config(network['name'], network['config'])
    except IndyError as e:
        if e.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    network['handle'] = await pool.open_pool_ledger(network['name'], None)
    print("{}'e bağlanıldı".format(network["name"]))
    return network

async def take_steward_control(pool):
    steward['pool'] = pool['handle']
    await create_wallet(steward)
    steward['did_info'] = json.dumps({'seed': steward['seed']})
    steward['did'], steward['key'] = await did.create_and_store_my_did(steward['wallet'], steward['did_info'])
    print("\"{}\" -> seed ile kontrol alındı.".format(steward["name"]))
    return steward

async def add_trust_actors(pool, steward):
    goverment['pool'] = pool['handle']
    company['pool'] = pool['handle']
    university['pool'] = pool['handle']

    print("\n\"Steward\" -> Hükümet ağa ekelniyor.")
    await getting_verinym(steward, goverment)
    print("\"Steward\" -> Hükümet ağa eklendi.")
    print("\n\"Steward\" -> Şirket ağa ekelniyor.")
    await getting_verinym(steward, company)
    print("\"Steward\" -> Şirket ağa eklendi.")
    print("\n\"Steward\" -> Üniversite ağa ekelniyor.")
    await getting_verinym(steward, university)
    print("\"Steward\" -> Üniversite ağa eklendi.")

    return goverment, company, university

async def add_person(pool):
    person['pool'] = pool['handle']
    await create_wallet(person)
    (person['did'], person['key']) = await did.create_and_store_my_did(person['wallet'], "{}")
    return person

async def create_credential_schema(issuer):
    
    (issuer['transcript_schema_id'], issuer['transcript_schema']) = \
        await anoncreds.issuer_create_schema(issuer['did'], transcript['name'], transcript['version'],
                                             json.dumps(transcript['attributes']))
    transcript_schema_id = issuer['transcript_schema_id']
    print(f"\"{issuer['name']} \" ->yeni bir {transcript['name']}-{transcript['version']} şeması oluşturuldu. Id: {transcript_schema_id}")

    await send_schema(issuer['name'],issuer['pool'], issuer['wallet'], issuer['did'], issuer['transcript_schema'], transcript_schema_id)
    return transcript_schema_id

async def send_schema(issuer_name, pool_handle, wallet_handle, _did, schema, schema_id):
    schema_request = await ledger.build_schema_request(_did, schema)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, schema_request)
    print(f"{schema_id} idli şema {issuer_name} tarafından ağda yayınlandı.")

async def get_schema(issuer, schema_id):
    get_schema_request = await ledger.build_get_schema_request(issuer['did'], schema_id)
    get_schema_response = await ensure_previous_request_applied(
        issuer['pool'], get_schema_request, lambda response: response['result']['data'] is not None)
    return await ledger.parse_get_schema_response(get_schema_response)

async def create_credential_definition(issuer, schema_id):
    print(f"{issuer['name']} -> {schema_id} idli şema ağ üzerinden alınıyor.")
    (issuer['transcript_schema_id'], issuer['transcript_schema']) = \
        await get_schema(issuer, schema_id)
    
    (issuer['transcript_cred_def_id'], issuer['transcript_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(issuer['wallet'], issuer['did'],
                                                               issuer['transcript_schema'], transcript_cred_def['tag'],
                                                               transcript_cred_def['type'],
                                                               json.dumps(transcript_cred_def['config']))
    
    print(f"{issuer['name']} -> {issuer['transcript_cred_def_id']} idli kimlik bilgisi tanımı şemaya uygun oluşturuldu.")
    
    cred_def_request = await ledger.build_cred_def_request(issuer['did'], issuer['transcript_cred_def'])
    await ledger.sign_and_submit_request(issuer['pool'], issuer['wallet'], issuer['did'], cred_def_request)
    print(f"{issuer['name']} -> {issuer['transcript_cred_def_id']} idli kimlik bilgisi tanımı üniversite kayıtlarına(cüzdanına) eklendi.")

async def get_cred_def_from_ledger(pool_handle, _did, cred_def_id):
    get_cred_def_request = await ledger.build_get_cred_def_request(_did, cred_def_id)
    get_cred_def_response = \
        await ensure_previous_request_applied(pool_handle, get_cred_def_request,
                                              lambda response: response['result']['data'] is not None)
    return await ledger.parse_get_cred_def_response(get_cred_def_response)

async def get_credential(university, person):
    university['transcript_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(university['wallet'], university['transcript_cred_def_id'])
    person['transcript_cred_offer'] = university['transcript_cred_offer']
    print(f"\"{university['name']}\" -> Transkripti aktarmak için gerekli gerekli tanımlar kişiye gönderildi.")

    print(f"\"{person['name']}\" -> Kendi transkiripti ile iligli kanıtı almak için üniversitey istek yapıyor.")
    transcript_cred_offer_object = json.loads(person['transcript_cred_offer'])
    person['transcript_schema_id'] = transcript_cred_offer_object['schema_id']
    person['transcript_cred_def_id'] = transcript_cred_offer_object['cred_def_id']
    print(f"\"{person['name']}\" -> İstek, imzalanıyor ve gönderiliyor.")
    #Yaptığı isteği özgün bir değerle imzalıyor. Bu kimliği özgün kılmak için yapılır.(Kimliği iptal edebilme ve takip edeiblmesini sağlar)
    person['master_secret_id'] = await anoncreds.prover_create_master_secret(person['wallet'], None)
    (person['university_transcript_cred_def_id'], person['university_transcript_cred_def']) = \
        await get_cred_def_from_ledger(person['pool'], person['did'], person['transcript_cred_def_id'])
    (person['transcript_cred_request'], person['transcript_cred_request_metadata']) = \
        await anoncreds.prover_create_credential_req(person['wallet'], person['did'],
                                                     person['transcript_cred_offer'], person['university_transcript_cred_def'],
                                                     person['master_secret_id'])
    print("\"Kişi\" -> İstek hazırlandı")
    university['transcript_cred_request'] = person['transcript_cred_request']
    print("\"Kişi\" -> Transkript almak için istek üniversiteye gönderildi")
    await create_credential_and_sendback()

async def create_credential_and_sendback():
    print("\"Üniversite\" -> Transkript isteği yapan kişi için oluşturuluyor.")
    university['person_transcript_cred_values'] = json.dumps({
        "first_name": {"raw": "Test", "encoded": "1139481716457488690172217916278103335"},
        "last_name": {"raw": "Kullanıcısı", "encoded": "5321642780241790123587902456789123452"},
        "degree": {"raw": "Bachelor of Science, Computer Science", "encoded": "12434523576212321"},
        "status": {"raw": "graduated", "encoded": "2213454313412354"},
        "ssn": {"raw": "123-45-6789", "encoded": "3124141231422543541"},
        "year": {"raw": "2024", "encoded": "2024"},
        "average": {"raw": "4", "encoded": "4"}
    })

    university['transcript_cred'], _, _ = \
        await anoncreds.issuer_create_credential(university['wallet'], university['transcript_cred_offer'],
                                                 university['transcript_cred_request'],
                                                 university['person_transcript_cred_values'], None, None)

    person['transcript_cred'] = university['transcript_cred']
    print("\"Üniversite\" -> Transkript isteği yapan kişiye gönderildi.")
    
    _, person['transcript_cred_def'] = await get_cred_def_from_ledger(person['pool'], person['did'],
                                                         person['transcript_cred_def_id'])

    await anoncreds.prover_store_credential(person['wallet'], None, person['transcript_cred_request_metadata'],
                                            person['transcript_cred'], person['transcript_cred_def'], None)
    print("\"Kişi\" -> Kullanıcının cüzdanına Transkiript kaydedildi")

async def get_credential_for_referent(search_handle, referent):
    credentials = json.loads(
        await anoncreds.prover_fetch_credentials_for_proof_req(search_handle, referent, 10))
    return credentials[0]['cred_info']

async def prover_get_entities_from_ledger(presenter, _did, identifiers, actor):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    print("\"{}\" -> başvuru için gerekli şema(tanım) alındı".format(actor))
    for item in identifiers.values():
        (received_schema_id, received_schema) = await get_schema(presenter, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        (received_cred_def_id, received_cred_def) = await get_cred_def_from_ledger(presenter['pool'], _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states)


async def present_credentials(verfier, confirmer , presenter):
    nonce = await anoncreds.generate_nonce()
    verfier['job_application_proof_request'] = json.dumps({
        'nonce': nonce,
        'name': 'Job-Application',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'first_name'
            },
            'attr2_referent': {
                'name': 'last_name'
            },
            'attr3_referent': {
                'name': 'degree',
                'restrictions': [{'cred_def_id': confirmer['transcript_cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'status',
                'restrictions': [{'cred_def_id': confirmer['transcript_cred_def_id']}]
            },
            'attr5_referent': {
                'name': 'ssn',
                'restrictions': [{'cred_def_id': confirmer['transcript_cred_def_id']}]
            },
            'attr6_referent': {
                'name': 'phone_number'
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'average',
                'p_type': '>=',
                'p_value': 4,
                'restrictions': [{'cred_def_id': confirmer['transcript_cred_def_id']}]
            }
        }
    })
    presenter['job_application_proof_request'] = verfier['job_application_proof_request']
    print(f"\"{verfier['name']}\" -> kişiden iş başvurusu için kanıtlaması gereken belgeler istendi")

    search_for_job_application_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(presenter['wallet'],
                                                                presenter['job_application_proof_request'], None)

    cred_for_attr1 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr4_referent')
    cred_for_attr5 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr5_referent')
    cred_for_predicate1 = \
    await get_credential_for_referent(search_for_job_application_proof_request, 'predicate1_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_job_application_proof_request)

    presenter['creds_for_job_application_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                                cred_for_attr2['referent']: cred_for_attr2,
                                                cred_for_attr3['referent']: cred_for_attr3,
                                                cred_for_attr4['referent']: cred_for_attr4,
                                                cred_for_attr5['referent']: cred_for_attr5,
                                                cred_for_predicate1['referent']: cred_for_predicate1}

    presenter['schemas_for_job_application'], presenter['cred_defs_for_job_application'], \
    presenter['revoc_states_for_job_application'] = \
        await prover_get_entities_from_ledger(presenter, presenter['did'],
                                              presenter['creds_for_job_application_proof'], presenter['name'])
    

    print(f"\"{presenter['name']}\"  -> kanıt oluşturuldu")
    presenter['job_application_requested_creds'] = json.dumps({
        'self_attested_attributes': {
            'attr1_referent': 'Test',
            'attr2_referent': 'Kullanıcısı',
            'attr6_referent': '123-45-6789'
        },
        'requested_attributes': {
            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True},
            'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True},
            'attr5_referent': {'cred_id': cred_for_attr5['referent'], 'revealed': True},
        },
        'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent']}}
    })

    presenter['job_application_proof'] = \
        await anoncreds.prover_create_proof(presenter['wallet'], presenter['job_application_proof_request'],
                                            presenter['job_application_requested_creds'], presenter['master_secret_id'],
                                            presenter['schemas_for_job_application'],
                                            presenter['cred_defs_for_job_application'],
                                            presenter['revoc_states_for_job_application'])

    print(f"\"{presenter['name']}\" -> kanıt şirkete gönderildi.")
    verfier['job_application_proof'] = presenter['job_application_proof']

async def verifier_get_entities_from_ledger(verifier, identifiers, actor):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        print("\"{}\" -> başvuru için gerekli şema ağ üzerinden alındı".format(actor))
        (received_schema_id, received_schema) = await get_schema(verifier, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        (received_cred_def_id, received_cred_def) = await get_cred_def_from_ledger(verifier['pool'], verifier['did'], item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_reg_defs), json.dumps(rev_regs)


async def validate_credential(verifier):
    job_application_proof_object = json.loads(verifier['job_application_proof'])
    verifier['schemas_for_job_application'], verifier['cred_defs_for_job_application'], \
    verifier['revoc_ref_defs_for_job_application'], verifier['revoc_regs_for_job_application'] = \
        await verifier_get_entities_from_ledger(verifier,
                                                job_application_proof_object['identifiers'], verifier['name'])

    print(f"\"{verifier['name']}\"  -> gelen başvuru kontrol ediliyor")
    assert 'Bachelor of Science, Computer Science' == \
           job_application_proof_object['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    assert 'graduated' == \
           job_application_proof_object['requested_proof']['revealed_attrs']['attr4_referent']['raw']
    assert '123-45-6789' == \
           job_application_proof_object['requested_proof']['revealed_attrs']['attr5_referent']['raw']

    assert 'Test' == job_application_proof_object['requested_proof']['self_attested_attrs']['attr1_referent']
    assert 'Kullanıcısı' == job_application_proof_object['requested_proof']['self_attested_attrs']['attr2_referent']
    assert '123-45-6789' == job_application_proof_object['requested_proof']['self_attested_attrs']['attr6_referent']

    assert await anoncreds.verifier_verify_proof(verifier['job_application_proof_request'], verifier['job_application_proof'],
                                                 verifier['schemas_for_job_application'],
                                                 verifier['cred_defs_for_job_application'],
                                                 verifier['revoc_ref_defs_for_job_application'],
                                                 verifier['revoc_regs_for_job_application'])
    print(f"\"{verifier['name']}\"  -> başvuru onaylandı.")


async def run():
    all_start_time = time.time()
    start_time = time.time()
    print("\n----- 1.Adım- Indy Ağınına Bağlanma-----")
    indyPool = await connect_network()
    print("----- 1. Adım süresi: {:.6f} saniye".format(time.time() - start_time))
    
    start_time = time.time()
    print("\n-----2.Adım- Steward'ın kontrolünü ele alma-----")
    steward = await take_steward_control(indyPool)
    print("----- 2. Adım süresi: {:.6f} saniye".format(time.time() - start_time))
    
    start_time = time.time()
    print("\n-----3.Adım- Diğer Katılımcıların Ağa Eklenmesi")
    goverment, company, university = await add_trust_actors(indyPool, steward)
    person = await add_person(indyPool)
    print("----- 3. Adım süresi: {:.6f} saniye".format(time.time() - start_time))
    
    start_time = time.time()
    print("\n-----4.Adım- Hükümet Transkript Şemasını(standart) Belirler")
    schema_id = await create_credential_schema(goverment)
    print("----- 4. Adım süresi: {:.6f} saniye".format(time.time() - start_time))
    
    start_time = time.time()
    print("\n-----5.Adım- Üniversite transkript için şemadan Kimlik bilgisi tanımı oluşturur")
    await create_credential_definition(university, schema_id)
    print("----- 5. Adım süresi: {:.6f} saniye".format(time.time() - start_time))
    
    start_time = time.time()
    print("\n-----6.Adım- Kişi üniverste sayfasından transkriptini ister ve alır.")
    await get_credential(university, person)
    print("----- 6. Adım süresi: {:.6f} saniye".format(time.time() - start_time))
    
    start_time = time.time()
    print("\n-----7.Adım- Kişi şirkete transkriptini kanıt olarak sunar.")
    await present_credentials(company, university, person)
    print("----- 7. Adım süresi: {:.6f} saniye".format(time.time() - start_time))
    
    start_time = time.time()
    print("\n-----8.Adım- Şirket sunulan kanıtı onaylar.")
    await validate_credential(company)
    print("----- 8. Adım süresi: {:.6f} saniye".format(time.time() - start_time))

    total_time = time.time() - all_start_time
    print("\n Toplam işlem süresi: {:.6f} saniye".format(total_time))

loop = asyncio.get_event_loop()
loop.run_until_complete(run())
  


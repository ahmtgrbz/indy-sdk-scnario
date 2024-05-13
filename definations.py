import json

transcript_cred_def = {
    'tag': 'TAG1',
    'type': 'CL',
    'config': {"support_revocation": False}
}

network = {
        "name": "Indy_Network",
        "genesis_txn_path": "Genesis.txn"
}

# Steward Agent Daha önceden bu stewarların private keyleri oluşturulurken bu seed kullanılmış bu radan kontrolü ele alabiliyoruz.
steward = {
        'name': "Sovrin Steward",
        'wallet_config': json.dumps({'id': 'sovrin_steward_wallet'}),
        'wallet_credentials': json.dumps({'key': 'steward_wallet_key'}),
        'seed': '000000000000000000000000Steward1'
}

goverment = {
        'name': "Hükümet",
        'wallet_config': json.dumps({'id': 'goverment_wallet'}),
        'wallet_credentials': json.dumps({'key': 'goverment_wallet_key'}),
        'role': 'TRUST_ANCHOR'
    }

company = {
        'name': 'Şirket',
        'wallet_config': json.dumps({'id': 'company_wallet'}),
        'wallet_credentials': json.dumps({'key': 'company_wallet_key'}),
        'role': 'TRUST_ANCHOR'
}

university = {
        'name': 'Üniversite',
        'wallet_config': json.dumps({'id': 'university_wallet'}),
        'wallet_credentials': json.dumps({'key': 'university_wallet_key'}),
        'role': 'TRUST_ANCHOR'
}

transcript = {
        'name': 'Transcript',
        'version': '1.0',
        'attributes': ['first_name', 'last_name', 'degree', 'status', 'year', 'average', 'ssn']
}

person = {
        'name': 'Kişi',
        'wallet_config': json.dumps({'id': 'Person_wallet'}),
        'wallet_credentials': json.dumps({'key': 'Person_wallet_key'})
}


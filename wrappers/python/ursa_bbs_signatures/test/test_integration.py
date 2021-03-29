from ursa_bbs_signatures.api import sign, verify, create_proof, verify_proof
from ursa_bbs_signatures.models.CreateProofRequest import CreateProofRequest
from ursa_bbs_signatures.models.ProofMessage import ProofMessage, ProofMessageType
from ursa_bbs_signatures.models.SignRequest import SignRequest
from ursa_bbs_signatures.models.VerifyProofRequest import VerifyProofRequest
from ursa_bbs_signatures.models.VerifyRequest import VerifyRequest
from ursa_bbs_signatures.models.keys.BlsKeyPair import BlsKeyPair


def test_full_integration():
    messages = [
        "message 1",
        "message 2",
        "message 3",
        "message 4",
        "message 5",
    ]

    # prepare signing keys
    key_pair = BlsKeyPair.generate_g2()
    public_key = key_pair.get_bbs_key(message_count=len(messages))
    sign_request = SignRequest(key_pair, messages)
    nonce = bytes([1, 2, 3])

    # sign messages
    signature = sign(sign_request)
    assert sign_request is not None

    # prepare verification keys
    verify_request = VerifyRequest(BlsKeyPair(key_pair.public_key), signature, messages)

    # assert the signature is valid
    assert verify(verify_request) is True
    # create proof
    proof_messages = [
        ProofMessage(messages[0], ProofMessageType.Revealed),
        ProofMessage(messages[1], ProofMessageType.HiddenProofSpecificBlinding),
        ProofMessage(messages[2], ProofMessageType.Revealed),
        ProofMessage(messages[3], ProofMessageType.HiddenProofSpecificBlinding),
        ProofMessage(messages[4], ProofMessageType.Revealed),
    ]

    proof_result = create_proof(
        CreateProofRequest(public_key, proof_messages, signature, nonce)
    )

    verify_result = verify_proof(
        VerifyProofRequest(
            public_key,
            proof_result,
            [
                x.message
                for x in proof_messages
                if x.proof_type == ProofMessageType.Revealed
            ],
            nonce,
        )
    )

    assert verify_result is True

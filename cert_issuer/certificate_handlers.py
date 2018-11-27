import json
import logging
import boto3

from cert_schema import normalize_jsonld
from cert_schema import validate_v2
from cert_issuer import helpers
from pycoin.serialize import b2h
from cert_issuer.models import CertificateHandler, BatchHandler

from cert_issuer.signer import FinalizableSigner

BUCKET = 'testingxertify'
KEY = 'certis/54ebe810-348b-473a-b75f-683110cdf0ba.json'


class CertificateV2Handler(CertificateHandler):
    #DEPRECATED-DANNY
    def get_byte_array_to_issue(self, certificate_metadata):
        logging.info("DANNY-----------------------------------------------------------------2");
        certificate_json = self._get_certificate_to_issue(certificate_metadata)
        normalized = normalize_jsonld(certificate_json, detect_unmapped_fields=False)
        return normalized.encode('utf-8')

    def add_proof(self, certificate_metadata, merkle_proof):
        """
        :param certificate_metadata:
        :param merkle_proof:
        :return:
        """
        client = boto3.client('s3',
                              aws_access_key_id='AKIAIPZZ2DOBQEVC6V6A',
                              aws_secret_access_key='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'
                              )
        stringPath = "certis/" + certificate_metadata.uid + ".json"
        result = client.get_object(Bucket=BUCKET, Key=(stringPath))
        certificateString = str(result["Body"].read().decode())
        nnnnnnn = json.dumps(certificateString)
        jsonJsonJson = json.loads(nnnnnnn)
        jsonJsonJsonxx = json.loads(jsonJsonJson)
        jsonJsonJsonxx['signature'] = merkle_proof

        """DANNYCOMMMENT-------This is for new file creation"""
        fileNameToSave= "newone/"+certificate_metadata.uid + ".json"
        client.put_object(Bucket=BUCKET, Key=fileNameToSave, Body=json.dumps(jsonJsonJsonxx))

    # DEPRECATED-DANNY
    def _get_certificate_to_issue(self, certificate_metadata):
        with open(certificate_metadata.unsigned_cert_file_name, 'r') as unsigned_cert_file:
            certificate_json = json.load(unsigned_cert_file)
        return certificate_json


class CertificateWebV2Handler(CertificateHandler):
    def get_byte_array_to_issue(self, certificate_json):
        logging.info("DANNY7777777");
        normalized = normalize_jsonld(certificate_json, detect_unmapped_fields=False)
        return normalized.encode('utf-8')

    def add_proof(self, certificate_json, merkle_proof):
        """
        :param certificate_metadata:
        :param merkle_proof:
        :return:
        """
        return merkle_proof


class CertificateBatchWebHandler(BatchHandler):
    def finish_batch(self, tx_id, chain):
        self.proof = next(self.merkle_tree.get_proof_generator(tx_id, chain))

    def get_certificate_generator(self):
        """
        Returns a generator (1-time iterator) of certificates in the batch
        :return:
        """

        for cert in self.certificates_to_issue:
            data_to_issue = self.certificate_handler.get_byte_array_to_issue(cert)
            yield data_to_issue

    def prepare_batch(self):
        """
        Propagates exception on failure
        :return: byte array to put on the blockchain
        """

        for cert in self.certificates_to_issue:
            self.certificate_handler.validate_certificate(cert)

        self.merkle_tree.populate(self.get_certificate_generator())
        logging.info('here is the op_return_code data: %s', b2h(self.merkle_tree.get_blockchain_data()))
        return self.merkle_tree.get_blockchain_data()


class CertificateBatchHandler(BatchHandler):
    """
    Manages a batch of certificates. Responsible for iterating certificates in a consistent order.

    In this case, certificates are initialized as an Ordered Dictionary, and we iterate in insertion order.
    """

    def pre_batch_actions(self, config):
        self._process_directories(config)

    """Aca se copian los directorios"""
    def post_batch_actions(self, config):
        #helpers.copy_output(self.certificates_to_issue)
        logging.info('Your Blockchain Certificates are in %s', config.blockchain_certificates_dir)

    def prepare_batch(self):
        """
        Propagates exception on failure
        :return: byte array to put on the blockchain
        """

        # validate batch
        for _, metadata in self.certificates_to_issue.items():
            logging.info("DANNY--------X---------Y------ %s",self.certificate_handler.validate_certificate(metadata))
            self.certificate_handler.validate_certificate(metadata)

        # sign batch
        with FinalizableSigner(self.secret_manager) as signer:
            for _, metadata in self.certificates_to_issue.items():
                logging.info('DANNYDDDDDDD%s',metadata.uid)
                self.certificate_handler.sign_certificate(signer, metadata)

        self.merkle_tree.populate(self.get_certificate_generator())
        logging.info('here is the op_return_code data: %s', b2h(self.merkle_tree.get_blockchain_data()))
        return self.merkle_tree.get_blockchain_data()

    def get_certificate_generator(self):
        """
        Returns a generator (1-time iterator) of certificates in the batch
        :return:
        """
        client = boto3.client('s3',
                              aws_access_key_id='AKIAIPZZ2DOBQEVC6V6A',
                              aws_secret_access_key='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'
                              )
        resp = client.list_objects_v2(Bucket=BUCKET, Prefix='certis')
        for obj in resp['Contents']:
            alg = obj['Key']
            logging.info("DANNNY78------------------------------------------------ %s", alg)
            if alg.find("json") > 1:
                logging.info("DANNNY7------------------------------------------------ %s",alg)
                result = client.get_object(Bucket=BUCKET, Key=alg)
                resultBytes=result["Body"].read()
                resultText=resultBytes.decode()
                nnnnnnn = json.dumps(resultText)
                jsonJsonJson = json.loads(nnnnnnn)
                jsonJsonJsonxx = json.loads(jsonJsonJson)
                normalized = normalize_jsonld(jsonJsonJsonxx, detect_unmapped_fields=False)
                normalizedEncode=normalized.encode('utf-8')

                #dataToIssue=str(resultText).encode('utf-8')
                logging.info("DANNNY---------------------(34)----------------------------- %s", normalizedEncode)
                #yield resultBytes
                yield normalizedEncode

    def finish_batch(self, tx_id, chain):
        proof_generator = self.merkle_tree.get_proof_generator(tx_id, chain)
        for uid, metadata in self.certificates_to_issue.items():
            logging.info('DANNYEEEEEE')
            proof = next(proof_generator)
            logging.info("DANNNYXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX8------------------------------------------------ %s", proof)
            self.certificate_handler.add_proof(metadata, proof)

    def _process_directories(self, config):
        unsigned_certs_dir = config.unsigned_certificates_dir
        signed_certs_dir = config.signed_certificates_dir
        blockchain_certificates_dir = config.blockchain_certificates_dir
        work_dir = config.work_dir

        certificates_metadata = helpers.prepare_issuance_batch(
            unsigned_certs_dir,
            signed_certs_dir,
            blockchain_certificates_dir,
            work_dir)

        num_certificates = len(certificates_metadata)
        logging.info('DANNYNUMCERTIFICATES')
        if num_certificates < 1:
            return None

        logging.info('Processing %d certificates under work path=%s', num_certificates, work_dir)
        self.set_certificates_in_batch(certificates_metadata)


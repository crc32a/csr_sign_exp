from OpenSSL import crypto

import random
import six

rnd = random.Random()

def rand_serial(n_bits=160):
    """
    :param n_bits: Generate a random serial number. The default
    size of the serial number is 160 buts which is as good as a UUID
    """
    return rnd.randint(0,2**n_bits)

def genkey(n_bits):
    """ generates an RSA PEM key of n_bits size
    """
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, n_bits)
    key = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
    return key


def gencsr(subj_name, key):
    """ Takes in a subject name and Pem encoded key and generates a CSR
    example subjname "cn=www.somehost.com,ST=Texas,L=San Antonio, O=Rackspace, OU=Rackspace hosting,C=US"
    """
    # Convert the pem key to a lowlevel OpenSSL key
    pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
    req = crypto.X509Req()
    allowed_oids = set(["CN","ST","L","O","OU","C"])
    #split the string up so we can add it to one by one into the subj attrs
    subj = req.get_subject()
    for oid_and_value in subj_name.split(","):
        oid, value = oid_and_value.split("=")
        if oid.upper() in allowed_oids:
            setattr(subj, oid.strip().upper(), value.strip())

    #Attach the public key
    req.set_pubkey(pkey)

    #sign the CSR with its own key with a sha1 signature
    req.sign(pkey, "sha1")

    #Return the pem encoding of the CSR
    return crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

def self_sign_csr(csr, key,validity_secs = 24*60*60):
    """ Generate a self signed root certificate.
    in this case the subject is pulled from the csr and placed
    in the new cert.
    """
    priv_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
    pcsr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
    pub_key = pcsr.get_pubkey()
    if pcsr.verify(pub_key) == -1:
        raise Exception("csr didn't even sign its own key")
    subj = pcsr.get_subject()
    x509 = crypto.X509()
    x509.set_version(2)
    x509.set_serial_number(rand_serial())
    x509.set_subject(pcsr.get_subject())
    x509.set_issuer(pcsr.get_subject())
    x509.set_pubkey(pcsr.get_pubkey())
    x509.add_extensions(get_exts(ca=True))
    x509.gmtime_adj_notBefore(0)
    x509.gmtime_adj_notAfter(validity_secs)
    x509.sign(priv_key, "sha1")
    return crypto.dump_certificate(crypto.FILETYPE_PEM, x509)

def sign_csr(csr, ca_key, ca_crt, validity_secs=24*60*60, ca=True):
    """ Sign the CSR with the ca key and cert
    the ca boolean specifies if the certificate is allowed to sign other certs
    """
    ca_PKey = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key)
    ca_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, ca_crt)
    pcsr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)

    x509 = crypto.X509()
    pub_key = pcsr.get_pubkey()
    x509.set_version(2)
    x509.set_serial_number(rand_serial())
    x509.set_pubkey(pub_key)
    x509.set_subject(pcsr.get_subject())
    x509.set_issuer(ca_x509.get_subject())
    x509.gmtime_adj_notBefore(0)
    x509.gmtime_adj_notAfter(validity_secs)
    x509.add_extensions(get_exts(ca=ca))
    x509.sign(ca_PKey, "sha1")
    return crypto.dump_certificate(crypto.FILETYPE_PEM, x509)


def get_exts(ca=True):
    ca_sign = 'digitalSignature, keyEncipherment,  Data Encipherment, Certificate Sign'
    ca_no_sign = 'digitalSignature, keyEncipherment,  Data Encipherment'
    if ca:
        exts = [crypto.X509Extension('keyUsage',True,ca_sign),
                crypto.X509Extension('basicConstraints', True, 'CA:true')]
    else:
        exts = [crypto.X509Extension('keyUsage', True, ca_no_sign),
                crypto.X509Extension('basicConstraints', True, 'CA:false')]
    return exts




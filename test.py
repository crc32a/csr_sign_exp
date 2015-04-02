#!/usr/bin/env python

from utils import cert_utils
import string

subj = "cn=www.test.org,ST=Texas,L=San Antonio,O=Rackspace,C=US"

root_key = cert_utils.genkey(2048)
root_csr = cert_utils.gencsr(subj, root_key)
root_crt = cert_utils.self_sign_csr(root_csr,root_key)

print("Root key csr and crt\n")
print("key:\n{0}\ncsr:\n{1}\ncrt:\n{2}\n".format(root_key,root_csr,root_crt))

#imd1 is signed by root
imd1_key = cert_utils.genkey(2048)
imd1_csr = cert_utils.gencsr("cn=IMD1", imd1_key)
imd1_crt = cert_utils.sign_csr(imd1_csr, root_key, root_crt,ca=True)

#imd2 is signed by imd1
imd2_key = cert_utils.genkey(2048)
imd2_csr = cert_utils.gencsr("cn=IMD2", imd2_key)
imd2_crt = cert_utils.sign_csr(imd2_csr, imd1_key, imd1_crt,ca=True)


#imd3 is signed by imd2
imd3_key = cert_utils.genkey(2048)
imd3_csr = cert_utils.gencsr("cn=IMD3", imd3_key)
imd3_crt = cert_utils.sign_csr(imd3_csr, imd2_key, imd2_crt, ca=True)


#lastly lets generate the user end certificate will be singed by imd3
subj = "".join(["cn=www.test.org,st=Texas,L=San Antonio,C=US,",
                "O=Rackspace, OU=Cloud LoadBalancing"])
user_key = cert_utils.genkey(2048)
user_csr = cert_utils.gencsr(subj, user_key)
user_crt = cert_utils.sign_csr(user_csr, imd3_key, imd3_crt, ca=False)

#so the whole chain is

open("./root.crt","w").write(root_crt)
open("./imds.crt","w").write(imd1_crt + imd2_crt + imd3_crt)
open("./user.crt","w").write(user_crt)

print("you can verify by running the command\n")
print("openssl verify -CAfile root.crt -untrusted imds.crt user.crt")
